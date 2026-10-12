//! Server-sent events: an incremental parser, a serialiser, and the pump
//! that rewrites an upstream event stream on its way to the client.

use std::collections::HashMap;

use bytes::{Bytes, BytesMut};
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use parda_engine::{Engine, StreamRestorer};

/// One SSE event. `raw` holds the original bytes until the event is changed,
/// so untouched events are forwarded byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
    pub raw: Option<Bytes>,
}

impl SseEvent {
    pub fn new(event: Option<&str>, data: String) -> Self {
        SseEvent {
            event: event.map(str::to_string),
            data,
            raw: None,
        }
    }

    /// Replace the data (drops the raw bytes).
    pub fn set_data(&mut self, data: String) {
        self.data = data;
        self.raw = None;
    }
}

/// Find the end of the first complete event: index just past its blank line.
fn event_end(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b'\n' {
            if buf.get(i + 1) == Some(&b'\n') {
                return Some((i, i + 2));
            }
            if buf.get(i + 1) == Some(&b'\r') && buf.get(i + 2) == Some(&b'\n') {
                return Some((i, i + 3));
            }
        }
        i += 1;
    }
    None
}

/// Take every complete event out of `buf`; a trailing partial event stays.
pub fn parse_sse(buf: &mut BytesMut) -> Vec<SseEvent> {
    let mut out = Vec::new();
    while let Some((body_end, total)) = event_end(buf) {
        let raw = buf.split_to(total).freeze();
        if let Some(ev) = parse_block(&raw[..body_end], raw.clone()) {
            out.push(ev);
        }
    }
    out
}

/// Parse whatever is left when the stream ends without a final blank line.
pub(crate) fn parse_rest(buf: &mut BytesMut) -> Option<SseEvent> {
    if buf.iter().all(|b| b.is_ascii_whitespace()) {
        buf.clear();
        return None;
    }
    let raw = buf.split().freeze();
    let mut with_end = raw.to_vec();
    with_end.extend_from_slice(b"\n\n");
    parse_block(&raw, Bytes::from(with_end))
}

fn parse_block(block: &[u8], raw: Bytes) -> Option<SseEvent> {
    let text = String::from_utf8_lossy(block);
    let mut event = None;
    let mut data: Option<String> = None;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        match field {
            "event" => event = Some(value.to_string()),
            "data" => match &mut data {
                Some(d) => {
                    d.push('\n');
                    d.push_str(value);
                }
                None => data = Some(value.to_string()),
            },
            _ => {}
        }
    }
    Some(SseEvent {
        event,
        data: data.unwrap_or_default(),
        raw: Some(raw),
    })
}

pub fn serialize(ev: &SseEvent) -> Bytes {
    if let Some(raw) = &ev.raw {
        return raw.clone();
    }
    let mut s = String::with_capacity(ev.data.len() + 32);
    if let Some(e) = &ev.event {
        s.push_str("event: ");
        s.push_str(e);
        s.push('\n');
    }
    for line in ev.data.split('\n') {
        s.push_str("data: ");
        s.push_str(line);
        s.push('\n');
    }
    s.push('\n');
    Bytes::from(s)
}

/// Per-provider stream rewriting.
pub(crate) trait StreamRewriter: Send {
    fn on_event(&mut self, ev: SseEvent, out: &mut Vec<SseEvent>);
    /// The upstream ended; flush anything held back.
    fn on_end(&mut self, out: &mut Vec<SseEvent>);
}

/// Stream restorers keyed by content block / choice / output item.
pub(crate) struct Restorers {
    engine: Engine,
    scope: String,
    map: HashMap<String, StreamRestorer>,
    order: Vec<String>,
}

impl Restorers {
    pub(crate) fn new(engine: Engine, scope: &str) -> Self {
        Restorers {
            engine,
            scope: scope.to_string(),
            map: HashMap::new(),
            order: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, key: &str, text: &str) -> String {
        if !self.map.contains_key(key) {
            self.map
                .insert(key.to_string(), self.engine.stream_restorer(&self.scope));
            self.order.push(key.to_string());
        }
        self.map
            .get_mut(key)
            .map(|r| r.push(text))
            .unwrap_or_default()
    }

    /// Flush and forget one key.
    pub(crate) fn finish(&mut self, key: &str) -> String {
        self.order.retain(|k| k != key);
        self.map
            .remove(key)
            .map(|mut r| r.finish())
            .unwrap_or_default()
    }

    /// Keys still open, oldest first.
    pub(crate) fn open_keys(&self) -> Vec<String> {
        self.order.clone()
    }

    pub(crate) fn restore(&self, text: &str) -> String {
        self.engine.restore(text, &self.scope)
    }
}

/// Read the upstream body, rewrite events and send them to the client as
/// soon as they are complete.
pub(crate) async fn pump(
    upstream: reqwest::Response,
    mut rw: Box<dyn StreamRewriter>,
    mut tx: mpsc::Sender<Result<Bytes, std::io::Error>>,
) {
    let mut stream = upstream.bytes_stream();
    let mut buf = BytesMut::new();
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(b) => {
                buf.extend_from_slice(&b);
                for ev in parse_sse(&mut buf) {
                    rw.on_event(ev, &mut out);
                }
                for ev in out.drain(..) {
                    if tx.send(Ok(serialize(&ev))).await.is_err() {
                        return; // client went away
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "upstream stream failed");
                let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                return;
            }
        }
    }
    if let Some(ev) = parse_rest(&mut buf) {
        rw.on_event(ev, &mut out);
    }
    rw.on_end(&mut out);
    for ev in out.drain(..) {
        if tx.send(Ok(serialize(&ev))).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_split_events_and_keeps_raw() {
        let mut buf = BytesMut::from(&b"event: a\ndata: {\"x\":1}\n\nevent: b\nda"[..]);
        let evs = parse_sse(&mut buf);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event.as_deref(), Some("a"));
        assert_eq!(evs[0].data, "{\"x\":1}");
        assert_eq!(
            serialize(&evs[0]),
            Bytes::from_static(b"event: a\ndata: {\"x\":1}\n\n")
        );
        buf.extend_from_slice(b"ta: 2\ndata: 3\r\n\r\n: comment\n\ndata: [DONE]\n\n");
        let evs = parse_sse(&mut buf);
        assert_eq!(evs.len(), 3);
        assert_eq!(evs[0].data, "2\n3");
        assert_eq!(evs[1].data, "");
        assert_eq!(evs[2].data, "[DONE]");
        assert!(buf.is_empty());
    }

    #[test]
    fn serialize_modified() {
        let mut ev = SseEvent::new(Some("x"), "a".into());
        ev.set_data("line1\nline2".into());
        assert_eq!(
            serialize(&ev),
            Bytes::from_static(b"event: x\ndata: line1\ndata: line2\n\n")
        );
    }

    #[test]
    fn trailing_event_without_blank_line() {
        let mut buf = BytesMut::from(&b"data: [DONE]"[..]);
        assert!(parse_sse(&mut buf).is_empty());
        let ev = parse_rest(&mut buf).unwrap();
        assert_eq!(ev.data, "[DONE]");
    }
}
