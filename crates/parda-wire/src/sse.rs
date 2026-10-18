//! Server-sent events: an incremental parser and a serialiser.

use bytes::{Bytes, BytesMut};

/// One SSE event. `raw` holds the original bytes until the event is changed,
/// so untouched events are forwarded byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
    /// `id:` and `retry:` fields, kept when the event is rewritten.
    pub id: Option<String>,
    pub retry: Option<String>,
    pub raw: Option<Bytes>,
}

impl SseEvent {
    pub fn new(event: Option<&str>, data: String) -> Self {
        SseEvent {
            event: event.map(str::to_string),
            data,
            id: None,
            retry: None,
            raw: None,
        }
    }

    #[cfg(test)]
    fn with_raw(mut self, raw: &'static [u8]) -> Self {
        self.raw = Some(Bytes::from_static(raw));
        self
    }

    /// Replace the data (drops the raw bytes).
    pub fn set_data(&mut self, data: String) {
        self.data = data;
        self.raw = None;
    }
}

/// Where the next event in `buf` ends, scanning from `from` (a line start).
enum Scan {
    /// `body_end` excludes the blank line; `total` includes it. `skip_lf`:
    /// the blank line ended in a CR at the very end of the buffer, so a
    /// following LF belongs to it.
    Event {
        body_end: usize,
        total: usize,
        skip_lf: bool,
    },
    /// No complete event yet. Resume at `line_start`; `searched` bytes from
    /// there are known to hold no line ending, so they need not be read again.
    Incomplete { line_start: usize, searched: usize },
}

/// `from` is a line start; `searched` (>= `from`, or 0) is how far into
/// that line an earlier call already looked for a line ending.
fn scan(buf: &[u8], from: usize, searched: usize) -> Scan {
    let mut pos = from;
    let mut look = searched.max(from).min(buf.len());
    loop {
        let Some(off) = buf[look..].iter().position(|&b| b == b'\r' || b == b'\n') else {
            return Scan::Incomplete {
                line_start: pos,
                searched: buf.len(),
            };
        };
        let i = look + off;
        let blank = i == pos;
        let (len, skip_lf) = if buf[i] == b'\n' {
            (1, false)
        } else if i + 1 < buf.len() {
            (if buf[i + 1] == b'\n' { 2 } else { 1 }, false)
        } else if blank {
            // A blank line ended by a CR: the event is complete now.
            (1, true)
        } else {
            // A CR at the end of a line: maybe half of a CRLF; wait (and
            // look at that CR again with the next chunk).
            return Scan::Incomplete {
                line_start: pos,
                searched: i,
            };
        };
        if blank {
            return Scan::Event {
                body_end: pos,
                total: i + len,
                skip_lf,
            };
        }
        pos = i + len;
        look = pos;
    }
}

/// Incremental SSE parser for one stream. Lines may end in LF, CRLF or CR,
/// and bytes already scanned are never scanned again.
#[derive(Default)]
pub struct SseParser {
    buf: BytesMut,
    /// Start of the first line not yet known to be complete and non-blank.
    scanned: usize,
    /// Bytes from `scanned` on that hold no line ending (never re-read).
    searched: usize,
    /// Drop a leading LF (the second half of a CRLF already used).
    skip_lf: bool,
}

impl SseParser {
    /// Add bytes; returns every event completed by them.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        let chunk = match (self.skip_lf, chunk.first()) {
            (true, Some(b'\n')) => &chunk[1..],
            _ => chunk,
        };
        if !chunk.is_empty() {
            self.skip_lf = false;
        }
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            match scan(&self.buf, self.scanned, self.searched) {
                Scan::Event {
                    body_end,
                    total,
                    skip_lf,
                } => {
                    let raw = self.buf.split_to(total).freeze();
                    self.scanned = 0;
                    self.searched = 0;
                    self.skip_lf = skip_lf;
                    if let Some(ev) = parse_block(&raw[..body_end], raw.clone()) {
                        out.push(ev);
                    }
                    if self.skip_lf && self.buf.first() == Some(&b'\n') {
                        let _ = self.buf.split_to(1);
                        self.skip_lf = false;
                    }
                }
                Scan::Incomplete {
                    line_start,
                    searched,
                } => {
                    self.scanned = line_start;
                    self.searched = searched;
                    return out;
                }
            }
        }
    }

    /// Bytes held for an event that is not complete yet.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Take the bytes held for an incomplete event, as they came (for a
    /// caller that gives up on parsing, e.g. an event too large to hold).
    pub fn take_buffered(&mut self) -> Bytes {
        self.scanned = 0;
        self.searched = 0;
        self.buf.split().freeze()
    }

    /// Whatever is left when the stream ends without a final blank line.
    pub fn finish(&mut self) -> Option<SseEvent> {
        self.scanned = 0;
        self.searched = 0;
        parse_rest(&mut self.buf)
    }
}

/// Take every complete event out of `buf`; a trailing partial event stays.
pub fn parse_sse(buf: &mut BytesMut) -> Vec<SseEvent> {
    let mut p = SseParser {
        buf: std::mem::take(buf),
        ..SseParser::default()
    };
    let out = p.feed(&[]);
    *buf = p.buf;
    out
}

/// Parse whatever is left when the stream ends without a final blank line.
pub fn parse_rest(buf: &mut BytesMut) -> Option<SseEvent> {
    if buf.iter().all(|b| b.is_ascii_whitespace()) {
        buf.clear();
        return None;
    }
    let raw = buf.split().freeze();
    let mut with_end = raw.to_vec();
    with_end.extend_from_slice(b"\n\n");
    parse_block(&raw, Bytes::from(with_end))
}

/// Split on LF, CRLF or CR.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        match rest.find(['\r', '\n']) {
            Some(i) => {
                let line = &rest[..i];
                let len = if rest[i..].starts_with("\r\n") { 2 } else { 1 };
                rest = &rest[i + len..];
                Some(line)
            }
            None => {
                let line = rest;
                rest = "";
                Some(line)
            }
        }
    })
}

fn parse_block(block: &[u8], raw: Bytes) -> Option<SseEvent> {
    let text = String::from_utf8_lossy(block);
    let mut ev = SseEvent::new(None, String::new());
    let mut data: Option<String> = None;
    for line in lines(&text) {
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        match field {
            "event" => ev.event = Some(value.to_string()),
            "data" => match &mut data {
                Some(d) => {
                    d.push('\n');
                    d.push_str(value);
                }
                None => data = Some(value.to_string()),
            },
            "id" => ev.id = Some(value.to_string()),
            "retry" => ev.retry = Some(value.to_string()),
            _ => {}
        }
    }
    ev.data = data.unwrap_or_default();
    ev.raw = Some(raw);
    Some(ev)
}

pub fn serialize(ev: &SseEvent) -> Bytes {
    if let Some(raw) = &ev.raw {
        return raw.clone();
    }
    let mut s = String::with_capacity(ev.data.len() + 32);
    if let Some(id) = &ev.id {
        s.push_str("id: ");
        s.push_str(id);
        s.push('\n');
    }
    if let Some(retry) = &ev.retry {
        s.push_str("retry: ");
        s.push_str(retry);
        s.push('\n');
    }
    if let Some(e) = &ev.event {
        s.push_str("event: ");
        s.push_str(e);
        s.push('\n');
    }
    for line in data_lines(&ev.data) {
        s.push_str("data: ");
        s.push_str(line);
        s.push('\n');
    }
    s.push('\n');
    Bytes::from(s)
}

/// The `data:` lines that carry `data`: split on CRLF, CR or LF (a reader
/// ends a line at each), every piece kept, empty ones included. A line
/// break in the data reads back as LF.
fn data_lines(data: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(data);
    std::iter::from_fn(move || {
        let text = rest?;
        match text.find(['\r', '\n']) {
            Some(i) => {
                let len = if text[i..].starts_with("\r\n") { 2 } else { 1 };
                rest = Some(&text[i + len..]);
                Some(&text[..i])
            }
            None => {
                rest = None;
                Some(text)
            }
        }
    })
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
    fn data_with_any_line_ending_stays_one_event() {
        // A reader splits lines on CRLF, CR or LF, so a CR in data must
        // start a new `data:` line, never end the event or truncate it.
        for (data, lines) in [
            ("a\rb", "data: a\ndata: b\n"),
            ("a\r\rdata: x", "data: a\ndata: \ndata: data: x\n"),
            ("a\r\nevent: pwn", "data: a\ndata: event: pwn\n"),
            ("a\n\nb\r", "data: a\ndata: \ndata: b\ndata: \n"),
            ("\r\n\r", "data: \ndata: \ndata: \n"),
        ] {
            let mut ev = SseEvent::new(Some("x"), String::new());
            ev.set_data(data.into());
            let out = serialize(&ev);
            assert_eq!(out, Bytes::from(format!("event: x\n{lines}\n")), "{data:?}");
            let mut p = SseParser::default();
            let evs = p.feed(&out);
            assert_eq!(evs.len(), 1, "{data:?}");
            assert_eq!(evs[0].event.as_deref(), Some("x"));
            assert_eq!(evs[0].data, data.replace("\r\n", "\n").replace('\r', "\n"));
            assert!(p.finish().is_none());
        }
    }

    #[test]
    fn id_and_retry_survive_a_rewrite() {
        let mut buf = BytesMut::from(&b"id: 7\nretry: 1500\nevent: x\ndata: a\n\n"[..]);
        let mut evs = parse_sse(&mut buf);
        assert_eq!(evs.len(), 1);
        evs[0].set_data("b".into());
        assert_eq!(
            serialize(&evs[0]),
            Bytes::from_static(b"id: 7\nretry: 1500\nevent: x\ndata: b\n\n")
        );
    }

    #[test]
    fn cr_only_and_mixed_line_endings() {
        let mut buf = BytesMut::from(&b"data: a\r\rdata: b\r\nevent: e\r\r\n"[..]);
        let evs = parse_sse(&mut buf);
        assert_eq!(evs.len(), 2, "{evs:?}");
        assert_eq!(evs[0].data, "a");
        assert_eq!(evs[1].data, "b");
        assert_eq!(evs[1].event.as_deref(), Some("e"));

        // A CRLF split across chunks is one line ending, not two.
        let mut p = SseParser::default();
        assert!(p.feed(b"data: x\r").is_empty());
        let evs = p.feed(b"\n\r\ndata: y\n\n");
        assert_eq!(evs.len(), 2);
        assert_eq!((evs[0].data.as_str(), evs[1].data.as_str()), ("x", "y"));
        // An event ended by a lone CR is delivered at once; a following LF
        // (the rest of a CRLF) does not start an empty event.
        let evs = p.feed(b"data: z\r\r");
        assert_eq!(evs.len(), 1);
        let evs = p.feed(b"\ndata: w\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "w");
    }

    #[test]
    fn chunks_are_not_rescanned() {
        let mut p = SseParser::default();
        for _ in 0..1000 {
            assert!(p.feed(b"data: 0123456789\n").is_empty());
        }
        // Everything up to the last complete line is known to hold no
        // event end and is not scanned again.
        assert_eq!(p.scanned, p.buf.len());
        assert_eq!(p.feed(b"\n").len(), 1);
        assert!(p.buf.is_empty());
    }

    #[test]
    fn one_huge_line_in_small_chunks_is_scanned_once() {
        use std::time::{Duration, Instant};
        // A 4 MB `data:` line (a big tool result) arriving in 16 KB chunks:
        // rescanning the unfinished line on every chunk is quadratic.
        let line = format!("data: {}", "x".repeat(4 * 1024 * 1024));
        let mut input = line.clone().into_bytes();
        input.extend_from_slice(b"\n\ndata: next\n\n");
        let started = Instant::now();
        let mut p = SseParser::default();
        let mut events = Vec::new();
        for chunk in input.chunks(16 * 1024) {
            events.extend(p.feed(chunk));
        }
        let took = started.elapsed();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data.len(), 4 * 1024 * 1024);
        assert_eq!(events[1].data, "next");
        assert!(took < Duration::from_secs(1), "took {took:?}");
        // A CR/LF split at a chunk edge still resolves correctly.
        let mut p = SseParser::default();
        let mut evs = Vec::new();
        for chunk in b"data: ab\r\n\r\n".chunks(1) {
            evs.extend(p.feed(chunk));
        }
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "ab");
    }

    #[test]
    fn any_chunking_gives_the_same_events() {
        let input =
            b"event: a\r\ndata: 1\r\n\r\ndata: 2\ndata: 3\r\rdata: 4\n\n: c\n\ndata: 5\r\n\r\n";
        let all = |chunk: usize| {
            let mut p = SseParser::default();
            let mut evs = Vec::new();
            for c in input.chunks(chunk) {
                evs.extend(p.feed(c));
            }
            evs.into_iter().map(|e| e.data).collect::<Vec<_>>()
        };
        let whole = all(input.len());
        assert_eq!(whole, ["1", "2\n3", "4", "", "5"]);
        for n in 1..12 {
            assert_eq!(all(n), whole, "{n}");
        }
    }

    #[test]
    fn buffered_bytes_can_be_taken_back() {
        let mut p = SseParser::default();
        assert_eq!(
            p.feed(b"data: a\n\ndata: long"),
            [SseEvent::new(None, "a".into()).with_raw(b"data: a\n\n")]
        );
        assert_eq!(p.buffered(), 10);
        assert_eq!(p.take_buffered(), Bytes::from_static(b"data: long"));
        assert_eq!(p.buffered(), 0);
        assert_eq!(p.feed(b"data: b\n\n").len(), 1);
    }

    #[test]
    fn trailing_event_without_blank_line() {
        let mut buf = BytesMut::from(&b"data: [DONE]"[..]);
        assert!(parse_sse(&mut buf).is_empty());
        let ev = parse_rest(&mut buf).unwrap();
        assert_eq!(ev.data, "[DONE]");
    }
}
