//! Restoring surrogates in a JSON document that arrives in fragments
//! (streamed tool-call arguments: `input_json_delta.partial_json`,
//! `delta.tool_calls[].function.arguments`,
//! `response.function_call_arguments.delta`).
//!
//! The fragments are JSON *text*, so a real value with `"`, `\` or a line
//! break cannot be pasted in verbatim. Each string value is decoded, run
//! through its own [`StreamRestorer`], and what it changed is re-encoded;
//! text it left alone goes out exactly as it came (escapes included), as do
//! keys and everything outside strings. Escapes split across fragments are
//! held until complete. Text that stops being JSON (prose after a bracket)
//! passes through unrestored from there on.

use std::collections::VecDeque;

use parda_engine::{Engine, StreamRestorer};

/// Restores the text of one JSON string value as it arrives in pieces.
pub trait ValueRestorer: Send {
    /// Restore the next piece; may hold back a possible surrogate prefix.
    fn push(&mut self, text: &str) -> String;
    /// Everything still held back.
    fn finish(&mut self) -> String;
    /// Bytes held back.
    fn pending_len(&self) -> usize;
    /// Text that went out around this restorer, unrestored (a URL part, an
    /// incomplete escape): context for what comes next. Called with nothing
    /// held back.
    fn skip(&mut self, text: &str) {
        let _ = text;
    }
}

impl ValueRestorer for StreamRestorer {
    fn push(&mut self, text: &str) -> String {
        StreamRestorer::push(self, text)
    }
    fn finish(&mut self) -> String {
        StreamRestorer::finish(self)
    }
    fn pending_len(&self) -> usize {
        StreamRestorer::pending_len(self)
    }
    fn skip(&mut self, text: &str) {
        StreamRestorer::skip(self, text)
    }
}

/// Makes a fresh [`ValueRestorer`] for each string value.
pub type NewValueRestorer = Box<dyn Fn() -> Box<dyn ValueRestorer> + Send + Sync>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Container {
    Object { expect_key: bool },
    Array,
}

enum State {
    /// Between tokens.
    Outside,
    /// Inside an object key: copied verbatim. `escaped` after a backslash.
    Key { escaped: bool },
    /// Inside a string value: decoded and restored.
    Value,
}

/// What may come next outside strings (to notice text that is not JSON).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// A value (the start, after `:`, after `,` in an array).
    Value,
    /// A value or `]` (after `[`).
    ValueOrEnd,
    /// A key or `}` (after `{`).
    KeyOrEnd,
    /// A key (after `,` in an object).
    Key,
    Colon,
    /// `,` or the end of the container; at the top level, another value.
    CommaOrEnd,
}

pub struct JsonFragRestorer {
    new_value: NewValueRestorer,
    stack: Vec<Container>,
    state: State,
    expect: Expect,
    /// Inside a number or a `true`/`false`/`null` literal.
    literal: bool,
    /// The text stopped being JSON: everything passes through.
    broken: bool,
    restorer: Option<Box<dyn ValueRestorer>>,
    /// An escape sequence still being read (starts with `\`).
    escape: String,
    /// A high surrogate waiting for its low half (and its raw text).
    high: Option<(u16, String)>,
    /// The current value's decoded text not yet gone out (what the restorer
    /// holds back, then what it has not been given yet), the raw text it
    /// came from, and the raw length of each decoded char.
    dec: String,
    raw: String,
    raw_lens: VecDeque<usize>,
    /// Where the text not yet given to the restorer starts in `dec`.
    fresh: usize,
}

/// JSON-encode `s` as string content (no surrounding quotes).
fn escape(s: &str) -> String {
    let quoted = serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into());
    quoted[1..quoted.len() - 1].to_string()
}

impl JsonFragRestorer {
    pub fn new(engine: Engine, scope: &str) -> Self {
        let scope = scope.to_string();
        Self::with_values(Box::new(move || Box::new(engine.stream_restorer(&scope))))
    }

    /// Restore each string value with a restorer from `new_value`.
    pub fn with_values(new_value: NewValueRestorer) -> Self {
        JsonFragRestorer {
            new_value,
            stack: Vec::new(),
            state: State::Outside,
            expect: Expect::Value,
            literal: false,
            broken: false,
            restorer: None,
            escape: String::new(),
            high: None,
            dec: String::new(),
            raw: String::new(),
            raw_lens: VecDeque::new(),
            fresh: 0,
        }
    }

    /// Feed a fragment; returns the JSON text that is safe to emit now.
    pub fn push(&mut self, chunk: &str) -> String {
        let mut out = String::with_capacity(chunk.len());
        for c in chunk.chars() {
            if self.broken {
                out.push(c);
                continue;
            }
            match self.state {
                State::Outside => self.outside(c, &mut out),
                State::Key { escaped } => {
                    out.push(c);
                    self.state = match (escaped, c) {
                        (false, '\\') => State::Key { escaped: true },
                        (false, '"') => {
                            self.expect = Expect::Colon;
                            State::Outside
                        }
                        _ => State::Key { escaped: false },
                    };
                }
                State::Value => self.value(c, &mut out),
            }
        }
        if matches!(self.state, State::Value) {
            self.emit(&mut out);
        }
        out
    }

    /// Text held back: a possible surrogate prefix or an unfinished escape.
    pub fn pending_len(&self) -> usize {
        self.restorer.as_ref().map_or(0, |r| r.pending_len())
            + self.escape.len()
            + self.high.as_ref().map_or(0, |(_, raw)| raw.len())
    }

    /// Flush everything held back (the document may be truncated).
    pub fn finish(&mut self) -> String {
        let mut out = String::new();
        if matches!(self.state, State::Value) {
            let mut raw = String::new();
            if let Some((_, h)) = self.high.take() {
                raw.push_str(&h);
            }
            raw.push_str(&std::mem::take(&mut self.escape));
            self.emit(&mut out);
            // The value goes on: keep its restorer (and whatever context it
            // tracks, such as a URL guard's state).
            let r = self.restorer.get_or_insert_with(|| (self.new_value)());
            let tail = r.finish();
            self.reconcile(&tail, 0, &mut out);
            // Incomplete escapes are re-emitted as they came.
            if let Some(r) = self.restorer.as_mut() {
                r.skip(&raw);
            }
            out.push_str(&raw);
        }
        out
    }

    fn outside(&mut self, c: char, out: &mut String) {
        out.push(c);
        if !self.follows_json(c) {
            // Not JSON (prose after a bracket): from here on it passes
            // through as it came.
            self.broken = true;
            return;
        }
        match c {
            '{' => self.stack.push(Container::Object { expect_key: true }),
            '[' => self.stack.push(Container::Array),
            '}' | ']' => {
                self.stack.pop();
            }
            ':' => {
                if let Some(Container::Object { expect_key }) = self.stack.last_mut() {
                    *expect_key = false;
                }
            }
            ',' => {
                if let Some(Container::Object { expect_key }) = self.stack.last_mut() {
                    *expect_key = true;
                }
            }
            '"' => {
                if matches!(
                    self.stack.last(),
                    Some(Container::Object { expect_key: true })
                ) {
                    self.state = State::Key { escaped: false };
                } else {
                    self.state = State::Value;
                    self.restorer = Some((self.new_value)());
                }
            }
            _ => {}
        }
    }

    /// Whether `c` (outside strings) can come next in JSON text, moving the
    /// expectation on.
    fn follows_json(&mut self, c: char) -> bool {
        if c.is_ascii_whitespace() || (c == '\u{feff}' && self.at_start()) {
            self.literal = false;
            return true;
        }
        if self.literal {
            if c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.') {
                return true;
            }
            self.literal = false;
        }
        let top = self.stack.is_empty();
        let value = matches!(self.expect, Expect::Value | Expect::ValueOrEnd)
            || (top && self.expect == Expect::CommaOrEnd);
        let next = match c {
            '{' if value => Expect::KeyOrEnd,
            '[' if value => Expect::ValueOrEnd,
            '"' if value => Expect::CommaOrEnd,
            '"' if matches!(self.expect, Expect::KeyOrEnd | Expect::Key) => Expect::Colon,
            '}' if matches!(self.expect, Expect::KeyOrEnd | Expect::CommaOrEnd)
                && matches!(self.stack.last(), Some(Container::Object { .. })) =>
            {
                Expect::CommaOrEnd
            }
            ']' if matches!(self.expect, Expect::ValueOrEnd | Expect::CommaOrEnd)
                && matches!(self.stack.last(), Some(Container::Array)) =>
            {
                Expect::CommaOrEnd
            }
            ',' if self.expect == Expect::CommaOrEnd && !top => match self.stack.last() {
                Some(Container::Object { .. }) => Expect::Key,
                _ => Expect::Value,
            },
            ':' if self.expect == Expect::Colon => Expect::Value,
            '-' | '0'..='9' | 't' | 'f' | 'n'
                if matches!(self.expect, Expect::Value | Expect::ValueOrEnd) =>
            {
                self.literal = true;
                Expect::CommaOrEnd
            }
            _ => return false,
        };
        self.expect = next;
        true
    }

    fn at_start(&self) -> bool {
        self.stack.is_empty() && self.expect == Expect::Value
    }

    fn value(&mut self, c: char, out: &mut String) {
        if !self.escape.is_empty() {
            // `\u` must be followed by four hex digits. Anything else is
            // not JSON: keep what was read as literal text and read `c`
            // normally (never slice into a partial escape).
            if self.escape.starts_with("\\u") && !c.is_ascii_hexdigit() {
                self.lone_high();
                let text = std::mem::take(&mut self.escape);
                for ch in text.chars() {
                    self.literal_char(ch);
                }
            } else {
                self.escape.push(c);
                self.escape_progress();
                return;
            }
        }
        match c {
            '\\' => self.escape.push(c),
            '"' => {
                self.lone_high();
                self.emit(out);
                if let Some(mut r) = self.restorer.take() {
                    let tail = r.finish();
                    self.reconcile(&tail, 0, out);
                }
                out.push('"');
                self.state = State::Outside;
            }
            c => {
                self.lone_high();
                self.literal_char(c);
            }
        }
    }

    /// A decoded char whose raw text is itself.
    fn literal_char(&mut self, c: char) {
        let mut b = [0; 4];
        let s: &str = c.encode_utf8(&mut b);
        self.dec.push(c);
        self.raw.push_str(s);
        self.raw_lens.push_back(s.len());
    }

    /// A decoded char with its whole raw text.
    fn decoded(&mut self, c: char, raw: &str) {
        self.dec.push(c);
        self.raw.push_str(raw);
        self.raw_lens.push_back(raw.len());
    }

    /// A pending high surrogate not followed by its low half.
    fn lone_high(&mut self) {
        if let Some((_, raw)) = self.high.take() {
            self.decoded('\u{fffd}', &raw);
        }
    }

    fn escape_progress(&mut self) {
        let e = &self.escape;
        let second = e.chars().nth(1).unwrap_or(' ');
        if second == 'u' {
            // Every char after `\u` is an ASCII hex digit (see `value`).
            if e.len() < 6 {
                return;
            }
            let unit = e.get(2..6).and_then(|h| u16::from_str_radix(h, 16).ok());
            let raw = std::mem::take(&mut self.escape);
            match unit {
                Some(u @ 0xD800..=0xDBFF) => {
                    self.lone_high();
                    self.high = Some((u, raw));
                }
                Some(u @ 0xDC00..=0xDFFF) => match self.high.take() {
                    Some((h, high_raw)) => {
                        let cp =
                            0x10000 + ((u32::from(h) - 0xD800) << 10) + (u32::from(u) - 0xDC00);
                        let c = char::from_u32(cp).unwrap_or('\u{fffd}');
                        self.decoded(c, &format!("{high_raw}{raw}"));
                    }
                    None => self.decoded('\u{fffd}', &raw),
                },
                Some(u) => {
                    self.lone_high();
                    self.decoded(char::from_u32(u32::from(u)).unwrap_or('\u{fffd}'), &raw);
                }
                None => {
                    self.lone_high();
                    for ch in raw.chars() {
                        self.literal_char(ch);
                    }
                }
            }
            return;
        }
        self.lone_high();
        let raw = std::mem::take(&mut self.escape);
        let ch = match second {
            '"' => '"',
            '\\' => '\\',
            '/' => '/',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            _ => {
                // Not valid JSON; keep the text as it came.
                for ch in raw.chars() {
                    self.literal_char(ch);
                }
                return;
            }
        };
        self.decoded(ch, &raw);
    }

    /// Give the restorer the value's text it has not seen yet.
    fn emit(&mut self, out: &mut String) {
        if self.fresh >= self.dec.len() {
            return;
        }
        let Some(r) = self.restorer.as_mut() else {
            return;
        };
        let restored = r.push(&self.dec[self.fresh..]);
        let held = r.pending_len();
        self.fresh = self.dec.len();
        self.reconcile(&restored, held, out);
    }

    /// `restored` is what the restorer made of the value's text but the
    /// last `held` bytes: the chars it left alone at the start and at the
    /// end go out as they came, the span between them JSON-escaped.
    fn reconcile(&mut self, restored: &str, held: usize, out: &mut String) {
        let Some(done) = self.dec.len().checked_sub(held) else {
            // Never: a restorer holds back only text it was given.
            out.push_str(&escape(restored));
            self.clear_value_text();
            return;
        };
        let dec = &self.dec[..done];
        let count = dec.chars().count();
        let raw_done: usize = self.raw_lens.iter().take(count).sum();
        let raw = &self.raw[..raw_done];
        if restored == dec {
            out.push_str(raw);
        } else {
            let (mut d0, mut o0, mut r0, mut k0) = (0, 0, 0, 0);
            for c in dec.chars() {
                if !restored[o0..].starts_with(c) {
                    break;
                }
                d0 += c.len_utf8();
                o0 += c.len_utf8();
                r0 += self.raw_lens[k0];
                k0 += 1;
            }
            let (mut o1, mut r1, mut k1) = (restored.len(), raw_done, count);
            for c in dec[d0..].chars().rev() {
                if o1 < o0 + c.len_utf8() || !restored[o0..o1].ends_with(c) {
                    break;
                }
                o1 -= c.len_utf8();
                k1 -= 1;
                r1 -= self.raw_lens[k1];
            }
            out.push_str(&raw[..r0]);
            out.push_str(&escape(&restored[o0..o1]));
            out.push_str(&raw[r1..]);
        }
        self.dec.drain(..done);
        self.raw.drain(..raw_done);
        self.raw_lens.drain(..count);
        self.fresh = self.dec.len();
    }

    fn clear_value_text(&mut self) {
        self.dec.clear();
        self.raw.clear();
        self.raw_lens.clear();
        self.fresh = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parda_core::Config;
    use parda_detect::{PersonBlock, RulesFile, Term};
    use parda_engine::EngineOptions;
    use serde_json::{Value, json};

    const ADDR: &str = "Flat 4\\B, \"Lotus\"\nPune";

    fn engine(dir: &std::path::Path) -> Engine {
        let mut config = Config::default();
        config.detect.model = "none".into();
        Engine::open(
            EngineOptions {
                config,
                rules: RulesFile {
                    person: vec![PersonBlock {
                        name: "Ravi Kumar".into(),
                        ..Default::default()
                    }],
                    term: vec![Term {
                        text: ADDR.into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                data_dir: dir.to_path_buf(),
                use_keyring: false,
            },
            None,
        )
        .unwrap()
    }

    /// Feed `text` in pieces of `n` chars and concatenate the output.
    fn run(e: &Engine, text: &str, n: usize) -> String {
        let mut r = JsonFragRestorer::new(e.clone(), "global");
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::new();
        for piece in chars.chunks(n) {
            out.push_str(&r.push(&piece.iter().collect::<String>()));
        }
        out.push_str(&r.finish());
        out
    }

    #[test]
    fn restores_values_with_json_escaping_for_any_chunking() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let addr = e.redact(ADDR, "global").unwrap().text;
        let name = e.redact("Ravi Kumar", "global").unwrap().text;
        let doc = json!({"to": [name, {"addr": addr}], "note": "caf\u{e9} \u{1f600}", "n": 1.5, "ok": true});
        let text = doc.to_string();
        for n in 1..8 {
            let out = run(&e, &text, n);
            let v: Value =
                serde_json::from_str(&out).unwrap_or_else(|err| panic!("{n}: {err}: {out}"));
            assert_eq!(v["to"][0], "Ravi Kumar", "{n}");
            assert_eq!(v["to"][1]["addr"], ADDR, "{n}");
            assert_eq!(v["note"], "caf\u{e9} \u{1f600}");
            assert_eq!(v["n"], 1.5);
        }
    }

    #[test]
    fn escaped_surrogates_and_split_escapes_are_decoded() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let name = e.redact("Ravi Kumar", "global").unwrap().text;
        // The upstream escaped every character of the surrogate.
        let escaped: String = name.encode_utf16().map(|u| format!("\\u{u:04x}")).collect();
        let text = format!("{{\"who\": \"{escaped}\", \"k\\\"{name}\": 1}}");
        for n in 1..5 {
            let out = run(&e, &text, n);
            let v: Value = serde_json::from_str(&out).unwrap_or_else(|err| panic!("{err}: {out}"));
            assert_eq!(v["who"], "Ravi Kumar");
            // Keys are left exactly as they came.
            assert_eq!(v[format!("k\"{name}")], 1);
        }
    }

    /// Upper-cases each value, holding back a trailing `x`.
    struct Upper(String);

    impl ValueRestorer for Upper {
        fn push(&mut self, text: &str) -> String {
            self.0.push_str(text);
            let keep = if self.0.ends_with('x') { 1 } else { 0 };
            let tail = self.0.split_off(self.0.len() - keep);
            std::mem::replace(&mut self.0, tail).to_uppercase()
        }
        fn finish(&mut self) -> String {
            std::mem::take(&mut self.0).to_uppercase()
        }
        fn pending_len(&self) -> usize {
            self.0.len()
        }
    }

    #[test]
    fn values_go_through_the_given_restorer_and_are_escaped() {
        let new_value: NewValueRestorer = Box::new(|| Box::new(Upper(String::new())));
        let mut r = JsonFragRestorer::with_values(new_value);
        let mut out = String::new();
        for piece in [
            "{\"ke",
            "y\": [\"a\\\"b",
            "x\", \"\\u00e9x",
            "\"], \"n\": 1}",
        ] {
            out.push_str(&r.push(piece));
            if piece.ends_with('x') {
                assert_eq!(r.pending_len(), 1);
            }
        }
        out.push_str(&r.finish());
        let v: Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
        assert_eq!(v, json!({"key": ["A\"BX", "\u{c9}X"], "n": 1}));
    }

    /// Upper-cases everything after the first `!` it has seen: its output
    /// depends on state carried from earlier pieces.
    struct AfterBang(bool);

    impl ValueRestorer for AfterBang {
        fn push(&mut self, text: &str) -> String {
            let mut out = String::new();
            for c in text.chars() {
                out.push(if self.0 { c.to_ascii_uppercase() } else { c });
                self.0 |= c == '!';
            }
            out
        }
        fn finish(&mut self) -> String {
            String::new()
        }
        fn pending_len(&self) -> usize {
            0
        }
    }

    /// M3: a forced flush in the middle of a value keeps that value's
    /// restorer, so its state (a URL guard's, here a flag) carries on, and
    /// the rest of the value is not lost.
    #[test]
    fn finish_mid_value_keeps_the_value_restorer() {
        let new_value: NewValueRestorer = Box::new(|| Box::new(AfterBang(false)));
        let mut r = JsonFragRestorer::with_values(new_value);
        let mut out = r.push("{\"a\": \"x!y");
        out.push_str(&r.finish());
        out.push_str(&r.push("z\", \"b\": \"q"));
        out.push_str(&r.finish());
        out.push_str(&r.push("!r\"}"));
        out.push_str(&r.finish());
        let v: Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
        // A new value starts with a new restorer.
        assert_eq!(v, json!({"a": "x!YZ", "b": "q!R"}));
    }

    #[test]
    fn pending_len_counts_what_is_held_back() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let tag = e.redact("Ravi Kumar", "global").unwrap().text;
        let mut r = JsonFragRestorer::new(e.clone(), "global");
        assert_eq!(r.push("{\"a\": \"x "), "{\"a\": \"x ");
        assert_eq!(r.pending_len(), 0);
        let half = &tag[..tag.len() - 2];
        assert_eq!(r.push(half), "");
        assert_eq!(r.pending_len(), half.len());
        r.push("\\u00");
        assert_eq!(r.pending_len(), half.len() + 4);
        assert_eq!(r.finish(), format!("{half}\\u00"));
        assert_eq!(r.pending_len(), 0);
    }

    #[test]
    fn truncated_documents_flush_their_tail() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        assert_eq!(run(&e, "{\"q\": \"abc\\u00", 3), "{\"q\": \"abc\\u00");
        assert_eq!(run(&e, "{\"q\": \"x\\ud83d", 2), "{\"q\": \"x\\ud83d");
    }

    /// Review finding (fix round 1b): string content that is not restored
    /// goes out exactly as it came (escapes included); only a restored
    /// value is JSON-escaped.
    #[test]
    fn unchanged_text_is_copied_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let name = e.redact("Ravi Kumar", "global").unwrap().text;
        let addr = e.redact(ADDR, "global").unwrap().text;
        let text = format!(
            "{{\"a\": \"C:\\\\Users \\/x \\u00e9 caf\u{e9} \\ud83d\\ude00\", \
             \"b\": \"x\\/ {name} \\u00e9\\n\", \"c\": \"\\t{addr}\\r\"}}"
        );
        let quoted = serde_json::to_string(ADDR).unwrap();
        let want = text
            .replace(&name, "Ravi Kumar")
            .replace(&addr, &quoted[1..quoted.len() - 1]);
        for n in 1..9 {
            assert_eq!(run(&e, &text, n), want, "{n}");
        }
    }

    /// Review finding (fix round 1b): text that stops being JSON (prose
    /// after a bracket) passes through from there on, unrestored and
    /// unchanged; JSON values one after another are still JSON.
    #[test]
    fn text_that_stops_being_json_passes_through() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let name = e.redact("Ravi Kumar", "global").unwrap().text;
        for (text, want) in [
            (
                format!("[\"a\"] and {name} said \"C:\\Users\""),
                format!("[\"a\"] and {name} said \"C:\\Users\""),
            ),
            (
                format!("{{\"k\": \"{name}\"}} then \"{name}\""),
                format!("{{\"k\": \"Ravi Kumar\"}} then \"{name}\""),
            ),
            (
                format!("{{\"k\": nope, \"v\": \"{name}\"}}"),
                "{\"k\": nope, \"v\": \"Ravi Kumar\"}".to_string(),
            ),
            (
                format!("{{\"k\": 1 2, \"v\": \"{name}\"}}"),
                format!("{{\"k\": 1 2, \"v\": \"{name}\"}}"),
            ),
            (
                format!("{{\"a\":\"{name}\"}}\n[\"{name}\", 1.5e3, true, null]"),
                "{\"a\":\"Ravi Kumar\"}\n[\"Ravi Kumar\", 1.5e3, true, null]".to_string(),
            ),
        ] {
            for n in 1..6 {
                assert_eq!(run(&e, &text, n), want, "{text} {n}");
            }
        }
    }

    #[test]
    fn malformed_unicode_escapes_never_panic_and_stay_literal() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let name = e.redact("Ravi Kumar", "global").unwrap().text;
        // Non-ASCII (or non-hex) where hex digits belong: `&e[2..6]` used to
        // cut a char in half. The bad escape goes out as it came and the
        // document after it is still restored.
        for bad in [
            "\\uabc\u{e9}",
            "\\uaa\u{20ac}",
            "\\u\u{1f600}\u{1f600}",
            "\\u12\u{e9}\u{e9}",
            "\\uzzzz",
            "\\u+123",
            "\\u12",
            "\\u\u{e9}",
            "\\\u{e9}",
        ] {
            let text = format!("{{\"a\": \"x{bad}y\", \"b\": \"{name}\"}}");
            for n in 1..8 {
                let out = run(&e, &text, n);
                assert_eq!(out, text.replace(&name, "Ravi Kumar"), "{bad} {n}");
            }
        }
    }
}
