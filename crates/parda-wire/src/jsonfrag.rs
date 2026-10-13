//! Restoring surrogates in a JSON document that arrives in fragments
//! (streamed tool-call arguments: `input_json_delta.partial_json`,
//! `delta.tool_calls[].function.arguments`,
//! `response.function_call_arguments.delta`).
//!
//! The fragments are JSON *text*, so a real value with `"`, `\` or a line
//! break cannot be pasted in verbatim. Each string value is decoded, run
//! through its own [`StreamRestorer`], and re-encoded; keys and everything
//! outside strings pass through unchanged. Escapes split across fragments
//! are held until complete.

use parda_engine::{Engine, StreamRestorer};

/// Restores the text of one JSON string value as it arrives in pieces.
pub trait ValueRestorer: Send {
    /// Restore the next piece; may hold back a possible surrogate prefix.
    fn push(&mut self, text: &str) -> String;
    /// Everything still held back.
    fn finish(&mut self) -> String;
    /// Bytes held back.
    fn pending_len(&self) -> usize;
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

pub struct JsonFragRestorer {
    new_value: NewValueRestorer,
    stack: Vec<Container>,
    state: State,
    restorer: Option<Box<dyn ValueRestorer>>,
    /// An escape sequence still being read (starts with `\`).
    escape: String,
    /// A high surrogate waiting for its low half (and its raw text).
    high: Option<(u16, String)>,
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
            restorer: None,
            escape: String::new(),
            high: None,
        }
    }

    /// Feed a fragment; returns the JSON text that is safe to emit now.
    pub fn push(&mut self, chunk: &str) -> String {
        let mut out = String::with_capacity(chunk.len());
        let mut decoded = String::new();
        for c in chunk.chars() {
            match self.state {
                State::Outside => self.outside(c, &mut out),
                State::Key { escaped } => {
                    out.push(c);
                    self.state = match (escaped, c) {
                        (false, '\\') => State::Key { escaped: true },
                        (false, '"') => State::Outside,
                        _ => State::Key { escaped: false },
                    };
                }
                State::Value => self.value(c, &mut decoded, &mut out),
            }
        }
        if matches!(self.state, State::Value) {
            self.emit(&decoded, &mut out);
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
            if let Some(mut r) = self.restorer.take() {
                out.push_str(&escape(&r.finish()));
            }
            // Incomplete escapes are re-emitted as they came.
            out.push_str(&raw);
            self.restorer = Some((self.new_value)());
        }
        out
    }

    fn outside(&mut self, c: char, out: &mut String) {
        out.push(c);
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

    fn value(&mut self, c: char, decoded: &mut String, out: &mut String) {
        if !self.escape.is_empty() {
            // `\u` must be followed by four hex digits. Anything else is
            // not JSON: keep what was read as literal text and read `c`
            // normally (never slice into a partial escape).
            if self.escape.starts_with("\\u") && !c.is_ascii_hexdigit() {
                self.lone_high(decoded);
                decoded.push_str(&std::mem::take(&mut self.escape));
            } else {
                self.escape.push(c);
                self.escape_progress(decoded);
                return;
            }
        }
        match c {
            '\\' => self.escape.push(c),
            '"' => {
                self.lone_high(decoded);
                self.emit(decoded, out);
                decoded.clear();
                if let Some(mut r) = self.restorer.take() {
                    out.push_str(&escape(&r.finish()));
                }
                out.push('"');
                self.state = State::Outside;
            }
            c => {
                self.lone_high(decoded);
                decoded.push(c);
            }
        }
    }

    /// A pending high surrogate not followed by its low half.
    fn lone_high(&mut self, decoded: &mut String) {
        if self.high.take().is_some() {
            decoded.push('\u{fffd}');
        }
    }

    fn escape_progress(&mut self, decoded: &mut String) {
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
                    self.lone_high(decoded);
                    self.high = Some((u, raw));
                }
                Some(u @ 0xDC00..=0xDFFF) => match self.high.take() {
                    Some((h, _)) => {
                        let cp =
                            0x10000 + ((u32::from(h) - 0xD800) << 10) + (u32::from(u) - 0xDC00);
                        decoded.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                    }
                    None => decoded.push('\u{fffd}'),
                },
                Some(u) => {
                    self.lone_high(decoded);
                    decoded.push(char::from_u32(u32::from(u)).unwrap_or('\u{fffd}'));
                }
                None => {
                    self.lone_high(decoded);
                    decoded.push_str(&raw);
                }
            }
            return;
        }
        self.lone_high(decoded);
        let ch = match second {
            '"' => '"',
            '\\' => '\\',
            '/' => '/',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            other => {
                // Not valid JSON; keep the text as it came.
                decoded.push('\\');
                other
            }
        };
        decoded.push(ch);
        self.escape.clear();
    }

    fn emit(&mut self, decoded: &str, out: &mut String) {
        if decoded.is_empty() {
            return;
        }
        if let Some(r) = self.restorer.as_mut() {
            out.push_str(&escape(&r.push(decoded)));
        }
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

    #[test]
    fn malformed_unicode_escapes_never_panic_and_stay_literal() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let name = e.redact("Ravi Kumar", "global").unwrap().text;
        // Non-ASCII (or non-hex) where hex digits belong: `&e[2..6]` used to
        // cut a char in half. The bad escape becomes literal text and the
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
                let v: Value = serde_json::from_str(&out)
                    .unwrap_or_else(|err| panic!("{bad} {n}: {err}: {out}"));
                assert_eq!(v["a"], format!("x{bad}y"), "{bad} {n}");
                assert_eq!(v["b"], "Ravi Kumar", "{bad} {n}");
            }
        }
    }
}
