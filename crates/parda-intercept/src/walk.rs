//! Which strings of an intercepted request are text to redact, and reading
//! them in every way the site's server may read them.
//!
//! Redaction walks a request twice in the same order: once to collect the
//! texts (one engine batch), once to write the results back.
//!
//! Nothing is skipped: every string, key and number is visited. Identifiers a
//! site needs verbatim (values under identifier keys, or identifier-looking
//! values) are visited as [`Tier::Identifier`] — the engine's dictionary and
//! rule tiers still see them, only the ML model does not — and only when they
//! are identifier-shaped ([`id_shaped`]); anything else is text. Keys follow
//! the same rule.
//!
//! One reader serves every body, multipart field, form value and JSON string,
//! whatever its declared type ([`read_text`]): a text is read literally, and
//! as JSON of any kind (one value or one per line, after whitespace, BOMs and
//! RFC 7464 record separators) or, when it holds `%XX`, `+` or `=`, decoded as
//! a form; each string, key, number, form key and value inside is read the
//! same ways in turn, a few levels deep. What any reading finds is replaced in
//! the raw text, encoded as each layer needs, so no reading of what goes out
//! holds it. Text that looks like escaped JSON but is not JSON is refused.

use parda_wire::body::JsonError;
use serde_json::Value;

use crate::hosts::HostList;
use crate::sites::Site;

/// How a string is redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tier {
    /// Every engine tier, the ML model included.
    Text,
    /// An identifier the site needs verbatim: the dictionary and rule tiers
    /// only (an e-mail, phone or key in it is still redacted), never the ML
    /// model, which could mistake an id or an enum word for a name.
    Identifier,
}

/// One value the engine replaced in a visited string: its byte range in the
/// string as it was visited, and what took its place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Found {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) surrogate: String,
    pub(crate) kind: String,
}

/// Receives the strings of a request to redact (collects them, or writes
/// the engine's results back).
pub(crate) trait Sink {
    /// Visit one string; may replace it.
    fn visit(&mut self, s: &mut String, tier: Tier);
    /// What the last [`Sink::visit`] replaced, in the string as it was
    /// visited; `None` when this sink cannot say.
    fn found(&self) -> Option<&[Found]> {
        None
    }
    /// One replacement of the visits so far was not used (the same value
    /// was found again in another reading of the same text): do not count
    /// it.
    fn forget(&mut self, kind: &str) {
        let _ = kind;
    }
}

impl<F: FnMut(&mut String, Tier)> Sink for F {
    fn visit(&mut self, s: &mut String, tier: Tier) {
        self(s, tier);
    }
}

/// Visits one string to redact; may replace it.
pub(crate) type Visit<'a> = &'a mut dyn Sink;

/// Longest value that may be treated as an identifier.
const MAX_ID_LEN: usize = 64;

/// Identifier-shaped: 1–64 characters of `[A-Za-z0-9_.:/+=-]` (UUIDs, hex,
/// base64 tokens, enum words). Only such values may skip the ML model;
/// anything with a space, an `@` and so on is text wherever it sits.
pub(crate) fn id_shaped(s: &str) -> bool {
    (1..=MAX_ID_LEN).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:/+=-".contains(&c))
}

/// What decides which strings are text.
pub(crate) struct Rules<'a> {
    /// The intercepted hosts: links to them are identifiers.
    pub(crate) hosts: &'a HostList,
    /// `intercept.skip_keys` (patterns).
    pub(crate) extra: &'a [String],
    pub(crate) site: Option<&'static Site>,
}

/// Shortest hex string taken for an identifier.
const MIN_HEX_ID: usize = 16;
/// Shortest base64 / base64url string taken for an identifier.
const MIN_BASE64_ID: usize = 32;

/// Keys whose values are what the user typed: always text, even when a value
/// looks like an identifier (a bare API key sent as a message), and JSON
/// typed there is text too.
const CONTENT_KEYS: &[&str] = &[
    "text",
    "parts",
    "content",
    "prompt",
    "message",
    "query",
    "query_str",
    "q",
    "input",
    "question",
    "instructions",
    "sensitive_string_value",
];

/// Identifier keys (lower-case patterns). Identifier-shaped values under
/// them skip the ML model.
const SKIP_KEYS: &[&str] = &[
    "id",
    "*_id",
    "*_ids",
    "uuid",
    "*_uuid",
    "*model*",
    "token",
    "*_token",
    "nonce",
    "signature",
    "timestamp",
    "*_time",
    "created*",
    "parent*",
    "organization*",
    "locale",
    "timezone",
    "client_*",
    "arkose*",
    "sentinel*",
    "action",
    "type",
    "role",
    "author",
    "status",
];

/// camelCase identifier suffixes (`conversationId`, `csrfToken`), matched
/// with case so that `paid` or `valid` stay text.
const SKIP_SUFFIXES: &[&str] = &["Id", "ID", "Ids", "IDs", "Uuid", "UUID", "Token", "Nonce"];

/// `pattern` with `*` wildcards matches `key`, ignoring ASCII case.
pub(crate) fn glob(pattern: &str, key: &str) -> bool {
    let p = pattern.as_bytes();
    let k = key.as_bytes();
    // Classic wildcard match with backtracking to the last `*`.
    let (mut pi, mut ki) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ki < k.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ki));
            pi += 1;
        } else if pi < p.len() && p[pi].eq_ignore_ascii_case(&k[ki]) {
            pi += 1;
            ki += 1;
        } else if let Some((sp, sk)) = star {
            pi = sp + 1;
            ki = sk + 1;
            star = Some((sp, sk + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

fn is_content_key(key: &str) -> bool {
    CONTENT_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key))
}

fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Long hex with at least one letter: a digit-only string may be a card or
/// account number, so the engine sees it.
fn is_hex_id(s: &str) -> bool {
    s.len() >= MIN_HEX_ID
        && s.bytes().all(|c| c.is_ascii_hexdigit())
        && s.bytes().any(|c| c.is_ascii_alphabetic())
}

fn is_base64_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'-' | b'_')
}

fn is_base64_id(s: &str) -> bool {
    s.len() >= MIN_BASE64_ID
        && s.bytes().all(is_base64_char)
        && s.bytes().any(|c| c.is_ascii_alphabetic())
}

/// A JSON web token: `eyJ…` and three base64url segments.
fn is_jwt(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    s.starts_with("eyJ")
        && parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(is_base64_char))
}

impl Rules<'_> {
    /// Identifier-shaped values under this key skip the ML model.
    pub(crate) fn skip_key(&self, key: &str) -> bool {
        SKIP_SUFFIXES
            .iter()
            .any(|s| key.len() > s.len() && key.ends_with(s))
            || SKIP_KEYS.iter().any(|p| glob(p, key))
            || self
                .site
                .is_some_and(|site| site.skip_keys.iter().any(|p| glob(p, key)))
            || self.extra.iter().any(|p| glob(p, key))
    }

    /// Does `value` look like an identifier the site needs verbatim (whatever
    /// its key)? Only identifier-shaped values ([`id_shaped`]) are then
    /// treated as identifiers.
    pub(crate) fn is_identifier(&self, value: &str) -> bool {
        is_uuid(value)
            || is_hex_id(value)
            || is_base64_id(value)
            || is_jwt(value)
            || self.is_own_link(value)
    }

    /// A link to one of the intercepted sites.
    fn is_own_link(&self, value: &str) -> bool {
        if value.contains(char::is_whitespace) {
            return false;
        }
        reqwest::Url::parse(value).is_ok_and(|u| {
            matches!(u.scheme(), "http" | "https")
                && u.host_str().is_some_and(|h| self.hosts.matches(h))
        })
    }
}

/// A request parda cannot filter safely: a multipart body it cannot split,
/// JSON that names a key twice (here or inside a string), text that looks
/// like escaped JSON but is not JSON, or a rewrite that would change the
/// shape of the JSON (two keys that would become the same tag).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Malformed;

/// What a text is to the site: decides its tier, and how the texts read
/// inside it are treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// The value of a content key (`prompt`, `parts`, …): what the user
    /// typed, always text. An object there has members by the key rules;
    /// JSON in a string there is [`Role::Typed`].
    Content,
    /// Read inside what the user typed: always text. JSON in it is read too
    /// (its keys get no say), but text that only looks like JSON is not
    /// refused: what the user typed is not parsed by the site, and may well
    /// be broken JSON (a question about code).
    Typed,
    /// A whole body, or a part of one read decoded: text. JSON in it
    /// follows the key rules; a form in it does not (what a body holds is
    /// what the user sent).
    Body,
    /// A declared form body or a query string: text, its keys and values
    /// by the key rules.
    Form,
    /// A value under a key (`skipped`: an identifier key), an array item,
    /// or a string in a document: an identifier when identifier-shaped and
    /// under an identifier key or identifier-looking.
    Value { skipped: bool },
    /// An object or form key: an identifier when identifier-shaped and a
    /// known protocol key or identifier-looking.
    Key,
    /// Read inside an identifier: an identifier too.
    Ident,
}

impl Role {
    fn tier(self, s: &str, rules: &Rules<'_>) -> Tier {
        let id = match self {
            Role::Content | Role::Typed | Role::Body | Role::Form => false,
            Role::Ident => true,
            Role::Value { skipped } => id_shaped(s) && (skipped || rules.is_identifier(s)),
            Role::Key => {
                id_shaped(s) && (rules.skip_key(s) || is_content_key(s) || rules.is_identifier(s))
            }
        };
        if id { Tier::Identifier } else { Tier::Text }
    }

    /// A value under `key`: a JSON member, a form value, a multipart field.
    pub(crate) fn member(self, key: &str, rules: &Rules<'_>) -> Role {
        match self {
            Role::Typed | Role::Ident => self,
            _ if is_content_key(key) => Role::Content,
            _ => Role::Value {
                skipped: rules.skip_key(key),
            },
        }
    }

    fn key(self) -> Role {
        match self {
            Role::Typed | Role::Ident => self,
            _ => Role::Key,
        }
    }

    /// A JSON value read in a text with this role: a lone value is what the
    /// text was (a body stays a body); JSON in a string starts afresh.
    fn json_root(self) -> Role {
        match self {
            Role::Form => Role::Body,
            Role::Content => Role::Typed,
            Role::Value { .. } | Role::Key => Role::Value { skipped: false },
            other => other,
        }
    }

    /// The items of an array with this role.
    fn item(self) -> Role {
        match self {
            Role::Body | Role::Form => Role::Value { skipped: false },
            other => other,
        }
    }

    /// What the user typed: never refused for looking like broken JSON, and
    /// a key given twice in JSON there is read, not refused.
    fn typed(self) -> bool {
        matches!(self, Role::Content | Role::Typed)
    }

    /// Forms read in texts with this role follow the key rules: declared
    /// forms, query strings, and strings in documents (URLs).
    fn form_keys(self) -> bool {
        matches!(self, Role::Form | Role::Value { .. } | Role::Key)
    }
}

/// How many levels readings nest (a form-decoded part, a JSON string); past
/// this a text is read literally only.
const MAX_DEPTH: usize = 4;

/// Characters a reader may skip around a JSON text: JSON and Unicode
/// whitespace (`\f`, `\v`, NBSP, U+2028, …), a byte-order mark, and the
/// separators FS, GS, RS (RFC 7464 records) and US, which Python's
/// `strip()` drops.
fn skippable(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{feff}' | '\u{1c}'..='\u{1f}' | '\u{180e}')
}

/// Characters that end a line of JSON values (none may stand raw in a JSON
/// string).
fn line_break(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1c}'..='\u{1e}')
}

/// `s[start..end]` without skippable characters around it.
fn trimmed(s: &str, start: usize, end: usize) -> std::ops::Range<usize> {
    let t = &s[start..end];
    let lead = t.len() - t.trim_start_matches(skippable).len();
    start + lead..start + lead + t.trim_matches(skippable).len()
}

/// The lines of `s` (byte ranges, without their breaks).
fn lines(s: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, c) in s.char_indices() {
        if line_break(c) {
            out.push((start, i));
            start = i + c.len_utf8();
        }
    }
    out.push((start, s.len()));
    out
}

fn opens_json(t: &str) -> bool {
    t.starts_with(['{', '[', '"'])
}

/// Is `json` one JSON value? One that names a key twice is refused when
/// `strict` (parsers keep different ones of the two), else valid JSON.
fn parses(json: &str, strict: bool) -> Result<bool, Malformed> {
    match parda_wire::body::parse_json_unique(json.as_bytes()) {
        Ok(_) => Ok(true),
        Err(JsonError::DuplicateKey) if strict => Err(Malformed),
        Err(JsonError::DuplicateKey) => {
            Ok(serde_json::from_str::<serde::de::IgnoredAny>(json).is_ok())
        }
        Err(JsonError::Invalid) => Ok(false),
    }
}

/// `text` as JSON: the byte ranges of its values. One value (after
/// skippable characters), else every line that is one (JSON lines, RFC
/// 7464 records, or a JSON line among text, such as a multipart field read
/// as text); at least one of them a string, object or array. See
/// [`parses`] for `strict`.
fn json_docs(text: &str, strict: bool) -> Result<Vec<std::ops::Range<usize>>, Malformed> {
    let whole = trimmed(text, 0, text.len());
    if opens_json(&text[whole.clone()]) && parses(&text[whole.clone()], strict)? {
        return Ok(vec![whole]);
    }
    let mut docs = Vec::new();
    for (a, b) in lines(text) {
        let r = trimmed(text, a, b);
        if !r.is_empty() && parses(&text[r.clone()], strict)? {
            docs.push(r);
        }
    }
    if !docs.iter().any(|r| opens_json(&text[r.clone()])) {
        docs.clear();
    }
    Ok(docs)
}

/// Is `text` one JSON value (after skippable characters)? For bodies and
/// fields declared as JSON. A key given twice is refused.
pub(crate) fn is_json_document(text: &str) -> Result<bool, Malformed> {
    let r = trimmed(text, 0, text.len());
    match parda_wire::body::parse_json_unique(text[r].as_bytes()) {
        Ok(_) => Ok(true),
        Err(JsonError::DuplicateKey) => Err(Malformed),
        Err(JsonError::Invalid) => Ok(false),
    }
}

/// Text (outside the JSON values `docs` of it) that looks like escaped
/// JSON but is not JSON: a lenient reader would decode escapes that glue a
/// letter to the value (`\n9876543210`) when read literally, so it cannot
/// be filtered safely. In a whole body or field (`top`): the text when it
/// starts like JSON, or a line of it that does, holding a backslash. In a
/// text inside one: the whole text, bracketed like JSON (`{…}`, `[…]`,
/// `"…"`) and holding a backslash.
fn looks_like_escaped_json(text: &str, docs: &[std::ops::Range<usize>], top: bool) -> bool {
    if !text.contains('\\') {
        return false;
    }
    let t = &text[trimmed(text, 0, text.len())];
    if docs.is_empty() && !top {
        return t.len() >= 2
            && matches!(
                (t.as_bytes()[0], t.as_bytes()[t.len() - 1]),
                (b'{', b'}') | (b'[', b']') | (b'"', b'"')
            );
    }
    let read =
        |r: &std::ops::Range<usize>| docs.iter().any(|d| d.start <= r.start && r.end <= d.end);
    if !top {
        return false;
    }
    (docs.is_empty() && opens_json(t))
        || lines(text).into_iter().any(|(a, b)| {
            let r = trimmed(text, a, b);
            let line = &text[r.clone()];
            line.contains('\\') && opens_json(line) && !read(&r)
        })
}

/// A valid `%XX` escape is in `s`.
fn has_escape(s: &str) -> bool {
    s.as_bytes()
        .windows(3)
        .any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
}

/// Decode a form component (`+` a space, `%XX` a byte; anything else as it
/// is), with, for each byte of the result, the raw range it came from. Bytes
/// that are not UTF-8 once decoded become U+FFFD.
fn decode_mapped(raw: &str) -> (String, Vec<(usize, usize)>) {
    let b = raw.as_bytes();
    let mut bytes = Vec::with_capacity(b.len());
    let mut from = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match b[i] {
            b'+' => {
                bytes.push(b' ');
                from.push((i, i + 1));
                i += 1;
            }
            b'%' if i + 2 < b.len() && hex(b[i + 1]).is_some() && hex(b[i + 2]).is_some() => {
                let v = hex(b[i + 1]).unwrap_or(0) * 16 + hex(b[i + 2]).unwrap_or(0);
                bytes.push(v as u8);
                from.push((i, i + 3));
                i += 3;
            }
            c => {
                bytes.push(c);
                from.push((i, i + 1));
                i += 1;
            }
        }
    }
    let mut text = String::with_capacity(bytes.len());
    let mut map = Vec::with_capacity(bytes.len());
    let mut at = 0;
    for chunk in bytes.utf8_chunks() {
        let valid = chunk.valid();
        text.push_str(valid);
        map.extend_from_slice(&from[at..at + valid.len()]);
        at += valid.len();
        let bad = chunk.invalid().len();
        if bad > 0 {
            let range = (from[at].0, from[at + bad - 1].1);
            text.push('\u{fffd}');
            map.extend_from_slice(&[range; 3]);
            at += bad;
        }
    }
    (text, map)
}

/// One form-encoded component: `+` is a space, `%XX` a byte.
fn decode_component(s: &str) -> String {
    decode_mapped(s).0
}

/// Percent-encode everything but unreserved characters (`%20` for a space:
/// right in a path, a query and a form alike).
fn encode_all(s: &str) -> String {
    const SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    percent_encoding::utf8_percent_encode(s, SET).to_string()
}

/// `s` as the content of a JSON string.
fn json_escape(s: &str) -> String {
    let quoted = Value::String(s.to_string()).to_string();
    quoted[1..quoted.len() - 1].to_string()
}

/// The text of the JSON string content `raw[start..end]` (valid JSON),
/// with, for each byte of it, the raw range it was read from: a whole
/// escape (a surrogate pair is one), or a whole character. A lone
/// surrogate reads as U+FFFD.
fn unescape(raw: &str, start: usize, end: usize) -> (String, Vec<(usize, usize)>) {
    let b = raw.as_bytes();
    let hex = |i: usize| {
        let h = b.get(i..i + 4)?;
        h.iter()
            .all(u8::is_ascii_hexdigit)
            .then(|| u32::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok())
            .flatten()
    };
    let mut text = String::with_capacity(end - start);
    let mut map = Vec::with_capacity(end - start);
    let mut i = start;
    while i < end {
        let (c, len) = match (b[i], b.get(i + 1)) {
            (b'\\', Some(b'u')) => match hex(i + 2) {
                Some(hi @ 0xD800..=0xDBFF) => match (b.get(i + 6), b.get(i + 7), hex(i + 8)) {
                    (Some(b'\\'), Some(b'u'), Some(lo @ 0xDC00..=0xDFFF)) => (
                        char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
                            .unwrap_or('\u{fffd}'),
                        12,
                    ),
                    _ => ('\u{fffd}', 6),
                },
                Some(u) => (char::from_u32(u).unwrap_or('\u{fffd}'), 6),
                None => ('\\', 1),
            },
            (b'\\', Some(&e)) if b"\"\\/bfnrt".contains(&e) => (
                match e {
                    b'b' => '\u{8}',
                    b'f' => '\u{c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    other => other as char,
                },
                2,
            ),
            _ => {
                let c = raw[i..].chars().next().unwrap_or('\u{fffd}');
                (c, c.len_utf8())
            }
        };
        text.push(c);
        map.extend(std::iter::repeat_n((i, i + len), c.len_utf8()));
        i += len;
    }
    (text, map)
}

/// A string or number of a JSON text.
struct Token {
    /// The raw range: a string's content (inside its quotes), a number.
    start: usize,
    end: usize,
    num: bool,
    role: Role,
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while matches!(b.get(i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        i += 1;
    }
    i
}

/// The index of the quote that ends the JSON string whose opening quote is
/// at `i`.
fn string_end(b: &[u8], i: usize) -> usize {
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return j,
            _ => j += 1,
        }
    }
    b.len()
}

/// The strings (keys too) and numbers of the valid JSON value at `i` in
/// `raw`, in order, with their roles; returns where the value ends.
fn scan_json(raw: &str, i: usize, role: Role, rules: &Rules<'_>, out: &mut Vec<Token>) -> usize {
    let b = raw.as_bytes();
    let i = skip_ws(b, i);
    match b.get(i) {
        Some(b'{') => {
            let mut i = skip_ws(b, i + 1);
            while b.get(i) == Some(&b'"') {
                let end = string_end(b, i);
                let key = unescape(raw, i + 1, end).0;
                out.push(Token {
                    start: i + 1,
                    end,
                    num: false,
                    role: role.key(),
                });
                // Past the `:`.
                i = skip_ws(b, end + 1) + 1;
                i = skip_ws(b, scan_json(raw, i, role.member(&key, rules), rules, out));
                if b.get(i) == Some(&b',') {
                    i = skip_ws(b, i + 1);
                }
            }
            i + 1
        }
        Some(b'[') => {
            let mut i = skip_ws(b, i + 1);
            while i < b.len() && b[i] != b']' {
                i = skip_ws(b, scan_json(raw, i, role.item(), rules, out));
                if b.get(i) == Some(&b',') {
                    i += 1;
                }
            }
            i + 1
        }
        Some(b'"') => {
            let end = string_end(b, i);
            out.push(Token {
                start: i + 1,
                end,
                num: false,
                role,
            });
            end + 1
        }
        Some(b't' | b'n') => i + 4,
        Some(b'f') => i + 5,
        Some(_) => {
            let start = i;
            let mut i = i + 1;
            while matches!(
                b.get(i),
                Some(b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
            ) {
                i += 1;
            }
            out.push(Token {
                start,
                end: i,
                num: true,
                role,
            });
            i
        }
        None => i,
    }
}

/// A text read inside another (a JSON string or number, a form key, value
/// or piece), to be read again in every way.
struct Part {
    /// Its raw range in the outer text.
    start: usize,
    end: usize,
    /// As the outer reading reads it.
    text: String,
    /// For each byte of `text`, the raw range it was read from.
    map: Vec<(usize, usize)>,
    role: Role,
    /// An identifier (rules only): hidden from the literal reading.
    ident: bool,
    /// A JSON number.
    num: bool,
    /// A number under an identifier key (a timestamp, a counter): kept as
    /// written, never read (a 10-digit timestamp reads like a phone).
    verbatim: bool,
    /// Read form-decoded: what replaces encoded text is encoded.
    percent: bool,
    /// A key or value of a form with key rules: what replaces any of it
    /// is encoded.
    encode: bool,
}

impl Part {
    fn json(raw: &str, t: Token, rules: &Rules<'_>) -> Part {
        if t.num {
            // Numbers are text (only the rules find values in them), but
            // under an identifier key they are identifiers.
            let verbatim = t.role == Role::Value { skipped: true };
            return Part {
                start: t.start,
                end: t.end,
                text: raw[t.start..t.end].to_string(),
                map: (t.start..t.end).map(|i| (i, i + 1)).collect(),
                role: Role::Ident,
                ident: verbatim,
                num: true,
                verbatim,
                percent: false,
                encode: false,
            };
        }
        let (text, map) = unescape(raw, t.start, t.end);
        Part {
            start: t.start,
            end: t.end,
            ident: t.role.tier(&text, rules) == Tier::Identifier,
            text,
            map,
            role: t.role,
            num: false,
            verbatim: false,
            percent: false,
            encode: false,
        }
    }

    fn form(
        raw: &str,
        start: usize,
        end: usize,
        role: Role,
        encode: bool,
        rules: &Rules<'_>,
    ) -> Part {
        let (text, map) = decode_mapped(&raw[start..end]);
        Part {
            start,
            end,
            ident: role.tier(&text, rules) == Tier::Identifier,
            text,
            map: map
                .into_iter()
                .map(|(a, b)| (a + start, b + start))
                .collect(),
            role,
            num: false,
            verbatim: false,
            percent: true,
            encode,
        }
    }

    /// An edit of this part's text, in the outer text's coordinates.
    fn lift(&self, raw: &str, e: Edit, view: usize) -> Edit {
        let start = self.map.get(e.start).map_or(self.end, |m| m.0);
        let end = match e.end.checked_sub(1) {
            Some(last) if e.end > e.start => self.map.get(last).map_or(self.end, |m| m.1),
            _ => start,
        };
        let encoded =
            self.encode || (self.percent && raw.get(start..end) != self.text.get(e.start..e.end));
        Edit {
            start,
            end,
            text: e.text,
            kinds: e.kinds,
            view,
            encoded,
        }
    }

    /// `start..end` (inside this part) widened to whole escapes.
    fn align(&self, start: usize, end: usize) -> (usize, usize) {
        let k = self.map.partition_point(|m| m.0 <= start);
        let start = if k > 0 { self.map[k - 1].0 } else { start };
        if end <= start {
            return (start, start);
        }
        let k = self.map.partition_point(|m| m.1 < end);
        (start, self.map.get(k).map_or(end, |m| m.1))
    }

    fn overlaps(&self, e: &Edit) -> bool {
        if e.start == e.end {
            return self.start <= e.start && e.start <= self.end;
        }
        self.start < e.end && e.start < self.end
    }
}

/// The other readings of a text: its JSON values, and the parts read in
/// them and in the text between them (form-decoded, when it holds `%XX`,
/// `+` or `=`).
struct View {
    parts: Vec<Part>,
    /// The byte ranges of the JSON values.
    docs: Vec<std::ops::Range<usize>>,
    /// A key given twice in the JSON is refused.
    strict: bool,
}

impl View {
    fn plain() -> View {
        View {
            parts: Vec::new(),
            docs: Vec::new(),
            strict: true,
        }
    }

    /// `top`: a whole body or multipart field.
    fn of(raw: &str, role: Role, top: bool, rules: &Rules<'_>) -> Result<View, Malformed> {
        // What the user typed is not parsed by the site: a key given twice
        // there is no reason to refuse it (every token is read anyway).
        let strict = !role.typed();
        let docs = json_docs(raw, strict)?;
        if strict && looks_like_escaped_json(raw, &docs, top) {
            return Err(Malformed);
        }
        let mut tokens = Vec::new();
        for d in &docs {
            scan_json(raw, d.start, role.json_root(), rules, &mut tokens);
        }
        let mut parts: Vec<Part> = tokens
            .into_iter()
            .map(|t| Part::json(raw, t, rules))
            .collect();
        // The text outside the JSON values.
        let mut at = 0;
        for (a, b) in docs
            .iter()
            .map(|d| (d.start, d.end))
            .chain([(raw.len(), raw.len())])
        {
            let gap = &raw[at..a];
            if has_escape(gap) || gap.contains(['+', '=']) {
                parts.extend(form_parts(raw, at, a, role, rules));
            }
            at = b;
        }
        parts.sort_by_key(|p| p.start);
        Ok(View {
            parts,
            docs,
            strict,
        })
    }

    fn in_doc(&self, start: usize, end: usize) -> bool {
        self.docs.iter().any(|d| d.start <= start && end <= d.end)
    }
}

/// The keys, values and pieces of `raw[from..to]` read as a form: split at
/// `&`, then at the first `=`. In a form with key rules, a URL before a
/// query key (`https://x/p?key=…`) is a part of its own. A part that is
/// neither an identifier nor JSON-looking is split again at `/`, `?` and
/// `#` (URL path segments, queries and fragments are decoded on their own).
fn form_parts(raw: &str, from: usize, to: usize, role: Role, rules: &Rules<'_>) -> Vec<Part> {
    let encode = role.form_keys();
    let mut parts = Vec::new();
    let mut add = |a: usize, b: usize, role: Role| {
        if a >= b {
            return;
        }
        let whole = Part::form(raw, a, b, role, encode, rules);
        let t = raw[a..b].trim_matches(skippable);
        if whole.ident || opens_json(t) || !t.contains(['/', '?', '#']) {
            parts.push(whole);
            return;
        }
        let mut s = a;
        for (i, c) in raw[a..b].char_indices() {
            if matches!(c, '/' | '?' | '#') {
                if a + i > s {
                    parts.push(Part::form(raw, s, a + i, role, encode, rules));
                }
                s = a + i + 1;
            }
        }
        if b > s {
            parts.push(Part::form(raw, s, b, role, encode, rules));
        }
    };
    let mut pos = from;
    for piece in raw[from..to].split('&') {
        let (ps, pe) = (pos, pos + piece.len());
        pos = pe + 1;
        match piece.find('=') {
            Some(k) if role.form_keys() => {
                let ke = ps + k;
                let ks = raw[ps..ke].rfind(['?', '#']).map_or(ps, |q| ps + q + 1);
                if ks > ps {
                    add(ps, ks - 1, role);
                }
                let key = decode_component(&raw[ks..ke]);
                add(ks, ke, role.key());
                add(ke + 1, pe, role.member(&key, rules));
            }
            Some(k) => {
                add(ps, ps + k, role);
                add(ps + k + 1, pe, role);
            }
            None if role == Role::Form => add(ps, pe, Role::Value { skipped: false }),
            None => add(ps, pe, role),
        }
    }
    parts
}

/// A replacement in a text, in that text's raw coordinates.
#[derive(Debug, Clone)]
struct Edit {
    start: usize,
    end: usize,
    /// The new text: as the reading that found it reads it, then (once
    /// merged) as the raw text holds it.
    text: String,
    /// The kinds of the engine findings it stands for (each counted once).
    kinds: Vec<String>,
    /// Which reading found it: 0 the literal one, `n` part `n - 1` of the
    /// other one.
    view: usize,
    /// The raw text it covers is form-encoded (`%XX`, `+`).
    encoded: bool,
}

/// Apply sorted, disjoint edits to `raw`.
fn apply(raw: &str, edits: &[Edit]) -> Result<String, Malformed> {
    let mut out = String::with_capacity(raw.len());
    let mut last = 0;
    for e in edits {
        out.push_str(raw.get(last..e.start).ok_or(Malformed)?);
        out.push_str(&e.text);
        last = e.end;
    }
    out.push_str(raw.get(last..).ok_or(Malformed)?);
    Ok(out)
}

/// Visit `text` as one string; what the sink replaced, as edits.
fn visit(text: &str, tier: Tier, f: Visit<'_>) -> Vec<Edit> {
    let mut s = text.to_string();
    f.visit(&mut s, tier);
    let edit = |start, end, text, kinds| Edit {
        start,
        end,
        text,
        kinds,
        view: 0,
        encoded: false,
    };
    match f.found() {
        Some(found) => found
            .iter()
            .map(|x| edit(x.start, x.end, x.surrogate.clone(), vec![x.kind.clone()]))
            .collect(),
        None if s == text => Vec::new(),
        // A sink that cannot say what it replaced: the changed middle.
        None => {
            let (a, b) = (text.as_bytes(), s.as_bytes());
            let mut p = a.iter().zip(b).take_while(|(x, y)| x == y).count();
            while !text.is_char_boundary(p) || !s.is_char_boundary(p) {
                p -= 1;
            }
            let room = a.len().min(b.len()) - p;
            let mut q = a
                .iter()
                .rev()
                .zip(b.iter().rev())
                .take_while(|(x, y)| x == y)
                .count()
                .min(room);
            while !text.is_char_boundary(a.len() - q) || !s.is_char_boundary(b.len() - q) {
                q -= 1;
            }
            vec![edit(
                p,
                a.len() - q,
                s[p..b.len() - q].to_string(),
                Vec::new(),
            )]
        }
    }
}

/// Read `raw` in every way a server may read it, and redact each reading
/// with `f`; returns the edits that leave a finding in none of them.
///
/// The readings: the literal text (identifiers inside it hidden, as they
/// skip the model); and either JSON (one value, or one per line, after
/// whitespace, BOMs and RS), its strings, keys and numbers each read again
/// the same ways, or, when it holds `%XX`, `+` or `=`, form-decoded, its
/// keys, values and pieces each read again the same ways. JSON in a string
/// is thus opened, and so is JSON in a form value, `MAX_DEPTH` levels deep.
/// What any reading finds is replaced in the raw text, encoded as each
/// layer needs; a value the literal reading finds across JSON tokens is
/// replaced in each token it covers (never in an identifier).
///
/// Also returns whether JSON was read in `raw` (at any depth).
fn read(
    raw: &str,
    role: Role,
    depth: usize,
    rules: &Rules<'_>,
    f: Visit<'_>,
) -> Result<(Vec<Edit>, bool), Malformed> {
    if raw.trim_matches(skippable).is_empty() {
        return Ok((Vec::new(), false));
    }
    let tier = role.tier(raw, rules);
    let role = if tier == Tier::Identifier {
        Role::Ident
    } else {
        role
    };
    let view = if depth < MAX_DEPTH {
        View::of(raw, role, depth == 0, rules)?
    } else {
        View::plain()
    };
    // The literal reading, identifiers hidden: they skip the model.
    let mut literal = raw.as_bytes().to_vec();
    if tier == Tier::Text {
        for p in view.parts.iter().filter(|p| p.ident) {
            literal[p.start..p.end].fill(b'_');
        }
    }
    // Whole characters became `_`: still UTF-8.
    let literal = String::from_utf8(literal).map_err(|_| Malformed)?;
    // The parts first: a value's canonical spelling (decoded) gets its tag
    // before the fragments the literal reading may see.
    let mut edits = Vec::new();
    let mut json = vec![false; view.parts.len()];
    for (n, part) in view.parts.iter().enumerate().filter(|(_, p)| !p.verbatim) {
        let (found, is_json) = read(&part.text, part.role, depth + 1, rules, f)?;
        json[n] = is_json;
        edits.extend(found.into_iter().map(|e| part.lift(raw, e, n + 1)));
    }
    edits.extend(visit(&literal, tier, f));
    let has_json = !view.docs.is_empty() || json.contains(&true);
    Ok((merge(raw, edits, &view, &json, f)?, has_json))
}

/// Merge what the readings of `raw` found into disjoint edits, as `raw`
/// holds them. Edits that overlap are one: the new texts of those not
/// inside another, in order (of two over the same text, the decoded
/// reading's); one inside another found by another reading is the same
/// value found twice, not counted again.
///
/// `json[n]`: JSON was read in part `n`.
fn merge(
    raw: &str,
    edits: Vec<Edit>,
    view: &View,
    json: &[bool],
    f: Visit<'_>,
) -> Result<Vec<Edit>, Malformed> {
    let mut forget = |kinds: &[String]| kinds.iter().for_each(|k| f.forget(k));
    let found_in_parts: Vec<(usize, usize, usize)> = edits
        .iter()
        .filter(|e| e.view != 0)
        .map(|e| (e.start, e.end, e.view))
        .collect();
    let mut hits = Vec::with_capacity(edits.len());
    for e in edits {
        if e.view != 0 {
            hits.push(e);
            continue;
        }
        // What the literal reading found, cut where it enters or leaves a
        // JSON value.
        let mut cuts = Vec::new();
        let mut at = e.start;
        for d in view
            .docs
            .iter()
            .filter(|d| d.start < e.end && e.start < d.end)
        {
            if d.start > at {
                cuts.push((at, d.start));
            }
            cuts.push((at.max(d.start), e.end.min(d.end)));
            at = e.end.min(d.end);
        }
        if at < e.end || cuts.is_empty() {
            cuts.push((at, e.end));
        }
        let mut kinds = Some(e.kinds);
        for (start, end) in cuts {
            let cut = Edit {
                start,
                end,
                text: e.text.clone(),
                kinds: Vec::new(),
                view: 0,
                encoded: false,
            };
            // Across form syntax (`data=x+ravi@…` reads as one e-mail
            // literally, also encoded), the value a finer reading found
            // decides: the key stays.
            let mut decoded = raw[start..end].to_string();
            for _ in 0..MAX_DEPTH {
                decoded = decode_component(&decoded);
            }
            if decoded.contains(['=', '&'])
                && found_in_parts
                    .iter()
                    .any(|&(s, t, _)| start <= s && t <= end)
            {
                continue;
            }
            // Inside a part with JSON in it, what its readings found decides:
            // cut here, the literal finding could split one of its escapes.
            let within_json = view
                .parts
                .iter()
                .enumerate()
                .find(|(n, p)| json[*n] && p.start <= start && end <= p.end);
            if let Some((n, _)) = within_json
                && found_in_parts
                    .iter()
                    .any(|&(s, t, v)| v == n + 1 && s < end && start < t)
            {
                continue;
            }
            let over: Vec<&Part> = view.parts.iter().filter(|p| p.overlaps(&cut)).collect();
            if view.in_doc(start, end) {
                // In JSON only strings and numbers change: a value found
                // across them is replaced in each (identifiers keep theirs).
                // Where a string's own (unescaped) reading found something,
                // it decides: read raw, escapes glue letters to a value.
                for (n, p) in view.parts.iter().enumerate() {
                    if p.ident || !p.overlaps(&cut) {
                        continue;
                    }
                    let (start, end) = p.align(start.max(p.start), end.min(p.end));
                    if found_in_parts
                        .iter()
                        .any(|&(s, t, v)| v == n + 1 && s < end && start < t)
                    {
                        continue;
                    }
                    hits.push(Edit {
                        start,
                        end,
                        kinds: kinds.take().unwrap_or_default(),
                        ..cut.clone()
                    });
                }
                continue;
            }
            // Inside an identifier, its own reading decides.
            match over[..] {
                [p] if p.ident && p.start <= start && end <= p.end => {}
                _ => hits.push(Edit {
                    kinds: kinds.take().unwrap_or_default(),
                    encoded: over.iter().any(|p| p.encode),
                    ..cut
                }),
            }
        }
        if let Some(kinds) = kinds {
            forget(&kinds);
        }
    }
    hits.sort_by_key(|h| (h.start, std::cmp::Reverse(h.end), !h.encoded, h.view));
    let mut merged: Vec<Edit> = Vec::new();
    let mut i = 0;
    while i < hits.len() {
        let mut end = hits[i].end;
        let mut j = i + 1;
        while j < hits.len() && hits[j].start < end {
            end = end.max(hits[j].end);
            j += 1;
        }
        let mut outer: Vec<&Edit> = Vec::new();
        for h in &hits[i..j] {
            if outer.iter().any(|o| o.start <= h.start && h.end <= o.end) {
                forget(&h.kinds);
            } else {
                outer.push(h);
            }
        }
        let mut text = String::new();
        let mut prev: Option<&str> = None;
        for o in &outer {
            if prev != Some(o.text.as_str()) {
                text.push_str(&o.text);
            }
            prev = Some(o.text.as_str());
        }
        merged.push(Edit {
            start: hits[i].start,
            end,
            text,
            kinds: outer.iter().flat_map(|o| o.kinds.iter().cloned()).collect(),
            view: 0,
            encoded: hits[i..j].iter().any(|h| h.encoded),
        });
        i = j;
    }
    // As each reading holds them: escaped in JSON strings; a JSON number
    // with edits becomes a string unless what replaces it is a number;
    // encoded where the text was form-encoded.
    let mut out: Vec<Edit> = Vec::new();
    let mut k = 0;
    while k < merged.len() {
        let e = &merged[k];
        let json = view
            .parts
            .iter()
            .find(|p| !p.percent && p.start <= e.start && e.end <= p.end);
        let Some(p) = json.filter(|p| p.num) else {
            let text = match json {
                Some(_) => json_escape(&e.text),
                None if view.in_doc(e.start, e.end) => return Err(Malformed),
                None if e.encoded => encode_all(&e.text),
                None => e.text.clone(),
            };
            out.push(Edit { text, ..e.clone() });
            k += 1;
            continue;
        };
        let mut inner = Vec::new();
        while let Some(e) = merged
            .get(k)
            .filter(|e| p.start <= e.start && e.end <= p.end)
        {
            inner.push(Edit {
                start: e.start - p.start,
                end: e.end - p.start,
                ..e.clone()
            });
            k += 1;
        }
        let text = apply(&raw[p.start..p.end], &inner)?;
        let text = match serde_json::from_str::<Value>(&text) {
            Ok(Value::Number(_)) => text,
            _ => Value::String(text).to_string(),
        };
        out.push(Edit {
            start: p.start,
            end: p.end,
            text,
            kinds: inner.into_iter().flat_map(|e| e.kinds).collect(),
            view: 0,
            encoded: false,
        });
    }
    // Every JSON value must still be JSON, and name no key twice (two keys
    // that became the same tag).
    if !out.is_empty() && !view.docs.is_empty() {
        let new = apply(raw, &out)?;
        let moved = |at: usize| {
            out.iter()
                .filter(|e| e.end <= at)
                .map(|e| e.text.len() as isize - (e.end - e.start) as isize)
                .sum::<isize>()
                .saturating_add(at as isize) as usize
        };
        for d in &view.docs {
            let json = new.get(moved(d.start)..moved(d.end)).ok_or(Malformed)?;
            if !parses(json, view.strict)? {
                return Err(Malformed);
            }
        }
    }
    Ok(out)
}

/// Redact `raw` (a body, a field, a query string) in every reading (see
/// [`read`]); returns the new text when something changed.
pub(crate) fn read_text(
    raw: &str,
    role: Role,
    rules: &Rules<'_>,
    f: Visit<'_>,
) -> Result<Option<String>, Malformed> {
    let (edits, _) = read(raw, role, 0, rules, f)?;
    if edits.is_empty() {
        return Ok(None);
    }
    let out = apply(raw, &edits)?;
    Ok((out != raw).then_some(out))
}

/// Redact a multipart field named `name` (see [`read_text`]); one declared
/// as JSON must be JSON.
fn read_field(
    text: &str,
    name: Option<&str>,
    json: bool,
    rules: &Rules<'_>,
    f: Visit<'_>,
) -> Result<Option<String>, Malformed> {
    if json && !is_json_document(text)? {
        return Err(Malformed);
    }
    let role = name.map_or(Role::Body, |n| Role::Body.member(n, rules));
    read_text(text, role, rules, f)
}

/// What a multipart walk did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct MultipartWalk {
    /// The rewritten body, when a text part changed.
    pub(crate) body: Option<Vec<u8>>,
    /// File parts (and non-text or non-UTF-8 fields) forwarded unscanned.
    pub(crate) unscanned: u32,
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

/// What a part's headers say about it.
#[derive(Default)]
struct PartHeaders {
    name: Option<String>,
    /// A `filename` is present.
    file: bool,
    content_type: Option<String>,
    /// `Content-Transfer-Encoding`, lower-case.
    encoding: Option<String>,
}

/// Whether the `charset` parameter of `content_type` is absent, UTF-8 or
/// US-ASCII (anything else cannot be read as UTF-8 text).
pub(crate) fn utf8_charset(content_type: &str) -> bool {
    content_type
        .split(';')
        .skip(1)
        .filter_map(|p| p.split_once('='))
        .filter(|(k, _)| k.trim().eq_ignore_ascii_case("charset"))
        .all(|(_, v)| {
            let v = v.trim().trim_matches('"').to_ascii_lowercase();
            matches!(v.as_str(), "utf-8" | "utf8" | "us-ascii")
        })
}

fn part_headers(headers: &str) -> PartHeaders {
    let mut part = PartHeaders::default();
    for line in headers.split("\r\n") {
        let Some((h, v)) = line.split_once(':') else {
            continue;
        };
        let h = h.trim();
        if h.eq_ignore_ascii_case("content-type") {
            part.content_type = Some(v.trim().to_ascii_lowercase());
        } else if h.eq_ignore_ascii_case("content-transfer-encoding") {
            part.encoding = Some(v.trim().to_ascii_lowercase());
        } else if h.eq_ignore_ascii_case("content-disposition") {
            for param in v.split(';').skip(1) {
                let Some((pk, pv)) = param.split_once('=') else {
                    continue;
                };
                let pk = pk.trim().to_ascii_lowercase();
                if pk == "filename" || pk == "filename*" {
                    part.file = true;
                } else if pk == "name" {
                    part.name = Some(pv.trim().trim_matches('"').to_string());
                }
            }
        }
    }
    part
}

/// What follows a `--boundary` that is a delimiter (RFC 2046).
#[derive(Clone, Copy)]
enum Delimiter {
    /// `--boundary` ends a line (after optional spaces or tabs); the CRLF
    /// is at this index.
    Open(usize),
    /// `--boundary--`: the last one.
    Close,
}

/// Is `--boundary` at `at` a delimiter, and which kind? Anything else after
/// it (`--boundaryx`, `--boundary-`) is part content.
fn delimiter_at(body: &[u8], at: usize, delim: &[u8]) -> Option<Delimiter> {
    let mut i = at + delim.len();
    if body.get(at..i)? != delim {
        return None;
    }
    if body[i..].starts_with(b"--") {
        return Some(Delimiter::Close);
    }
    while matches!(body.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    body[i..].starts_with(b"\r\n").then_some(Delimiter::Open(i))
}

/// The first delimiter at or after `from`: a `--boundary` that starts a
/// line (follows a CRLF at or after `from`, or starts the body when
/// `first`). Returns where its `--` is.
fn next_delimiter(
    body: &[u8],
    delim: &[u8],
    from: usize,
    first: bool,
) -> Option<(usize, Delimiter)> {
    let mut at = from;
    loop {
        let p = find(body, delim, at)?;
        let line_start = (first && p == 0) || (p >= from + 2 && &body[p - 2..p] == b"\r\n");
        if line_start && let Some(d) = delimiter_at(body, p, delim) {
            return Some((p, d));
        }
        at = p + 1;
    }
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decode MIME base64 (line breaks and spaces ignored, padding required);
/// `None` when it is not base64.
fn base64_decode(text: &[u8]) -> Option<Vec<u8>> {
    let chars: Vec<u8> = text
        .iter()
        .copied()
        .filter(|c| !matches!(c, b'\r' | b'\n' | b' ' | b'\t'))
        .collect();
    if !chars.len().is_multiple_of(4) {
        return None;
    }
    let pad = chars.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(chars.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0);
    for &c in &chars[..chars.len() - pad] {
        let v = BASE64.iter().position(|&b| b == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Encode as MIME base64: padded, lines of 76 characters joined by CRLF.
fn base64_encode(data: &[u8]) -> String {
    let mut chars = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                chars.push(BASE64[(n >> (18 - 6 * i)) as usize & 63]);
            } else {
                chars.push(b'=');
            }
        }
    }
    chars
        .chunks(76)
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Visit the text fields of a `multipart/form-data` body: fields without a
/// filename whose type is text or JSON, as they are or base64-encoded.
/// Files, and fields parda cannot decode, are forwarded unchanged and
/// counted as unscanned. Delimiters are found as RFC 2046 defines them.
pub(crate) fn walk_multipart(
    body: &[u8],
    boundary: &str,
    rules: &Rules<'_>,
    f: Visit<'_>,
) -> Result<MultipartWalk, Malformed> {
    let delim = format!("--{boundary}");
    let delim = delim.as_bytes();
    // A preamble must end in CRLF before the first delimiter.
    let (mut pos, mut kind) = next_delimiter(body, delim, 0, true).ok_or(Malformed)?;
    // Servers skip the preamble and the epilogue; one that holds a
    // look-alike delimiter could be read as a part by a lenient parser.
    if find(&body[..pos], delim, 0).is_some() {
        return Err(Malformed);
    }
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[..pos]);
    let mut walk = MultipartWalk::default();
    let mut changed = false;
    while let Delimiter::Open(line_end) = kind {
        let (next, next_kind) = next_delimiter(body, delim, line_end, false).ok_or(Malformed)?;
        // The CRLF before the next delimiter belongs to the delimiter.
        let content_end = next - 2;
        let headers_end = find(body, b"\r\n\r\n", line_end).ok_or(Malformed)?;
        let content_start = headers_end + 4;
        if content_start > content_end {
            // No blank line before the next delimiter.
            return Err(Malformed);
        }
        let headers = String::from_utf8_lossy(&body[line_end + 2..headers_end.max(line_end + 2)]);
        let content = &body[content_start..content_end];
        out.extend_from_slice(&body[pos..content_start]);
        let part = part_headers(&headers);
        let texty = part.content_type.as_deref().is_none_or(|t| {
            (t.starts_with("text/") || t.starts_with("application/json") || t.contains("+json"))
                && utf8_charset(t)
        });
        let base64 = part.encoding.as_deref() == Some("base64");
        let identity = part
            .encoding
            .as_deref()
            .is_none_or(|e| matches!(e, "7bit" | "8bit" | "binary"));
        let mut new = None;
        let text = if part.file || !texty || !(identity || base64) {
            None
        } else if base64 {
            base64_decode(content).and_then(|d| String::from_utf8(d).ok())
        } else {
            std::str::from_utf8(content).ok().map(str::to_string)
        }
        // NULs: another charset (UTF-16) read as UTF-8.
        .filter(|t| !t.contains('\0'));
        match text {
            Some(text) => {
                let json = part
                    .content_type
                    .as_deref()
                    .is_some_and(|t| t.starts_with("application/json") || t.contains("+json"));
                if let Some(value) = read_field(&text, part.name.as_deref(), json, rules, f)? {
                    new = Some(if base64 {
                        base64_encode(value.as_bytes())
                    } else {
                        value
                    });
                }
            }
            None => walk.unscanned += 1,
        }
        match new {
            Some(value) => {
                // The new text must not end the part early.
                let framed = [b"\r\n", value.as_bytes(), b"\r\n"].concat();
                if next_delimiter(&framed, delim, 0, false).is_some() {
                    return Err(Malformed);
                }
                changed = true;
                out.extend_from_slice(value.as_bytes());
            }
            None => out.extend_from_slice(content),
        }
        out.extend_from_slice(b"\r\n");
        (pos, kind) = (next, next_kind);
    }
    if find(body, delim, pos + delim.len() + 2).is_some() {
        return Err(Malformed);
    }
    out.extend_from_slice(&body[pos..]);
    if changed {
        walk.body = Some(out);
    }
    Ok(walk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hosts() -> HostList {
        HostList::new(&["chatgpt.com".to_string(), "gemini.google.com".to_string()])
    }

    fn rules<'a>(hosts: &'a HostList, extra: &'a [String], site: &str) -> Rules<'a> {
        Rules {
            hosts,
            extra,
            site: crate::sites::for_host(site),
        }
    }

    fn mark(s: &str, tier: Tier) -> String {
        match tier {
            Tier::Text => s.to_string(),
            Tier::Identifier => format!("#{s}"),
        }
    }

    fn upper(s: &mut String, _: Tier) {
        *s = s.to_uppercase();
    }

    #[test]
    fn identifier_shape() {
        for v in [
            "abc",
            "aaa2b8c1-55f4-4bd2-9a1c-0123456789ab",
            "client-created-root",
            "AJvLN6M:1697000000000",
            "a/b+c=d_e.f",
            &"x".repeat(64),
        ] {
            assert!(id_shaped(v), "{v}");
        }
        for v in [
            "",
            "Ravi Kumar",
            "ravi@example.com",
            "a,b",
            "x?y",
            "naïve",
            &"x".repeat(65),
        ] {
            assert!(!id_shaped(v), "{v}");
        }
    }

    #[test]
    fn globs() {
        assert!(glob("trace*", "TraceTag"));
        assert!(glob("*_id", "message_id"));
        assert!(glob("*model*", "default_MODEL_slug"));
        assert!(glob("f.sid", "F.SID"));
        assert!(glob("__*", "__a"));
        assert!(!glob("__*", "_a"));
        assert!(!glob("*_id", "valid"));
        assert!(glob("*", ""));
    }

    #[test]
    fn identifier_keys_are_skipped() {
        let h = hosts();
        let extra = ["trace*".to_string()];
        let r = rules(&h, &extra, "example.com");
        for key in [
            "id",
            "ID",
            "message_id",
            "conversationId",
            "userID",
            "uuid",
            "parent_message_uuid",
            "fileUuid",
            "model",
            "model_slug",
            "defaultModel",
            "token",
            "arkose_token",
            "csrfToken",
            "nonce",
            "clientNonce",
            "signature",
            "timestamp",
            "create_time",
            "created_at",
            "createdAt",
            "parent",
            "parentMessageId",
            "conversation_id",
            "organization_uuid",
            "organizationId",
            "locale",
            "timezone",
            "client_contextual_info",
            "arkose_dx",
            "sentinel_proof",
            "action",
            "type",
            "role",
            "author",
            "status",
            "ref_file_ids",
            "messageIds",
            "trace_tag",
        ] {
            assert!(r.skip_key(key), "{key} should be skipped");
        }
        for key in [
            "name", "text", "parts", "content", "prompt", "paid", "valid", "android", "title",
            "message", "query", "q", "email", "hidden", "squid",
        ] {
            assert!(!r.skip_key(key), "{key} should be text");
        }
        // Site lists add to the generic rules.
        let g = rules(&h, &[], "gemini.google.com");
        assert!(g.skip_key("at") && g.skip_key("f.sid") && g.skip_key("_reqid"));
        assert!(!r.skip_key("at"));
    }

    #[test]
    fn identifier_values_are_skipped() {
        let h = hosts();
        let r = rules(&h, &[], "chatgpt.com");
        for v in [
            "aaa2b8c1-55f4-4bd2-9a1c-0123456789ab",
            "AAA2B8C1-55F4-4BD2-9A1C-0123456789AB",
            "deadbeef00112233",
            "0123456789abcdef0123456789abcdef",
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3ODk",
            "gAAAAABmZ2xvYmFsX3Rva2VuX3ZhbHVlX18tX18tX18tX18=",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
            "https://chatgpt.com/c/123",
            "https://sub.chatgpt.com/x?y=1",
        ] {
            assert!(r.is_identifier(v), "{v} should be an identifier");
        }
        for v in [
            "Ravi Kumar",
            "4111111111111111",
            "123456789012345678901234567890123",
            "ravi.kumar@example.com",
            "https://example.com/ravi",
            "deadbeef",
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVld",
            "sk proj with spaces and more than thirty two characters",
            "",
        ] {
            assert!(!r.is_identifier(v), "{v} should be text");
        }
    }

    /// The texts `raw` is read as (identifiers marked `#`), and the result.
    fn visits(raw: &str, role: Role, r: &Rules<'_>) -> Vec<String> {
        let mut out = Vec::new();
        read_text(raw, role, r, &mut |s: &mut String, tier| {
            out.push(mark(s, tier))
        })
        .unwrap();
        out
    }

    /// Replaces each needle with its tag and says where (like the engine).
    struct Finder {
        needles: Vec<(&'static str, &'static str)>,
        found: Vec<Found>,
        seen: Vec<String>,
    }

    impl Finder {
        fn new(needles: &[(&'static str, &'static str)]) -> Self {
            Finder {
                needles: needles.to_vec(),
                found: Vec::new(),
                seen: Vec::new(),
            }
        }
    }

    impl Sink for Finder {
        fn visit(&mut self, s: &mut String, tier: Tier) {
            self.seen.push(mark(s, tier));
            self.found.clear();
            for (needle, tag) in &self.needles {
                for (i, _) in s.match_indices(needle) {
                    self.found.push(Found {
                        start: i,
                        end: i + needle.len(),
                        surrogate: tag.to_string(),
                        kind: "K".into(),
                    });
                }
            }
            // Longest first where two start together; overlaps dropped.
            self.found
                .sort_by_key(|x| (x.start, std::cmp::Reverse(x.end)));
            let mut end = 0;
            self.found.retain(|x| {
                let keep = x.start >= end;
                end = end.max(x.end);
                keep
            });
            let mut out = String::new();
            let mut last = 0;
            for x in &self.found {
                out.push_str(&s[last..x.start]);
                out.push_str(&x.surrogate);
                last = x.end;
            }
            out.push_str(&s[last..]);
            *s = out;
        }

        fn found(&self) -> Option<&[Found]> {
            Some(&self.found)
        }
    }

    fn find(
        raw: &str,
        role: Role,
        needles: &[(&'static str, &'static str)],
    ) -> Result<String, Malformed> {
        let h = hosts();
        let r = rules(&h, &[], "chatgpt.com");
        let mut f = Finder::new(needles);
        Ok(read_text(raw, role, &r, &mut f)?.unwrap_or_else(|| raw.to_string()))
    }

    #[test]
    fn json_tokens_get_their_tiers_and_the_literal_hides_identifiers() {
        let h = hosts();
        let r = rules(&h, &[], "chatgpt.com");
        let key = "sk-proj-0123456789abcdefghijABCDEFGHIJ0123456789";
        let body = json!({
            "action": "next",
            "messages": [{
                "id": "aaa2b8c1-55f4-4bd2-9a1c-0123456789ab",
                "author": {"role": "user", "name": "Ravi Kumar"},
                "content": {"content_type": "text", "parts": ["Email Ravi Kumar", key]},
                "metadata": {"note": "deadbeef00112233deadbeef"}
            }],
            "parent_message_id": "client-created-root",
            "model": "ravi.k@gmail.com",
            "type": "Ravi Kumar",
            "timezone_offset_min": -330,
            "create_time": 1760000000.123,
            "client_contextual_info": {"page_title": "x"},
            "tags": ["a", "  "],
            "ids": ["aaa2b8c1-55f4-4bd2-9a1c-0123456789ab"],
        })
        .to_string();
        let mut seen = visits(&body, Role::Body, &r);
        let literal = seen.pop().unwrap();
        // Every string, key and number is read on its own. Identifier-shaped
        // values under identifier keys (or looking like ids) skip only the
        // model; a value with a space or an `@` is text under any key;
        // content keys (`parts`) are always text; numbers meet the rules
        // only, and under identifier keys (`create_time`) are kept as
        // written. Keys follow the value rule.
        assert_eq!(
            seen,
            [
                "#action",
                "#next",
                "messages",
                "#id",
                "#aaa2b8c1-55f4-4bd2-9a1c-0123456789ab",
                "#author",
                "#role",
                "#user",
                "name",
                "Ravi Kumar",
                "#content",
                "#content_type",
                "#text",
                "#parts",
                "Email Ravi Kumar",
                key,
                "metadata",
                "note",
                "#deadbeef00112233deadbeef",
                "#parent_message_id",
                "#client-created-root",
                "#model",
                "ravi.k@gmail.com",
                "#type",
                "Ravi Kumar",
                "timezone_offset_min",
                "#-330",
                "#create_time",
                "#client_contextual_info",
                "page_title",
                "x",
                "tags",
                "a",
                "ids",
                "#aaa2b8c1-55f4-4bd2-9a1c-0123456789ab",
            ]
        );
        // And the whole text literally (a value split across tokens), its
        // identifiers hidden from the model.
        assert_eq!(literal.len(), body.len());
        for hidden in [
            "aaa2b8c1",
            "client-created-root",
            "deadbeef",
            "1760000000",
            "parent_message_id",
        ] {
            assert!(!literal.contains(hidden), "{literal}");
        }
        for shown in [
            "Email Ravi Kumar",
            key,
            "ravi.k@gmail.com",
            "-330",
            "\"name\"",
        ] {
            assert!(literal.contains(shown), "{literal}");
        }
    }

    #[test]
    fn json_in_strings_is_opened_and_rewritten_exactly() {
        let h = hosts();
        let r = rules(&h, &[], "gemini.google.com");
        let inner = r#"[["Ravi Kumar here",0,null,1e2],["en"],["c_1a2b3c","r_9f8e7d"]]"#;
        let body = json!([null, inner]).to_string();
        let ravi = |s: &mut String, t: Tier| {
            if s.starts_with("Ravi") {
                upper(s, t)
            }
        };
        let out = read_text(&body, Role::Body, &r, &mut { ravi })
            .unwrap()
            .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v[1],
            r#"[["RAVI KUMAR HERE",0,null,1e2],["en"],["c_1a2b3c","r_9f8e7d"]]"#
        );
        // Unchanged JSON-in-string keeps its exact text.
        let spaced = json!({"blob": r#"{ "a" : "x" }"#}).to_string();
        assert_eq!(
            read_text(&spaced, Role::Body, &r, &mut |_: &mut String, _: Tier| {}),
            Ok(None)
        );
        // JSON typed into a content field is read too, but all of it is
        // text: its keys get no say.
        let typed = json!({"prompt": r#"{"id": "Ravi Kumar", "n": "ab12"}"#}).to_string();
        let seen = visits(&typed, Role::Body, &r);
        for v in ["id", "Ravi Kumar", "ab12"] {
            assert!(seen.iter().any(|s| s == v), "{seen:?}");
        }
        // Nesting beyond the limit is read literally, never skipped.
        let mut s = String::from("\"deep Ravi\"");
        for _ in 0..6 {
            s = serde_json::to_string(&json!([s])).unwrap();
        }
        let out = read_text(&s, Role::Body, &r, &mut { ravi_anywhere })
            .unwrap()
            .unwrap();
        assert!(
            !out.contains("deep Ravi") && out.contains("deep RAVI"),
            "{out}"
        );
    }

    fn ravi_anywhere(s: &mut String, _: Tier) {
        *s = s.replace("Ravi", "RAVI");
    }

    #[test]
    fn renamed_keys_keep_their_place_and_never_merge() {
        let h = hosts();
        let r = rules(&h, &[], "chatgpt.com");
        let tag = |s: &mut String, _: Tier| {
            if s.starts_with("Ravi") || s.starts_with("ravi") {
                *s = "[NAME_1]".into();
            }
        };
        let read = |v: Value| read_text(&v.to_string(), Role::Body, &r, &mut { tag });
        assert_eq!(
            read(json!({"a": 1, "Ravi Kumar": {"ravi k": 2}, "z": 3})),
            Ok(Some(r#"{"a":1,"[NAME_1]":{"[NAME_1]":2},"z":3}"#.into()))
        );
        // Two keys that would become the same text: one value would be
        // lost, so the body is refused.
        for v in [
            json!({"Ravi Kumar": 1, "ravi kumar": 2}),
            json!({"Ravi Kumar": 1, "[NAME_1]": 2}),
            json!([{"x": {"[NAME_1]": 1, "Ravi": 2}}]),
        ] {
            assert_eq!(read(v), Err(Malformed));
        }
        // JSON repeating a key, here or inside a string, is refused.
        assert_eq!(
            read_text(r#"{"a":"x","a":"y"}"#, Role::Body, &r, &mut { tag }),
            Err(Malformed)
        );
        assert_eq!(
            read(json!({"blob": r#"{"a":"x","a":"Ravi"}"#})),
            Err(Malformed)
        );
        // Typed into a message it is text the site never parses: read, not
        // refused.
        let typed = json!({"prompt": r#"{"a":"x","a":"Ravi"}"#});
        assert_eq!(
            read(typed),
            Ok(Some(
                json!({"prompt": r#"{"a":"x","a":"[NAME_1]"}"#}).to_string()
            ))
        );
    }

    /// Open item: a value split across JSON tokens is found by the literal
    /// reading of the whole text and replaced in each token; escapes are
    /// never split; identifiers keep their value.
    #[test]
    fn literal_findings_are_written_back_into_tokens() {
        assert_eq!(
            find(
                r#"["Ravi","Kumar"]"#,
                Role::Body,
                &[(r#"Ravi","Kumar"#, "[X]")]
            ),
            Ok(r#"["[X]","[X]"]"#.into())
        );
        assert_eq!(
            find(
                r#"{"Ravi":"Kumar","n":1}"#,
                Role::Body,
                &[(r#"Ravi":"Kumar"#, "[X]")]
            ),
            Ok(r#"{"[X]":"[X]","n":1}"#.into())
        );
        // A finding glued to an escape takes the whole escape.
        assert_eq!(
            find(r#"{"m":"Hi\nRavi"}"#, Role::Body, &[("nRavi", "[X]")]),
            Ok(r#"{"m":"Hi[X]"}"#.into())
        );
        // A number becomes a string with the tag.
        assert_eq!(
            find(
                r#"{"p":9876543210,"n":2}"#,
                Role::Body,
                &[("9876543210", "[X]")]
            ),
            Ok(r#"{"p":"[X]","n":2}"#.into())
        );
        // Under an identifier key a number is kept as written (timestamps
        // read like phones), and so is an identifier.
        let ids = r#"{"create_time":1760000000.123,"n":1}"#;
        assert_eq!(
            find(ids, Role::Body, &[("1760000000", "[X]")]),
            Ok(ids.into())
        );
        // The strings and numbers of a JSON line among text change; the text
        // around is read literally.
        assert_eq!(
            find(
                "note Ravi\n{\"m\":\"Ravi\"}\n",
                Role::Body,
                &[("Ravi", "[X]")]
            ),
            Ok("note [X]\n{\"m\":\"[X]\"}\n".into())
        );
    }

    #[test]
    fn form_values_are_rewritten_exactly() {
        let h = hosts();
        let r = rules(&h, &[], "gemini.google.com");
        let freq = serde_json::to_string(&json!([null, r#"[["Ravi Kumar",0]]"#])).unwrap();
        let enc: String = form_urlencoded::byte_serialize(freq.as_bytes()).collect();
        let raw = format!("f.req={enc}&at=AJvLN6M%3A1697000000000&q=Ravi+Kumar&flag&e=%E2%9C%93");
        let seen = visits(&raw, Role::Form, &r);
        // Keys and values by the key rules; a piece without `=` is a text
        // of its own; the whole text literally last, identifiers hidden.
        for v in [
            "f.req",
            "Ravi Kumar",
            "#at",
            "#AJvLN6M:1697000000000",
            "#q",
            "flag",
            "e",
            "✓",
        ] {
            assert!(seen.iter().any(|s| s == v), "{v}: {seen:?}");
        }
        assert!(!seen.last().unwrap().contains("AJvLN6M"));
        let ravi = |s: &mut String, t: Tier| {
            if s.starts_with("Ravi") {
                upper(s, t)
            }
        };
        let out = read_text(&raw, Role::Form, &r, &mut { ravi })
            .unwrap()
            .unwrap();
        let pairs: Vec<(String, String)> = form_urlencoded::parse(out.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(pairs[0].0, "f.req");
        let outer: Value = serde_json::from_str(&pairs[0].1).unwrap();
        assert_eq!(outer[1], r#"[["RAVI KUMAR",0]]"#);
        // Untouched pairs keep their bytes; changed text is encoded.
        assert!(
            out.ends_with("&at=AJvLN6M%3A1697000000000&q=RAVI%20KUMAR&flag&e=%E2%9C%93"),
            "{out}"
        );
    }

    /// The decoded reading maps every byte back to the raw text it came
    /// from, so a value found decoded is replaced in the raw text exactly.
    #[test]
    fn decoded_readings_map_back_to_raw_bytes() {
        let (d, map) = decode_mapped("a+%C3%A9%zz%FF%40b");
        assert_eq!(d, "a é%zz\u{fffd}@b");
        assert_eq!(map.len(), d.len());
        assert_eq!(map[1], (1, 2)); // `+`
        assert_eq!((map[2], map[3]), ((2, 5), (5, 8))); // `é` from two escapes
        assert_eq!(&map[7..10], &[(11, 14); 3]); // U+FFFD for `%FF`
        assert_eq!(map[10], (14, 17)); // `@`
        let raw = r#""a\u00e9\ud83d\ude00\ud83d\n""#;
        let (t, map) = unescape(raw, 1, raw.len() - 1);
        assert_eq!(t, "aé😀\u{fffd}\n");
        assert_eq!((map[1], map[3]), ((2, 8), (8, 20)));
        assert_eq!(map[t.len() - 1], (26, 28));
        // Two readings of one text: one replacement where they overlap,
        // encoded where the raw text was encoded.
        assert_eq!(
            find(
                "n=Ravi%20Kumar&m=x",
                Role::Form,
                &[("Ravi Kumar", "[N]"), ("Ravi", "[R]")]
            ),
            Ok("n=%5BN%5D&m=x".into())
        );
    }

    /// Text that looks like escaped JSON but is not JSON is refused, except
    /// what the user typed (a question about broken JSON).
    #[test]
    fn escaped_json_looking_text_is_refused() {
        let refused = |raw: &str, role| find(raw, role, &[]) == Err(Malformed);
        for raw in [
            "{\"m\":\"x\\n\", bad}",
            "note\n[\"x\\n\"",
            "\u{a0}\"x\\n",
            "{\"t\":1}\n{\"m\":\"x\\n\", bad}",
        ] {
            assert!(refused(raw, Role::Body), "{raw:?}");
            assert!(!refused(raw, Role::Typed), "{raw:?}");
        }
        // Inside a body: only text bracketed like JSON.
        let inner = |s: &str| json!({ "blob": s }).to_string();
        assert!(refused(&inner("{\"m\":\"x\\n\", bad}"), Role::Body));
        assert!(!refused(&inner("{\"m\":\"x\\n\", bad"), Role::Body));
        assert!(!refused(&inner("\"Hi\" C:\\new"), Role::Body));
        assert!(!refused(
            &json!({ "prompt": "{\"m\":\"x\\n\", bad}" }).to_string(),
            Role::Body
        ));
        // Backslashes elsewhere are text.
        assert!(!refused("C:\\new Ravi", Role::Body));
    }

    fn multipart(boundary: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        b.extend_from_slice(b"Content-Disposition: form-data; name=\"prompt\"\r\n\r\n");
        b.extend_from_slice(b"Ravi Kumar asks\r\n");
        b.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        b.extend_from_slice(
            b"Content-Disposition: form-data; name=\"file\"; filename=\"r.png\"\r\n\
              Content-Type: image/png\r\n\r\n",
        );
        b.extend_from_slice(b"\x89PNG\r\n\x1a\nRavi\xff\r\n");
        b.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        b.extend_from_slice(b"Content-Disposition: form-data; name=\"conversation_id\"\r\n\r\n");
        b.extend_from_slice(b"Ravi id\r\n");
        b.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        b
    }

    #[test]
    fn multipart_text_fields_are_rewritten_and_files_counted() {
        let h = hosts();
        let r = rules(&h, &[], "chatgpt.com");
        let body = multipart("XyZ");
        let mut seen = Vec::new();
        let w = walk_multipart(&body, "XyZ", &r, &mut |s: &mut String, t| {
            seen.push(mark(s, t))
        })
        .unwrap();
        // `conversation_id` is an identifier key, but "Ravi id" is not
        // identifier-shaped: text.
        assert_eq!(seen, ["Ravi Kumar asks", "Ravi id"]);
        assert_eq!(
            w,
            MultipartWalk {
                body: None,
                unscanned: 1
            }
        );
        let w = walk_multipart(&body, "XyZ", &r, &mut upper).unwrap();
        let out = w.body.unwrap();
        let want = String::from_utf8_lossy(&body)
            .replace("Ravi Kumar asks", "RAVI KUMAR ASKS")
            .replace("Ravi id", "RAVI ID");
        assert_eq!(String::from_utf8_lossy(&out), want);
        // The file bytes are untouched.
        assert!(out.windows(10).any(|w| w == b"Ravi\xff\r\n--X"));
        // A body that does not split is refused.
        assert_eq!(
            walk_multipart(b"no parts here", "XyZ", &r, &mut upper),
            Err(Malformed)
        );
        let mut cut = body.clone();
        cut.truncate(body.len() - 12);
        assert_eq!(walk_multipart(&cut, "XyZ", &r, &mut upper), Err(Malformed));
        assert_eq!(
            walk_multipart(b"x--XyZ--", "XyZ", &r, &mut upper),
            Err(Malformed)
        );
        let mut pre = b"preamble\r\n".to_vec();
        pre.extend_from_slice(&body);
        assert!(walk_multipart(&pre, "XyZ", &r, &mut upper).is_ok());
    }

    fn tag_name(s: &mut String, _: Tier) {
        *s = s.replace("Ravi Kumar", "[NAME_1]");
    }

    /// Review M6: a delimiter is `--boundary` followed by `--`, or by
    /// optional spaces or tabs and CRLF (RFC 2046). Anything else after
    /// `--boundary` is part content.
    #[test]
    fn multipart_delimiters_follow_rfc_2046() {
        let h = hosts();
        let r = rules(&h, &[], "chatgpt.com");
        // A text field holding `--XyZx` and fake part headers is one field.
        let field = "hi\r\n--XyZx\r\nContent-Disposition: form-data; name=\"f\"; \
                     filename=\"a.txt\"\r\n\r\nRavi Kumar";
        let body = format!(
            "--XyZ\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\n{field}\r\n--XyZ--\r\n"
        );
        let mut seen = Vec::new();
        let w = walk_multipart(body.as_bytes(), "XyZ", &r, &mut |s: &mut String, t| {
            seen.push(mark(s, t))
        })
        .unwrap();
        // One field, read literally last (its form-decoded parts first).
        assert_eq!(seen.last().map(String::as_str), Some(field));
        assert!(seen.iter().all(|s| field.contains(s.as_str())), "{seen:?}");
        assert_eq!(w.unscanned, 0);
        let w = walk_multipart(body.as_bytes(), "XyZ", &r, &mut tag_name).unwrap();
        assert_eq!(
            String::from_utf8(w.body.unwrap()).unwrap(),
            body.replace("Ravi Kumar", "[NAME_1]")
        );
        // Padding before the CRLF is allowed.
        let body = "preamble\r\n--XyZ \t\r\nContent-Disposition: form-data; \
                    name=\"a\"\r\n\r\nRavi Kumar\r\n--XyZ\t\r\nContent-Disposition: form-data; \
                    name=\"b\"\r\n\r\nx\r\n--XyZ--\r\nepilogue";
        let mut seen = Vec::new();
        walk_multipart(body.as_bytes(), "XyZ", &r, &mut |s: &mut String, t| {
            seen.push(mark(s, t))
        })
        .unwrap();
        assert_eq!(seen, ["Ravi Kumar", "x"]);
        // A body whose only `--XyZ` lines are look-alikes does not split,
        // and a preamble or epilogue holding one (a part to a lenient
        // parser, never scanned) is refused.
        for bad in [
            "--XyZx\r\n\r\nRavi Kumar\r\n--XyZ--",
            "--XyZjunk\r\n\r\nRavi Kumar\r\n--XyZ\r\n\r\nx\r\n--XyZ--",
            "--XyZ\r\n\r\nx\r\n--XyZ--\r\n--XyZ\r\n\r\nRavi Kumar\r\n--XyZ--",
            "--XyZ\r\n\r\nx\r\n--XyZ----XyZ",
            "--XyZ\r\n\r\nRavi Kumar\r\n--XyZ-",
            "--XyZ\r\n\r\nRavi Kumar\r\n--XyZ x\r\n",
        ] {
            assert_eq!(
                walk_multipart(bad.as_bytes(), "XyZ", &r, &mut upper),
                Err(Malformed),
                "{bad:?}"
            );
        }
    }

    fn base64_part(encoding: &str, content: &str) -> String {
        format!(
            "--XyZ\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: {encoding}\r\n\r\n{content}\r\n--XyZ--\r\n"
        )
    }

    /// Base64 lines of at most 76 characters, CRLF between them.
    fn wrapped(b64: &str) -> String {
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(76)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        lines.join("\r\n")
    }

    /// Review M6: base64 text parts are decoded, scanned and re-encoded;
    /// parts parda cannot decode are counted as unscanned.
    #[test]
    fn base64_text_parts_are_decoded_and_scanned() {
        let h = hosts();
        let r = rules(&h, &[], "chatgpt.com");
        let body = base64_part("base64", "UmF2aSBLdW1hciBhc2tz");
        let mut seen = Vec::new();
        let w = walk_multipart(body.as_bytes(), "XyZ", &r, &mut |s: &mut String, t| {
            seen.push(mark(s, t))
        })
        .unwrap();
        assert_eq!(seen, ["Ravi Kumar asks"]);
        assert_eq!(w, MultipartWalk::default());
        let w = walk_multipart(body.as_bytes(), "XyZ", &r, &mut upper).unwrap();
        assert_eq!(
            String::from_utf8(w.body.unwrap()).unwrap(),
            base64_part("base64", "UkFWSSBLVU1BUiBBU0tT")
        );
        // Long values come in (and go out) as 76-character lines.
        let long = wrapped(
            "UmF2aSBLdW1hciBhc2tzIGFib3V0IGNhZsOpIFJhdmkgS3VtYXIgYXNrcyBhYm91dCBjYWbDqSBSYXZpIEt1\
             bWFyIGFza3MgYWJvdXQgY2Fmw6kgUmF2aSBLdW1hciBhc2tzIGFib3V0IGNhZsOpIA==",
        );
        let upper_long = wrapped(
            "UkFWSSBLVU1BUiBBU0tTIEFCT1VUIENBRsOJIFJBVkkgS1VNQVIgQVNLUyBBQk9VVCBDQUbDiSBSQVZJIEtV\
             TUFSIEFTS1MgQUJPVVQgQ0FGw4kgUkFWSSBLVU1BUiBBU0tTIEFCT1VUIENBRsOJIA==",
        );
        let w = walk_multipart(
            base64_part("BASE64", &long).as_bytes(),
            "XyZ",
            &r,
            &mut upper,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(w.body.unwrap()).unwrap(),
            base64_part("BASE64", &upper_long)
        );
        // Unchanged text keeps its exact bytes.
        let w = walk_multipart(body.as_bytes(), "XyZ", &r, &mut |_: &mut String, _| {}).unwrap();
        assert_eq!(w.body, None);
        // Not base64, not UTF-8 once decoded, or an encoding parda does not
        // decode: unscanned, never visited.
        for (encoding, content) in [
            ("base64", "not base64!"),
            ("base64", "UmF2a"),
            ("base64", "//5SYQ=="),
            ("quoted-printable", "Ravi=20Kumar"),
            ("x-uuencode", "Ravi Kumar"),
        ] {
            let body = base64_part(encoding, content);
            let mut seen = Vec::new();
            let w = walk_multipart(body.as_bytes(), "XyZ", &r, &mut |s: &mut String, t| {
                seen.push(mark(s, t))
            })
            .unwrap();
            assert!(seen.is_empty(), "{encoding} {content}: {seen:?}");
            assert_eq!(w.unscanned, 1, "{encoding} {content}");
            assert_eq!(w.body, None);
        }
        // Identity encodings are read as they are.
        for encoding in ["7bit", "8bit", "binary"] {
            let body = base64_part(encoding, "Ravi Kumar");
            let w = walk_multipart(body.as_bytes(), "XyZ", &r, &mut tag_name).unwrap();
            assert_eq!(w.unscanned, 0);
            assert_eq!(
                String::from_utf8(w.body.unwrap()).unwrap(),
                base64_part(encoding, "[NAME_1]")
            );
        }
    }
}
