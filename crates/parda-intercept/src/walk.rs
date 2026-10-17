//! Which strings of an intercepted request are text to redact, and walking
//! them in JSON, form-encoded and multipart bodies and in query strings.
//!
//! Redaction walks a request twice in the same order: once to collect the
//! texts (one engine batch), once to write the results back.
//!
//! Nothing is skipped: every string and every key is visited. Identifiers a site needs
//! verbatim (values under identifier keys, or identifier-looking values) are
//! visited as [`Tier::Identifier`] — the engine's dictionary and rule tiers
//! still see them, only the ML model does not — and only when they are
//! identifier-shaped ([`id_shaped`]); anything else is text. Keys follow the
//! same rule.
//!
//! A string that reads differently once form/URL-decoded (`%XX`, `+`) is
//! visited in both readings: as it is, and component by component decoded
//! (form keys and values, URL path segments, query and fragment). What
//! either finds is replaced in the raw text, so a value survives in neither.
//! Whole text bodies and multipart fields get both readings whenever they
//! hold `%XX`, `+` or `=`.

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

/// Passes visits on to a sink, noting whether one changed its string.
pub(crate) struct Tracking<'a, 'b> {
    pub(crate) inner: &'a mut (dyn Sink + 'b),
    pub(crate) changed: bool,
}

impl Sink for Tracking<'_, '_> {
    fn visit(&mut self, s: &mut String, tier: Tier) {
        let before = s.clone();
        self.inner.visit(s, tier);
        self.changed |= *s != before;
    }

    fn found(&self) -> Option<&[Found]> {
        self.inner.found()
    }

    fn forget(&mut self, kind: &str) {
        self.inner.forget(kind);
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

/// JSON carried inside strings is opened this many levels deep; deeper
/// levels are text.
const MAX_NESTED_JSON: usize = 4;

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
/// JSON that names a key twice (here or inside a string), or two JSON keys
/// that would become the same tag.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Malformed;

/// Visit every text in a JSON document: its strings and its object keys.
pub(crate) fn walk_json(v: &mut Value, rules: &Rules<'_>, f: Visit<'_>) -> Result<(), Malformed> {
    walk_value(v, None, false, 0, rules, f)
}

/// `skipped`: the value sits under an identifier key (its strings and arrays
/// of strings; objects inside it have their own keys).
fn walk_value(
    v: &mut Value,
    key: Option<&str>,
    skipped: bool,
    depth: usize,
    rules: &Rules<'_>,
    f: Visit<'_>,
) -> Result<(), Malformed> {
    match v {
        Value::String(s) => visit_at(
            s,
            key.is_some_and(is_content_key),
            skipped,
            depth,
            Reading::Nested,
            rules,
            f,
        ),
        Value::Array(items) => items
            .iter_mut()
            .try_for_each(|x| walk_value(x, key, skipped, depth, rules, f)),
        Value::Object(map) => {
            // Keys are text too (`{"Ravi Kumar": …}`). A changed key is
            // renamed after the walk, so both passes see the same order.
            let mut renamed = Vec::new();
            for (k, x) in map.iter_mut() {
                let mut new_key = k.clone();
                visit_key(&mut new_key, rules, f);
                walk_value(x, Some(k), rules.skip_key(k), depth, rules, f)?;
                if new_key != *k {
                    renamed.push((k.clone(), new_key));
                }
            }
            if !renamed.is_empty() {
                let old = std::mem::take(map);
                let mut renamed: std::collections::HashMap<_, _> = renamed.into_iter().collect();
                for (k, x) in old {
                    let k = renamed.remove(&k).unwrap_or(k);
                    if map.contains_key(&k) {
                        return Err(Malformed);
                    }
                    map.insert(k, x);
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Visit a multipart field named `key`: a body of its own, read literally
/// or decoded as a form by the server (see [`Reading::Body`]).
pub(crate) fn visit_field(
    s: &mut String,
    key: Option<&str>,
    rules: &Rules<'_>,
    f: Visit<'_>,
) -> Result<(), Malformed> {
    let content = key.is_some_and(is_content_key);
    let skipped = key.is_some_and(|k| rules.skip_key(k));
    visit_at(s, content, skipped, 0, Reading::Body, rules, f)
}

/// Visit a text body (any body not declared as a form or JSON): what the
/// user typed, never an identifier, redacted as it reads literally and as
/// it reads decoded as a form.
pub(crate) fn visit_body_text(
    s: &mut String,
    rules: &Rules<'_>,
    f: Visit<'_>,
) -> Result<(), Malformed> {
    visit_at(s, true, false, 0, Reading::Body, rules, f)
}

/// Visit a key (a JSON object key, a form or query key) by the rule values
/// follow: it skips only the ML model when it is identifier-shaped and
/// either looks like an identifier itself or is a known protocol key (the
/// built-in identifier and content keys, the site's and `skip_keys`).
/// Anything else is text, so a name used as a key reaches the model.
fn visit_key(k: &mut String, rules: &Rules<'_>, f: Visit<'_>) {
    if k.trim().is_empty() {
        return;
    }
    let known = rules.skip_key(k) || is_content_key(k) || rules.is_identifier(k);
    let tier = if id_shaped(k) && known {
        Tier::Identifier
    } else {
        Tier::Text
    };
    visit_views(k, tier, Reading::Nested, f);
}

/// How a string may be read by whoever receives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// A whole body or multipart field not declared as a form: some servers
    /// read it literally, others decode it as a form. Any `%XX`, `+` or `=`
    /// gives it a decoded reading.
    Body,
    /// A string inside a document. A `%XX` escape gives it a decoded
    /// reading (a URL's path, query or fragment, a bare query string), and
    /// so does a `+` or `=` in a string without whitespace.
    Nested,
}

/// A valid `%XX` escape is in `s`.
fn has_escape(s: &str) -> bool {
    s.as_bytes()
        .windows(3)
        .any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
}

/// Does `s` have a decoded reading besides its literal one?
fn decodes(s: &str, reading: Reading) -> bool {
    if has_escape(s) {
        return true;
    }
    let form_like = s.contains(['+', '=']);
    match reading {
        Reading::Body => form_like,
        Reading::Nested => form_like && !s.contains(char::is_whitespace),
    }
}

/// `content`: what the user typed (a content key, a text body); `depth`:
/// how many JSON-in-string or URL-query levels this string sits in.
fn visit_at(
    s: &mut String,
    content: bool,
    skipped: bool,
    depth: usize,
    reading: Reading,
    rules: &Rules<'_>,
    f: Visit<'_>,
) -> Result<(), Malformed> {
    if s.trim().is_empty() {
        return Ok(());
    }
    // JSON inside a string is opened; past the depth limit (or when it does
    // not parse) the string is text like any other. JSON typed into a
    // message is text.
    if !content && depth < MAX_NESTED_JSON && nested_json(s, depth, rules, f)? {
        return Ok(());
    }
    let tier = plain_tier(s, content, skipped, rules);
    // A body is one text in both of its readings.
    if reading == Reading::Body && decodes(s, reading) {
        visit_views(s, tier, reading, f);
        return Ok(());
    }
    // The queries of URLs in it are walked as forms, with the key rules:
    // percent-encoding hides an e-mail from the rules.
    if depth < MAX_NESTED_JSON && url_queries(s, content, skipped, depth, rules, f)? {
        return Ok(());
    }
    visit_views(s, tier, Reading::Nested, f);
    Ok(())
}

/// The tier of `s` as one text: identifier-shaped values under identifier
/// keys, or that look like identifiers, skip the ML model.
fn plain_tier(s: &str, content: bool, skipped: bool, rules: &Rules<'_>) -> Tier {
    if !content && id_shaped(s) && (skipped || rules.is_identifier(s)) {
        Tier::Identifier
    } else {
        Tier::Text
    }
}

/// Visit `s` (no JSON opened) as it reads literally and, when it reads
/// differently decoded, as it reads decoded: each component (form keys,
/// values and pieces, URL path segments, queries and fragments) that holds
/// a `%XX` escape or a `+`, decoded on its own. What either reading finds
/// is replaced in the raw text (re-encoded where the raw text was encoded),
/// so a value survives in neither.
fn visit_views(s: &mut String, tier: Tier, reading: Reading, f: Visit<'_>) {
    if s.trim().is_empty() {
        return;
    }
    if !decodes(s, reading) {
        f.visit(s, tier);
        return;
    }
    let orig = s.clone();
    // Decoded components first: a value's canonical spelling gets its tag
    // before the fragments the literal reading may see.
    let mut hits: Option<Vec<Hit>> = Some(Vec::new());
    let mut decoded_changed = Vec::new();
    for (n, (a, b)) in components(&orig).into_iter().enumerate() {
        let (d, map) = decode_mapped(&orig[a..b]);
        if d == orig[a..b] || d.trim().is_empty() {
            continue;
        }
        let mut dd = d.clone();
        f.visit(&mut dd, tier);
        match (f.found(), hits.as_mut()) {
            (Some(found), Some(hits)) => {
                for x in found {
                    let (start, end) = (a + map[x.start].0, a + map[x.end - 1].1);
                    hits.push(Hit {
                        start,
                        end,
                        surrogate: x.surrogate.clone(),
                        kind: x.kind.clone(),
                        visit: n + 1,
                        encoded: orig[start..end] != d[x.start..x.end],
                    });
                }
            }
            _ => hits = None,
        }
        if dd != d {
            decoded_changed.push((a, b, dd));
        }
    }
    let mut raw = orig.clone();
    f.visit(&mut raw, tier);
    match (f.found(), hits.as_mut()) {
        (Some(found), Some(hits)) => hits.extend(found.iter().map(|x| Hit {
            start: x.start,
            end: x.end,
            surrogate: x.surrogate.clone(),
            kind: x.kind.clone(),
            visit: 0,
            encoded: false,
        })),
        _ => hits = None,
    }
    *s = match hits {
        Some(hits) => merge_hits(&orig, hits, f),
        // A sink that cannot say what it replaced: the decoded reading's
        // changes, re-encoded, else the literal one's.
        None if !decoded_changed.is_empty() => {
            let mut out = String::with_capacity(orig.len());
            let mut last = 0;
            for (a, b, dd) in decoded_changed {
                out.push_str(&orig[last..a]);
                out.push_str(&encode_all(&dd));
                last = b;
            }
            out.push_str(&orig[last..]);
            out
        }
        None => raw,
    };
}

/// A replacement found in one reading of a text, in raw coordinates.
struct Hit {
    start: usize,
    end: usize,
    surrogate: String,
    kind: String,
    /// Which visit found it (0: the literal reading).
    visit: usize,
    /// The raw text it covers is encoded (`%XX` or `+`).
    encoded: bool,
}

/// Replace every hit in `orig`. Overlapping hits are one replacement: the
/// surrogates of those not inside another, in order (re-encoded when one
/// covers encoded text; of two over the same text, the decoded reading's).
/// A hit inside one found by another reading is the same value found
/// twice: not counted.
fn merge_hits(orig: &str, mut hits: Vec<Hit>, f: Visit<'_>) -> String {
    hits.sort_by_key(|h| (h.start, std::cmp::Reverse(h.end), !h.encoded, h.visit));
    let mut out = String::with_capacity(orig.len());
    let mut last = 0;
    let mut i = 0;
    while i < hits.len() {
        // One cluster of overlapping hits.
        let mut end = hits[i].end;
        let mut j = i + 1;
        while j < hits.len() && hits[j].start < end {
            end = end.max(hits[j].end);
            j += 1;
        }
        let cluster = &hits[i..j];
        let mut outer: Vec<&Hit> = Vec::new();
        for h in cluster {
            match outer.iter().find(|o| o.start <= h.start && h.end <= o.end) {
                Some(o) if o.visit != h.visit => f.forget(&h.kind),
                Some(_) => {}
                None => outer.push(h),
            }
        }
        let mut sur = String::new();
        let mut prev: Option<&str> = None;
        for o in &outer {
            if prev != Some(o.surrogate.as_str()) {
                sur.push_str(&o.surrogate);
            }
            prev = Some(o.surrogate.as_str());
        }
        if cluster.iter().any(|h| h.encoded) {
            sur = encode_all(&sur);
        }
        out.push_str(&orig[last..hits[i].start]);
        out.push_str(&sur);
        last = end;
        i = j;
    }
    out.push_str(&orig[last..]);
    out
}

/// The byte ranges of the components of `s` that are decoded on their own:
/// split at `&` and `=` (form keys, values and pieces) and at `/`, `?` and
/// `#` (URL path segments, query, fragment).
fn components(s: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, c) in s.bytes().enumerate() {
        if matches!(c, b'&' | b'=' | b'/' | b'?' | b'#') {
            if i > start {
                out.push((start, i));
            }
            start = i + 1;
        }
    }
    if s.len() > start {
        out.push((start, s.len()));
    }
    out
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

/// If `s` holds a JSON object or array, walk it and re-serialise it when a
/// text inside changed. Returns false when `s` is not JSON; JSON with a
/// repeated key is refused.
fn nested_json(
    s: &mut String,
    depth: usize,
    rules: &Rules<'_>,
    f: Visit<'_>,
) -> Result<bool, Malformed> {
    let t = s.trim();
    let bracketed =
        (t.starts_with('{') && t.ends_with('}')) || (t.starts_with('[') && t.ends_with(']'));
    if !bracketed {
        return Ok(false);
    }
    let mut inner = match parda_wire::body::parse_json_unique(s.as_bytes()) {
        Ok(v) => v,
        Err(JsonError::Invalid) => return Ok(false),
        Err(JsonError::DuplicateKey) => return Err(Malformed),
    };
    let mut track = Tracking {
        inner: f,
        changed: false,
    };
    walk_value(&mut inner, None, false, depth + 1, rules, &mut track)?;
    if track.changed {
        let out = parda_wire::walk::preserve_numbers(s.as_bytes(), inner.to_string().into_bytes());
        *s = String::from_utf8(out)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
    }
    Ok(true)
}

/// The byte ranges of the queries (after `?`, before `#`) of the `http://`
/// and `https://` URLs in `s`. A URL runs to whitespace, a quote or `<`/`>`.
fn url_query_spans(s: &str) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let rest = &b[i..];
        let scheme = if rest.len() >= 8 && rest[..8].eq_ignore_ascii_case(b"https://") {
            8
        } else if rest.len() >= 7 && rest[..7].eq_ignore_ascii_case(b"http://") {
            7
        } else {
            0
        };
        let starts_word = i == 0 || !b[i - 1].is_ascii_alphanumeric();
        if scheme == 0 || !starts_word {
            i += 1;
            continue;
        }
        // The URL's end, by characters (whitespace may be non-ASCII).
        let end = s[i..]
            .char_indices()
            .find(|&(_, c)| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`'))
            .map_or(s.len(), |(j, _)| i + j);
        let url = &b[i + scheme..end];
        if let Some(q) = url.iter().position(|&c| c == b'?') {
            let start = i + scheme + q + 1;
            let stop = b[start..end]
                .iter()
                .position(|&c| c == b'#')
                .map_or(end, |h| start + h);
            if stop > start {
                spans.push((start, stop));
            }
        }
        i = end.max(i + 1);
    }
    spans
}

/// If `s` holds URLs with queries, visit the text around them as usual and
/// each query as a form (decoded keys and values, re-encoded when changed).
/// Returns false when there is no such URL.
fn url_queries(
    s: &mut String,
    content: bool,
    skipped: bool,
    depth: usize,
    rules: &Rules<'_>,
    f: Visit<'_>,
) -> Result<bool, Malformed> {
    let spans = url_query_spans(s);
    if spans.is_empty() {
        return Ok(false);
    }
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for (start, stop) in spans {
        // The text before the query, without its `?`.
        let mut text = s[last..start - 1].to_string();
        let tier = plain_tier(&text, content, skipped, rules);
        visit_views(&mut text, tier, Reading::Nested, f);
        out.push_str(&text);
        out.push('?');
        let query = &s[start..stop];
        match walk_form_at(query, depth + 1, rules, f)? {
            Some(new) => out.push_str(&new),
            None => out.push_str(query),
        }
        last = stop;
    }
    let mut text = s[last..].to_string();
    let tier = plain_tier(&text, content, skipped, rules);
    visit_views(&mut text, tier, Reading::Nested, f);
    out.push_str(&text);
    *s = out;
    Ok(true)
}

/// One form-encoded component: `+` is a space, `%XX` a byte.
fn decode_component(s: &str) -> String {
    let spaced = s.replace('+', " ");
    percent_encoding::percent_decode_str(&spaced)
        .decode_utf8_lossy()
        .into_owned()
}

fn encode_component(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Visit the keys and values of a form-encoded string (a body or a query);
/// a piece without `=` is a text of its own. Returns the rewritten string
/// when something changed; keys, values and pieces that did not change keep
/// their exact bytes.
pub(crate) fn walk_form(
    raw: &str,
    rules: &Rules<'_>,
    f: Visit<'_>,
) -> Result<Option<String>, Malformed> {
    walk_form_at(raw, 0, rules, f)
}

fn walk_form_at(
    raw: &str,
    depth: usize,
    rules: &Rules<'_>,
    f: Visit<'_>,
) -> Result<Option<String>, Malformed> {
    let mut out = String::with_capacity(raw.len());
    let mut changed = false;
    for (i, piece) in raw.split('&').enumerate() {
        if i > 0 {
            out.push('&');
        }
        let Some((k_raw, v_raw)) = piece.split_once('=') else {
            let mut text = decode_component(piece);
            let before = text.clone();
            visit_at(&mut text, false, false, depth, Reading::Nested, rules, f)?;
            if text == before {
                out.push_str(piece);
            } else {
                changed = true;
                out.push_str(&encode_component(&text));
            }
            continue;
        };
        let key = decode_component(k_raw);
        let mut new_key = key.clone();
        visit_key(&mut new_key, rules, f);
        let mut value = decode_component(v_raw);
        let before = value.clone();
        visit_at(
            &mut value,
            is_content_key(&key),
            rules.skip_key(&key),
            depth,
            Reading::Nested,
            rules,
            f,
        )?;
        if new_key == key {
            out.push_str(k_raw);
        } else {
            changed = true;
            out.push_str(&encode_component(&new_key));
        }
        out.push('=');
        if value == before {
            out.push_str(v_raw);
        } else {
            changed = true;
            out.push_str(&encode_component(&value));
        }
    }
    Ok(changed.then_some(out))
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
            t.starts_with("text/") || t.starts_with("application/json") || t.contains("+json")
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
        };
        match text {
            Some(text) => {
                let mut value = text.clone();
                visit_field(&mut value, part.name.as_deref(), rules, f)?;
                if value != text {
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

    /// The texts visited, identifiers marked with a leading `#`.
    fn collect_json(v: &mut Value, r: &Rules<'_>) -> Vec<String> {
        let mut out = Vec::new();
        walk_json(v, r, &mut |s: &mut String, tier| out.push(mark(s, tier))).unwrap();
        out
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

    #[test]
    fn json_walk_visits_text_only() {
        let h = hosts();
        let r = rules(&h, &[], "chatgpt.com");
        let key = "sk-proj-0123456789abcdefghijABCDEFGHIJ0123456789";
        let mut v = json!({
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
            "client_contextual_info": {"page_title": "x"},
            "tags": ["a", "  "],
            "ids": ["aaa2b8c1-55f4-4bd2-9a1c-0123456789ab"],
        });
        assert_eq!(
            collect_json(&mut v, &r),
            // Every string and every key is visited. Identifier-shaped
            // values under identifier keys (or looking like ids) skip only
            // the model; a value with a space or an `@` is text under any
            // key; content keys (`parts`) are always text. Keys follow the
            // same rule: only known protocol keys (or id-looking ones) skip
            // the model.
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
                "#client_contextual_info",
                "page_title",
                "x",
                "tags",
                "a",
                "ids",
                "#aaa2b8c1-55f4-4bd2-9a1c-0123456789ab",
            ]
        );
    }

    #[test]
    fn json_in_strings_is_walked_and_reserialised() {
        let h = hosts();
        let r = rules(&h, &[], "gemini.google.com");
        let inner = r#"[["Ravi Kumar here",0,null,1e2],["en"],["c_1a2b3c","r_9f8e7d"]]"#;
        let mut v = json!([null, inner]);
        assert_eq!(
            collect_json(&mut v, &r),
            ["Ravi Kumar here", "en", "c_1a2b3c", "r_9f8e7d"]
        );
        walk_json(&mut v, &r, &mut |s: &mut String, t| {
            if s.starts_with("Ravi") {
                upper(s, t)
            }
        })
        .unwrap();
        assert_eq!(
            v[1],
            r#"[["RAVI KUMAR HERE",0,null,1e2],["en"],["c_1a2b3c","r_9f8e7d"]]"#
        );
        // Unchanged JSON-in-string keeps its exact text.
        let spaced = r#"{ "a" : "x" }"#;
        let mut v = json!({"blob": spaced});
        walk_json(&mut v, &r, &mut |_: &mut String, _: Tier| {}).unwrap();
        assert_eq!(v["blob"], spaced);
        // JSON typed into a content field is text: its keys get no say.
        let mut v = json!({"prompt": r#"{"id": "Ravi Kumar"}"#});
        assert_eq!(
            collect_json(&mut v, &r),
            ["#prompt", r#"{"id": "Ravi Kumar"}"#]
        );
        // Nesting beyond the limit is visited as text, never skipped.
        let mut s = String::from("\"deep Ravi\"");
        for _ in 0..6 {
            s = serde_json::to_string(&json!([s])).unwrap();
        }
        let mut v: Value = serde_json::from_str(&s).unwrap();
        let got = collect_json(&mut v, &r);
        assert_eq!(got.len(), 1);
        assert!(got[0].contains("deep Ravi") && got[0].starts_with('['));
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
        let mut v = json!({"a": 1, "Ravi Kumar": {"ravi k": 2}, "z": 3});
        walk_json(&mut v, &r, &mut { tag }).unwrap();
        assert_eq!(v.to_string(), r#"{"a":1,"[NAME_1]":{"[NAME_1]":2},"z":3}"#);
        // Two keys that would become the same text: one value would be
        // lost, so the body is refused.
        for mut v in [
            json!({"Ravi Kumar": 1, "ravi kumar": 2}),
            json!({"Ravi Kumar": 1, "[NAME_1]": 2}),
            json!([{"x": {"[NAME_1]": 1, "Ravi": 2}}]),
        ] {
            assert_eq!(walk_json(&mut v, &r, &mut { tag }), Err(Malformed));
        }
        // JSON repeating a key inside a string is refused too.
        let mut v = json!({"blob": r#"{"a":"x","a":"Ravi"}"#});
        assert_eq!(walk_json(&mut v, &r, &mut { tag }), Err(Malformed));
    }

    #[test]
    fn url_queries_in_strings_are_found() {
        fn spans(s: &str) -> Vec<&str> {
            url_query_spans(s)
                .into_iter()
                .map(|(a, b)| &s[a..b])
                .collect()
        }
        assert_eq!(spans("https://a.example/p?q=1#f"), ["q=1"]);
        assert_eq!(
            spans("x HTTP://a/?b=c d \"https://e/?f\" https://g/h #?i"),
            ["b=c", "f"]
        );
        assert_eq!(spans("https://a/b\u{a0}?c https://a/?"), Vec::<&str>::new());
        assert_eq!(spans("xhttps://a/?b ftp://a/?b https://é/?ü=1"), ["ü=1"]);
        assert!(spans("no url ?q=1").is_empty());
    }

    /// Scan R5.2/R5.3: the decoded reading maps every byte back to the raw
    /// text it came from, so a value found decoded is replaced in the raw
    /// text exactly.
    #[test]
    fn decoded_readings_map_back_to_raw_bytes() {
        let (d, map) = decode_mapped("a+%C3%A9%zz%FF%40b");
        assert_eq!(d, "a é%zz\u{fffd}@b");
        assert_eq!(map.len(), d.len());
        assert_eq!(map[1], (1, 2)); // `+`
        assert_eq!((map[2], map[3]), ((2, 5), (5, 8))); // `é` from two escapes
        assert_eq!(&map[7..10], &[(11, 14); 3]); // U+FFFD for `%FF`
        assert_eq!(map[10], (14, 17)); // `@`
        assert_eq!(
            components("https://x.example/u/a%40b/?q=1&r#f=g"),
            [
                (0, 6),
                (8, 17),
                (18, 19),
                (20, 25),
                (27, 28),
                (29, 30),
                (31, 32),
                (33, 34),
                (35, 36)
            ]
        );
        // Two readings of one text: one replacement where they overlap,
        // re-encoded where the raw text was encoded, counted once.
        struct Forget(Vec<String>);
        impl Sink for Forget {
            fn visit(&mut self, _: &mut String, _: Tier) {}
            fn forget(&mut self, kind: &str) {
                self.0.push(kind.to_string());
            }
        }
        let hit = |start, end, s: &str, visit, encoded| Hit {
            start,
            end,
            surrogate: s.into(),
            kind: "Person".into(),
            visit,
            encoded,
        };
        let orig = "n=Ravi%20Kumar&m=x.y+z@e.example";
        let mut sink = Forget(Vec::new());
        let out = merge_hits(
            orig,
            vec![
                hit(2, 6, "[NAME_2]", 0, false),
                hit(2, 14, "[NAME_1]", 1, true),
                hit(17, 32, "[EMAIL_1]", 0, false),
                hit(21, 32, "[EMAIL_2]", 2, false),
            ],
            &mut sink,
        );
        assert_eq!(out, "n=%5BNAME_1%5D&m=[EMAIL_1]");
        assert_eq!(sink.0.len(), 2);
    }

    #[test]
    fn form_values_are_rewritten_exactly() {
        let h = hosts();
        let r = rules(&h, &[], "gemini.google.com");
        let freq = serde_json::to_string(&json!([null, r#"[["Ravi Kumar",0]]"#])).unwrap();
        let enc: String = form_urlencoded::byte_serialize(freq.as_bytes()).collect();
        let raw = format!("f.req={enc}&at=AJvLN6M%3A1697000000000&q=Ravi+Kumar&flag&e=%E2%9C%93");
        let mut seen = Vec::new();
        assert_eq!(
            walk_form(&raw, &r, &mut |s: &mut String, t| seen.push(mark(s, t))),
            Ok(None)
        );
        // Keys too; a piece without `=` is a text of its own.
        assert_eq!(
            seen,
            [
                "f.req",
                "Ravi Kumar",
                "#at",
                "#AJvLN6M:1697000000000",
                "#q",
                "Ravi Kumar",
                "flag",
                "e",
                "✓"
            ]
        );
        let out = walk_form(&raw, &r, &mut |s: &mut String, t| {
            if s.starts_with("Ravi") {
                upper(s, t)
            }
        })
        .unwrap()
        .unwrap();
        let pairs: Vec<(String, String)> = form_urlencoded::parse(out.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(pairs[0].0, "f.req");
        let outer: Value = serde_json::from_str(&pairs[0].1).unwrap();
        assert_eq!(outer[1], r#"[["RAVI KUMAR",0]]"#);
        // Untouched pairs keep their bytes; changed ones are re-encoded.
        assert!(out.contains("&at=AJvLN6M%3A1697000000000&q=RAVI+KUMAR&flag&e=%E2%9C%93"));
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
        assert_eq!(seen, [field]);
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
