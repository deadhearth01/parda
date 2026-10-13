//! Which strings of an intercepted request are text to redact, and walking
//! them in JSON, form-encoded and multipart bodies and in query strings.
//!
//! Redaction walks a request twice in the same order: once to collect the
//! texts (one engine batch), once to write the results back.

use serde_json::Value;

use crate::hosts::HostList;
use crate::sites::Site;

/// Visits one text to redact; may replace it.
pub(crate) type Visit<'a> = &'a mut dyn FnMut(&mut String);

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

/// Identifier keys (lower-case patterns). Their values are never changed.
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
    /// Values under this key are never changed.
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

    /// Does `value` look like an identifier the site needs verbatim?
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

/// Visit every text in a JSON document.
pub(crate) fn walk_json(v: &mut Value, rules: &Rules<'_>, f: Visit<'_>) {
    walk_value(v, None, false, 0, rules, f);
}

/// `skipped`: the value sits under an identifier key; its strings (and
/// arrays of strings) are left alone, objects inside it are still walked.
fn walk_value(
    v: &mut Value,
    key: Option<&str>,
    skipped: bool,
    depth: usize,
    rules: &Rules<'_>,
    f: Visit<'_>,
) {
    match v {
        Value::String(s) if !skipped => visit_at(s, key, depth, rules, f),
        Value::Array(items) => {
            for x in items {
                walk_value(x, key, skipped, depth, rules, f);
            }
        }
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                let skip = rules.skip_key(k);
                walk_value(x, Some(k), skip, depth, rules, f);
            }
        }
        _ => {}
    }
}

/// Visit one string value found under `key` (keys are checked by the
/// caller).
pub(crate) fn visit_text(s: &mut String, key: Option<&str>, rules: &Rules<'_>, f: Visit<'_>) {
    visit_at(s, key, 0, rules, f);
}

fn visit_at(s: &mut String, key: Option<&str>, depth: usize, rules: &Rules<'_>, f: Visit<'_>) {
    if s.trim().is_empty() {
        return;
    }
    let content = key.is_some_and(is_content_key);
    if !content && depth < MAX_NESTED_JSON && nested_json(s, depth, rules, f) {
        return;
    }
    if !content && rules.is_identifier(s) {
        return;
    }
    f(s);
}

/// If `s` holds a JSON object or array, walk it and re-serialise it when a
/// text inside changed. Returns false when `s` is not JSON.
fn nested_json(s: &mut String, depth: usize, rules: &Rules<'_>, f: Visit<'_>) -> bool {
    let t = s.trim();
    let bracketed =
        (t.starts_with('{') && t.ends_with('}')) || (t.starts_with('[') && t.ends_with(']'));
    if !bracketed {
        return false;
    }
    let Ok(mut inner) = serde_json::from_str::<Value>(s) else {
        return false;
    };
    let mut changed = false;
    walk_value(
        &mut inner,
        None,
        false,
        depth + 1,
        rules,
        &mut |t: &mut String| {
            let before = t.clone();
            f(t);
            changed |= *t != before;
        },
    );
    if changed {
        let out = parda_wire::walk::preserve_numbers(s.as_bytes(), inner.to_string().into_bytes());
        *s = String::from_utf8(out)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
    }
    true
}

/// One form-encoded component: `+` is a space, `%XX` a byte.
fn decode_component(s: &str) -> String {
    let spaced = s.replace('+', " ");
    percent_encoding::percent_decode_str(&spaced)
        .decode_utf8_lossy()
        .into_owned()
}

/// Visit the values of a form-encoded string (a body or a query). Returns
/// the rewritten string when a value changed; pairs that did not change keep
/// their exact bytes.
pub(crate) fn walk_form(raw: &str, rules: &Rules<'_>, f: Visit<'_>) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut changed = false;
    for (i, piece) in raw.split('&').enumerate() {
        if i > 0 {
            out.push('&');
        }
        let Some((k_raw, v_raw)) = piece.split_once('=') else {
            out.push_str(piece);
            continue;
        };
        let key = decode_component(k_raw);
        if rules.skip_key(&key) {
            out.push_str(piece);
            continue;
        }
        let mut value = decode_component(v_raw);
        let before = value.clone();
        visit_text(&mut value, Some(&key), rules, f);
        if value == before {
            out.push_str(piece);
        } else {
            changed = true;
            out.push_str(k_raw);
            out.push('=');
            out.extend(form_urlencoded::byte_serialize(value.as_bytes()));
        }
    }
    changed.then_some(out)
}

/// A multipart body parda cannot split into parts.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Malformed;

/// What a multipart walk did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct MultipartWalk {
    /// The rewritten body, when a text part changed.
    pub(crate) body: Option<Vec<u8>>,
    /// File parts (and non-UTF-8 fields) forwarded unscanned.
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

/// `name` and whether a `filename` is present, from a part's headers.
fn disposition(headers: &str) -> (Option<String>, bool, Option<String>) {
    let mut name = None;
    let mut file = false;
    let mut content_type = None;
    for line in headers.split("\r\n") {
        let Some((h, v)) = line.split_once(':') else {
            continue;
        };
        let h = h.trim();
        if h.eq_ignore_ascii_case("content-type") {
            content_type = Some(v.trim().to_ascii_lowercase());
        } else if h.eq_ignore_ascii_case("content-disposition") {
            for param in v.split(';').skip(1) {
                let Some((pk, pv)) = param.split_once('=') else {
                    continue;
                };
                let pk = pk.trim().to_ascii_lowercase();
                if pk == "filename" || pk == "filename*" {
                    file = true;
                } else if pk == "name" {
                    name = Some(pv.trim().trim_matches('"').to_string());
                }
            }
        }
    }
    (name, file, content_type)
}

/// Visit the text fields of a `multipart/form-data` body: fields without a
/// filename whose type is text or JSON. Files are forwarded unchanged and
/// counted as unscanned.
pub(crate) fn walk_multipart(
    body: &[u8],
    boundary: &str,
    rules: &Rules<'_>,
    f: Visit<'_>,
) -> Result<MultipartWalk, Malformed> {
    let delim = format!("--{boundary}");
    let delim = delim.as_bytes();
    let next_delim = [b"\r\n".as_slice(), delim].concat();
    let mut pos = find(body, delim, 0).ok_or(Malformed)?;
    // A preamble must end in CRLF before the first delimiter.
    if pos != 0 && !(pos >= 2 && &body[pos - 2..pos] == b"\r\n") {
        return Err(Malformed);
    }
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[..pos]);
    let mut walk = MultipartWalk::default();
    let mut changed = false;
    loop {
        let after = pos + delim.len();
        if body[after..].starts_with(b"--") {
            out.extend_from_slice(&body[pos..]);
            break;
        }
        let line_end = find(body, b"\r\n", after).ok_or(Malformed)?;
        let headers_end = find(body, b"\r\n\r\n", line_end).ok_or(Malformed)?;
        let headers = String::from_utf8_lossy(&body[line_end + 2..headers_end.max(line_end + 2)]);
        let content_start = headers_end + 4;
        let content_end = find(body, &next_delim, content_start).ok_or(Malformed)?;
        let content = &body[content_start..content_end];
        out.extend_from_slice(&body[pos..content_start]);
        let (name, file, content_type) = disposition(&headers);
        let texty = content_type.as_deref().is_none_or(|t| {
            t.starts_with("text/") || t.starts_with("application/json") || t.contains("+json")
        });
        let mut new = None;
        if file || !texty {
            walk.unscanned += 1;
        } else if !name.as_deref().is_some_and(|n| rules.skip_key(n)) {
            match std::str::from_utf8(content) {
                Ok(text) => {
                    let mut value = text.to_string();
                    visit_text(&mut value, name.as_deref(), rules, f);
                    if value != text {
                        new = Some(value);
                    }
                }
                Err(_) => walk.unscanned += 1,
            }
        }
        match new {
            Some(value) => {
                if find(value.as_bytes(), delim, 0).is_some() {
                    return Err(Malformed);
                }
                changed = true;
                out.extend_from_slice(value.as_bytes());
            }
            None => out.extend_from_slice(content),
        }
        // The CRLF before the next delimiter belongs to the delimiter.
        out.extend_from_slice(b"\r\n");
        pos = content_end + 2;
    }
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

    fn collect_json(v: &mut Value, r: &Rules<'_>) -> Vec<String> {
        let mut out = Vec::new();
        walk_json(v, r, &mut |s: &mut String| out.push(s.clone()));
        out
    }

    fn upper(s: &mut String) {
        *s = s.to_uppercase();
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
            "model": "auto",
            "timezone_offset_min": -330,
            "client_contextual_info": {"page_title": "x"},
            "tags": ["a", "  "],
        });
        assert_eq!(
            collect_json(&mut v, &r),
            // Identifier keys (`author`, `client_*`) skip strings, but objects
            // under them are still walked; an identifier-looking value in
            // `parts` (a content key) is still text.
            ["Ravi Kumar", "Email Ravi Kumar", key, "x", "a"]
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
        walk_json(&mut v, &r, &mut |s: &mut String| {
            if s.starts_with("Ravi") {
                upper(s)
            }
        });
        assert_eq!(
            v[1],
            r#"[["RAVI KUMAR HERE",0,null,1e2],["en"],["c_1a2b3c","r_9f8e7d"]]"#
        );
        // Unchanged JSON-in-string keeps its exact text.
        let spaced = r#"{ "a" : "x" }"#;
        let mut v = json!({"blob": spaced});
        walk_json(&mut v, &r, &mut |_| {});
        assert_eq!(v["blob"], spaced);
        // JSON typed into a content field is text: its keys get no say.
        let mut v = json!({"prompt": r#"{"id": "Ravi Kumar"}"#});
        assert_eq!(collect_json(&mut v, &r), [r#"{"id": "Ravi Kumar"}"#]);
        // Nesting beyond the limit is visited as text.
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
    fn form_values_are_rewritten_exactly() {
        let h = hosts();
        let r = rules(&h, &[], "gemini.google.com");
        let freq = serde_json::to_string(&json!([null, r#"[["Ravi Kumar",0]]"#])).unwrap();
        let enc: String = form_urlencoded::byte_serialize(freq.as_bytes()).collect();
        let raw = format!("f.req={enc}&at=AJvLN6M%3A1697000000000&q=Ravi+Kumar&flag&e=%E2%9C%93");
        let mut seen = Vec::new();
        assert_eq!(
            walk_form(&raw, &r, &mut |s: &mut String| seen.push(s.clone())),
            None
        );
        assert_eq!(seen, ["Ravi Kumar", "Ravi Kumar", "✓"]);
        let out = walk_form(&raw, &r, &mut |s: &mut String| {
            if s.starts_with("Ravi") {
                upper(s)
            }
        })
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
        let w =
            walk_multipart(&body, "XyZ", &r, &mut |s: &mut String| seen.push(s.clone())).unwrap();
        assert_eq!(seen, ["Ravi Kumar asks"]);
        assert_eq!(
            w,
            MultipartWalk {
                body: None,
                unscanned: 1
            }
        );
        let w = walk_multipart(&body, "XyZ", &r, &mut upper).unwrap();
        let out = w.body.unwrap();
        let want = String::from_utf8_lossy(&body).replace("Ravi Kumar asks", "RAVI KUMAR ASKS");
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
}
