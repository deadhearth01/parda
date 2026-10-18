//! Request readings: a value found in any way a server may read a request
//! body (literally, form-decoded, as JSON of any kind, JSON inside strings)
//! must be gone from every reading of what parda forwards, or the request
//! is refused. Regression tests for the round-2 request findings
//! (`round2-request-findings.json`), and a generative differential test
//! over values, encoder chains and declared content types.

use bytes::Bytes;
use http::HeaderMap;
use http::header::CONTENT_TYPE;
use serde_json::Value;

use crate::engine_transform::EngineTransform;
use crate::engine_transform::tests::{engine, headers, rewrite, transform};
use crate::transform::{BodyTransform, Refusal, RequestOutcome};

/// Characters a lenient reader skips around a JSON text (Python `strip()`,
/// JS `trim()`, RFC 7464 record separators).
fn skippable(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}' || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `+` a space, `%XX` a byte (lossy).
fn form_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(&s.replace('+', " "))
        .decode_utf8_lossy()
        .into_owned()
}

/// Every way a server may read `s`, `depth` levels deep: as it is;
/// form-decoded as a whole and piece by piece (`&`, then `=`); and as JSON
/// (one value, or one value per line after skippable characters), each
/// string and key of it read again the same ways and each number as text.
/// Written independently of parda's own readings.
pub(crate) fn readings(s: &str, depth: usize, out: &mut Vec<String>) {
    out.push(s.to_string());
    if depth == 0 {
        return;
    }
    let whole = form_decode(s);
    if whole != s {
        readings(&whole, depth - 1, out);
    }
    for piece in s.split('&') {
        for part in piece.splitn(2, '=') {
            if part != s {
                readings(&form_decode(part), depth - 1, out);
            }
        }
    }
    let trimmed = s.trim_matches(skippable);
    let docs: Vec<Value> = match serde_json::from_str::<Value>(trimmed) {
        Ok(v) => vec![v],
        Err(_) => s
            .split(['\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}'])
            .filter_map(|l| serde_json::from_str::<Value>(l.trim_matches(skippable)).ok())
            .collect(),
    };
    for v in &docs {
        json_readings(v, depth - 1, out);
    }
}

fn json_readings(v: &Value, depth: usize, out: &mut Vec<String>) {
    match v {
        Value::String(s) => readings(s, depth, out),
        Value::Number(n) => out.push(n.to_string()),
        Value::Array(items) => items.iter().for_each(|x| json_readings(x, depth, out)),
        Value::Object(map) => {
            for (k, x) in map {
                readings(k, depth, out);
                json_readings(x, depth, out);
            }
        }
        _ => {}
    }
}

/// `secret` survives in no reading of `body`.
#[track_caller]
pub(crate) fn assert_gone(sent: &str, body: &[u8], secret: &str) {
    let text = String::from_utf8_lossy(body);
    let mut all = Vec::new();
    readings(&text, 5, &mut all);
    if let Some(r) = all.iter().find(|r| r.contains(secret)) {
        panic!("{sent:?} -> {text:?}: {secret:?} survives in the reading {r:?}");
    }
}

/// The request is refused as unreadable.
#[track_caller]
fn assert_unparseable(sent: &str, r: &Refusal) {
    assert_eq!(r.status, 400, "{sent:?}: {}", r.message);
    assert!(
        r.message.starts_with("parda_unparseable_body"),
        "{sent:?}: {}",
        r.message
    );
}

fn send(t: &EngineTransform, ct: &str, body: &str) -> Result<RequestOutcome, Refusal> {
    t.rewrite_request(
        "chatgpt.com",
        "/x",
        &headers(ct),
        Bytes::from(body.to_string()),
    )
}

/// `body` (as `ct`) goes out with `secret` gone from every reading.
#[track_caller]
fn redacted(t: &EngineTransform, ct: &str, body: &str, secret: &str) {
    let out = send(t, ct, body).unwrap_or_else(|r| panic!("{ct} {body:?}: {}", r.message));
    assert_gone(&format!("{ct} {body}"), &out.body, secret);
    assert!(!out.counts.is_empty(), "{ct} {body:?}");
}

const TEXT_TYPES: [&str; 3] = ["text/plain;charset=UTF-8", "text/plain", ""];
const FORM_TYPES: [&str; 2] = [
    "application/x-www-form-urlencoded",
    "application/x-www-form-urlencoded; charset=UTF-8",
];

/// Round 2, finding 1: a lone JSON string in a text/plain or untyped body
/// (JSON.stringify twice) was read as text, so the escapes in the JSON
/// inside it glued their letter to the value.
#[test]
fn r2_1_lone_json_strings_holding_json_are_opened() {
    let dir = tempfile::tempdir().unwrap();
    let t = transform(&engine(dir.path()), |_| {});
    for ct in TEXT_TYPES {
        for (inner, secret) in [
            (r#"{"m":"Contact:\n9876543210"}"#, "9876543210"),
            (r#"{"m":"Card:\t4111111111111111"}"#, "4111111111111111"),
            (r#"{"m":"José Ravi Kumar"}"#, "Kumar"),
        ] {
            let lone = Value::String(inner.to_string()).to_string();
            redacted(&t, ct, &lone, secret);
            redacted(&t, ct, &format!("{lone}\n\"x\""), secret);
        }
    }
}

/// Round 2, finding 2: a body typed as a form (jQuery's label for JSON)
/// holding JSON lines, a lone JSON string or escaped JSON-looking text was
/// read as a form, each `=`-less piece literally.
#[test]
fn r2_2_form_typed_json_lines_strings_and_escaped_text() {
    let dir = tempfile::tempdir().unwrap();
    let t = transform(&engine(dir.path()), |_| {});
    for ct in FORM_TYPES {
        for (body, secret) in [
            ("{\"t\":1}\n{\"m\":\"Phone:\\n9876543210\"}", "9876543210"),
            (
                "{\"t\":1}\n{\"m\":\"Card:\\t4111111111111111\"}",
                "4111111111111111",
            ),
            ("{\"t\":1}\n{\"m\":\"Hi\\nRavi Kumar\"}", "Kumar"),
            ("\"Phone:\\n9876543210\"", "9876543210"),
            ("\"Jos\\u00e9 Ravi\\u0020Kumar\"", "Kumar"),
            ("{\"t\":1}\n{\"m\":\"id 2345+6789+0124 x\"}", "6789"),
            ("data={\"m\":\"Phone:\\n9876543210\"}&x=1", "9876543210"),
            // A lone JSON string as a value, or one percent-encoded.
            ("a=1&data=\"Phone:\\n9876543210\"", "9876543210"),
            ("a=1&%22Phone%3A%5Cn9876543210%22", "9876543210"),
            (
                "q=%7B%22m%22%3A%22Phone%3A%5Cn9876543210%22%7D",
                "9876543210",
            ),
        ] {
            redacted(&t, ct, body, secret);
        }
        // Escaped JSON-looking text that is not JSON: refused.
        for body in [
            "{\"m\":\"Phone:\\n9876543210\", bad}",
            "x=1\n{\"m\":\"Phone:\\n9876543210\", bad}",
            "%7B%22m%22%3A%22Phone%3A%5Cn9876543210%22%2C%20bad%7D",
            "data={\"m\":\"Phone:\\n9876543210\", bad}",
        ] {
            assert_unparseable(body, &send(&t, ct, body).unwrap_err());
        }
        // A backslash that does not start like JSON, and JSON-looking text
        // without one, are form text.
        for body in [
            "a=1&b=C%3A%5Cnew+Ravi+Kumar",
            "q=%5BDraft%5D+Ravi+Kumar",
            "q=\"Ravi Kumar\"",
        ] {
            redacted(&t, ct, body, "Kumar");
        }
    }
}

/// Round 2, finding 3: RFC 7464 JSON text sequences (RS before each
/// record) and JSON after `\f`, `\v` or NBSP were read literally.
#[test]
fn r2_3_record_separators_and_unicode_whitespace_before_json() {
    let dir = tempfile::tempdir().unwrap();
    let t = transform(&engine(dir.path()), |_| {});
    for ct in TEXT_TYPES {
        for (body, secret) in [
            (
                "\u{1e}{\"m\":\"Card:\\t4111111111111111\"}\n",
                "4111111111111111",
            ),
            (
                "\u{1e}{\"t\":1}\n\u{1e}{\"m\":\"Phone:\\n9876543210\"}\n",
                "9876543210",
            ),
            ("\u{1e}{\"m\":\"Jos\\u00e9 Ravi\\u0020Kumar\"}", "Kumar"),
            ("\u{c}{\"m\":\"Phone:\\n9876543210\"}", "9876543210"),
            ("\u{b}{\"m\":\"Phone:\\n9876543210\"}", "9876543210"),
            ("\u{a0}{\"m\":\"Phone:\\n9876543210\"}", "9876543210"),
            (
                "\u{2028}{\"m\":\"Phone:\\n9876543210\"}\u{3000}",
                "9876543210",
            ),
            ("\u{1e}\"Aadhaar:\\n2345 6789 0124\"", "6789"),
            // Records without line breaks between them.
            (
                "\u{1e}{\"t\":1}\u{1e}{\"m\":\"Phone:\\n9876543210\"}",
                "9876543210",
            ),
        ] {
            redacted(&t, ct, body, secret);
        }
        // Escaped, JSON-looking after those characters, not JSON: refused.
        for body in [
            "\u{1e}{\"m\":\"Phone:\\n9876543210\", bad}\n",
            "note\n\u{a0}[\"Phone:\\n9876543210\"\n",
            "note\n\u{c}\"Phone:\\n9876543210",
        ] {
            assert_unparseable(body, &send(&t, ct, body).unwrap_err());
        }
    }
}

/// Round 2, finding 4: a single JSON object or array in a text/plain or
/// untyped body lost the readings JSON lines get: numbers as text and
/// strings form-decoded.
#[test]
fn r2_4_single_containers_get_every_reading() {
    let dir = tempfile::tempdir().unwrap();
    let t = transform(&engine(dir.path()), |_| {});
    for ct in TEXT_TYPES {
        for (body, secret) in [
            ("{\"phone\":9876543210}", "9876543210"),
            ("{\"card\":4111111111111111}", "4111111111111111"),
            ("{\"card\":4111111111111111}\n", "4111111111111111"),
            ("[234567890124]", "234567890124"),
            ("{\"m\":\"id 2345+6789+0124\"}", "6789"),
        ] {
            redacted(&t, ct, body, secret);
            // Still JSON (a number became a string).
            let out = send(&t, ct, body).unwrap();
            serde_json::from_slice::<Value>(&out.body).unwrap();
        }
    }
    // Declared JSON too: numbers are text.
    redacted(
        &t,
        "application/json",
        "{\"phone\":9876543210}",
        "9876543210",
    );
}

/// Round 2, finding 5: form-encoded text/plain or untyped bodies never
/// opened the JSON in their decoded values.
#[test]
fn r2_5_form_encoded_text_bodies_open_json_values() {
    let dir = tempfile::tempdir().unwrap();
    let t = transform(&engine(dir.path()), |_| {});
    for ct in TEXT_TYPES {
        for (body, secret) in [
            (
                "data={\"m\":\"Card:\\t4111111111111111\"}&x=1",
                "4111111111111111",
            ),
            ("q={\"m\":\"Phone:\\n9876543210\"}", "9876543210"),
            (
                "q=%7B%22m%22%3A%22Phone%3A%5Cn9876543210%22%7D",
                "9876543210",
            ),
        ] {
            redacted(&t, ct, body, secret);
        }
    }
}

fn field(name: &str, ct: Option<&str>, value: &str) -> String {
    let ct = ct.map_or(String::new(), |c| format!("Content-Type: {c}\r\n"));
    format!(
        "--BB\r\nContent-Disposition: form-data; name=\"{name}\"\r\n{ct}\r\n{value}\r\n--BB--\r\n"
    )
}

/// Round 2, finding 6: multipart text fields holding JSON lines or a lone
/// JSON string (even declared as JSON) were read literally, and escaped
/// JSON-looking text in them was never refused.
#[test]
fn r2_6_multipart_fields_get_the_body_readings() {
    let dir = tempfile::tempdir().unwrap();
    let t = transform(&engine(dir.path()), |_| {});
    let mp = "multipart/form-data; boundary=BB";
    for ct in [None, Some("text/plain"), Some("application/json")] {
        for (value, secret) in [
            ("{\"t\":1}\n{\"m\":\"Phone:\\n9876543210\"}", "9876543210"),
            ("\"Phone:\\n9876543210\"", "9876543210"),
            ("{\"m\":\"Phone:\\n9876543210\"}", "9876543210"),
            (
                "\u{1e}{\"m\":\"Card:\\t4111111111111111\"}",
                "4111111111111111",
            ),
        ] {
            if ct == Some("application/json") && value.contains('\n') {
                continue;
            }
            redacted(&t, mp, &field("meta", ct, value), secret);
        }
        let body = field("meta", ct, "{\"m\":\"Phone:\\n9876543210\", bad}");
        assert_unparseable(&body, &send(&t, mp, &body).unwrap_err());
    }
    // A field declared as JSON that is not JSON is refused.
    let body = field("meta", Some("application/json"), "Phone: 9876543210");
    assert_unparseable(&body, &send(&t, mp, &body).unwrap_err());
}

/// Round 2, finding 7: a Content-Type holding a byte outside visible ASCII
/// made the body look untyped, so a UTF-16 or Latin-1 body went out
/// unscanned instead of being refused; so did a second Content-Type.
#[test]
fn r2_7_unreadable_content_types_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let t = transform(&engine(dir.path()), |_| {});
    let utf16: Vec<u8> = "Ravi Kumar, ravi@example.com, 9876543210"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let latin1 = b"Ravi Kumar caf\xe9 9876543210".to_vec();
    for (ct, body) in [
        (&b"text/plain; charset=utf-16le; x=\xff"[..], &utf16),
        (b"application/json; charset=utf-16le; x=\xe9", &utf16),
        (b"text/plain; charset=iso-8859-1; v=\xe9", &latin1),
        // Unknown charsets on any type.
        (b"application/octet-stream; charset=x-unknown", &latin1),
    ] {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, http::HeaderValue::from_bytes(ct).unwrap());
        let r = t
            .rewrite_request("chatgpt.com", "/x", &h, Bytes::from(body.clone()))
            .unwrap_err();
        assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(ct));
        assert!(r.message.starts_with("parda_not_utf8"), "{}", r.message);
    }
    // Two Content-Types: refused, whichever comes first.
    let mut h = HeaderMap::new();
    h.append(CONTENT_TYPE, "application/octet-stream".parse().unwrap());
    h.append(
        CONTENT_TYPE,
        "text/plain; charset=utf-16le".parse().unwrap(),
    );
    let r = t
        .rewrite_request("chatgpt.com", "/x", &h, Bytes::from(utf16.clone()))
        .unwrap_err();
    assert_eq!(r.status, 400, "{}", r.message);
}

/// Implementer's open item: a value split across JSON tokens is found by
/// the literal reading of the whole text and replaced in each token; JSON
/// stays JSON.
#[test]
fn values_split_across_json_tokens_are_replaced_in_each() {
    let dir = tempfile::tempdir().unwrap();
    let t = transform(&engine(dir.path()), |_| {});
    for ct in ["application/json", "text/plain", ""] {
        for body in [
            r#"{"Ravi":"Kumar"}"#,
            r#"["Ravi","Kumar"]"#,
            r#"{"first":"Ravi","last":"Kumar","n":1}"#,
        ] {
            let out = send(&t, ct, body).unwrap();
            let v: Value = serde_json::from_slice(&out.body).unwrap();
            for secret in ["Ravi", "Kumar"] {
                assert_gone(body, &out.body, secret);
            }
            assert!(v.is_object() || v.is_array());
        }
    }
}

/// Nothing found in any reading: the exact bytes go on.
#[test]
fn clean_bodies_keep_their_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let t = transform(&engine(dir.path()), |_| {});
    for (ct, body) in [
        (
            "application/json",
            "{ \"q\" : \"hello there\",\n \"n\": 1.50e3, \"u\": \"a+b%20c\" }",
        ),
        (
            "text/plain",
            "\u{1e}{\"t\":1}\n\u{1e}{\"m\":\"hi\\nthere\"}\n",
        ),
        ("", "a=1&b=%7B%22m%22%3A%22hi%22%7D"),
        ("application/x-www-form-urlencoded", "a=1&b=x+y&c"),
    ] {
        let out = rewrite(&t, "chatgpt.com", ct, Bytes::from(body));
        assert_eq!(out.body, body, "{ct}");
        assert!(out.counts.is_empty(), "{ct}");
    }
}

/// One way a client encodes a text into a request body (or into a value
/// of one): each has a matching consumer ([`decode`]) that reads the text
/// back the way a server does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Enc {
    /// `{"t":1,"m":"<text>"}`: JSON escapes (`\n`, `\t`, `\"`).
    Json,
    /// `{"m":"<text>"}` with every character `\uXXXX`-escaped.
    JsonU,
    /// A lone JSON string (JSON.stringify of the text).
    JsonStr,
    /// `x=1&m=<text>`, form-encoded (`+` for spaces, `%XX`).
    Form,
    /// Every byte `%XX`, no key.
    Percent,
    /// `data=<text>&x=1`, only `%`, `&`, `+`, `=` encoded and spaces `+`
    /// (JSON in a form value, as jQuery sends it).
    Plus,
    /// An RFC 7464 record: RS, the text, LF.
    Rs,
    /// A second NDJSON line after `{"t":1}`.
    Ndjson,
    /// A multipart text field `meta` (boundary `BB<n>`).
    Multipart(u8),
}

const ENCODERS: [Enc; 9] = [
    Enc::Json,
    Enc::JsonU,
    Enc::JsonStr,
    Enc::Form,
    Enc::Percent,
    Enc::Plus,
    Enc::Rs,
    Enc::Ndjson,
    Enc::Multipart(0),
];

fn encode(e: Enc, text: &str) -> String {
    match e {
        Enc::Json => format!("{{\"t\":1,\"m\":{}}}", Value::String(text.into())),
        Enc::JsonU => {
            let escaped: String = text.encode_utf16().map(|u| format!("\\u{u:04x}")).collect();
            format!("{{\"m\":\"{escaped}\"}}")
        }
        Enc::JsonStr => Value::String(text.into()).to_string(),
        Enc::Form => format!(
            "x=1&m={}",
            form_urlencoded::byte_serialize(text.as_bytes()).collect::<String>()
        ),
        Enc::Percent => text.bytes().map(|b| format!("%{b:02X}")).collect(),
        Enc::Plus => {
            let v = text
                .replace('%', "%25")
                .replace('&', "%26")
                .replace('+', "%2B")
                .replace('=', "%3D")
                .replace(' ', "+");
            format!("data={v}&x=1")
        }
        Enc::Rs => format!("\u{1e}{text}\n"),
        Enc::Ndjson => format!("{{\"t\":1}}\n{text}\n"),
        Enc::Multipart(n) => format!(
            "--BB{n}\r\nContent-Disposition: form-data; name=\"meta\"\r\n\r\n{text}\r\n--BB{n}--\r\n"
        ),
    }
}

/// The matching consumer: the text a server reads back from `body`.
fn decode(e: Enc, body: &str) -> Option<String> {
    let json = || serde_json::from_str::<Value>(body).ok();
    let form = |key: &str| {
        form_urlencoded::parse(body.as_bytes())
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    };
    match e {
        Enc::Json | Enc::JsonU => Some(json()?.get("m")?.as_str()?.to_string()),
        Enc::JsonStr => Some(json()?.as_str()?.to_string()),
        Enc::Form => form("m"),
        Enc::Percent => Some(
            percent_encoding::percent_decode_str(body)
                .decode_utf8()
                .ok()?
                .into_owned(),
        ),
        Enc::Plus => form("data"),
        Enc::Rs => Some(body.strip_prefix('\u{1e}')?.strip_suffix('\n')?.to_string()),
        Enc::Ndjson => Some(
            body.strip_prefix("{\"t\":1}\n")?
                .strip_suffix('\n')?
                .to_string(),
        ),
        Enc::Multipart(n) => {
            let start = body.find("\r\n\r\n")? + 4;
            let end = body.rfind(&format!("\r\n--BB{n}--"))?;
            body.get(start..end).map(str::to_string)
        }
    }
}

/// Values the test engine finds: the fragment that must not survive, and
/// the value as typed.
const VALUES: [(&str, &str); 6] = [
    ("Kumar", "Ravi Kumar"),
    ("ravi.kumar@", "ravi.kumar@example.com"),
    ("9876543210", "9876543210"),
    // The engine finds a PAN by its label.
    ("ABCDE1234F", "PAN: ABCDE1234F"),
    ("6789", "2345 6789 0124"),
    ("4111111111111111", "4111111111111111"),
];

/// Text around a value: a JSON escape glues its letter to the value.
const CARRIERS: [&str; 2] = ["Contact:\n{} ok", "id {}"];

/// Declared types crossed with every chain (`None`: no Content-Type; the
/// multipart boundary is the outermost multipart encoder's).
const TYPES: [Option<&str>; 6] = [
    Some("application/json"),
    Some("text/plain"),
    Some("application/x-www-form-urlencoded"),
    None,
    Some("application/octet-stream"),
    Some("multipart/form-data"),
];

/// Multipart encoders get boundaries by depth, so nested fields never end
/// early.
fn numbered(chain: &[Enc]) -> Vec<Enc> {
    chain
        .iter()
        .enumerate()
        .map(|(i, e)| match e {
            Enc::Multipart(_) => Enc::Multipart(i as u8),
            other => *other,
        })
        .collect()
}

/// The type a real client declares for a body whose outer encoding is `e`.
fn natural(e: Enc) -> Option<&'static str> {
    Some(match e {
        Enc::Json | Enc::JsonU | Enc::JsonStr => "application/json",
        Enc::Form | Enc::Plus => "application/x-www-form-urlencoded",
        Enc::Percent | Enc::Rs | Enc::Ndjson => "text/plain",
        Enc::Multipart(_) => "multipart/form-data",
    })
}

/// What happened to one request.
#[derive(Debug, Default)]
struct Tally {
    sent: usize,
    refused: Vec<String>,
}

/// Send `value` through `chain` (innermost first) declared as `ty`; the
/// value must be gone from the text the matching consumers read back, and
/// from every reading of the forwarded body, or the request refused. A
/// body declared the way its outer encoding says is never refused.
fn differential(
    t: &EngineTransform,
    chain: &[Enc],
    (fragment, value): (&str, &str),
    carrier: &str,
    ty: Option<&str>,
    tally: &mut Tally,
) {
    let chain = numbered(chain);
    let mut body = carrier.replace("{}", value);
    for e in &chain {
        body = encode(*e, &body);
    }
    let outer = *chain.last().unwrap();
    let ct = match (ty, outer) {
        (Some("multipart/form-data"), Enc::Multipart(n)) => {
            format!("multipart/form-data; boundary=BB{n}")
        }
        (Some("multipart/form-data"), _) => "multipart/form-data; boundary=BB9".into(),
        (Some(ty), _) => ty.into(),
        (None, _) => String::new(),
    };
    let case = format!("{chain:?} as {ct:?}: {body:?}");
    match send(t, &ct, &body) {
        Err(r) => {
            assert!(
                matches!(r.status, 400 | 415),
                "{case}: {} {}",
                r.status,
                r.message
            );
            assert!(
                ty != natural(outer),
                "{case}: refused though declared as sent: {}",
                r.message
            );
            tally.refused.push(format!("{case} -> {}", r.message));
        }
        Ok(out) => {
            assert_eq!(out.unscanned, 0, "{case}");
            let sent = String::from_utf8(out.body.to_vec()).unwrap();
            let mut read = sent.clone();
            for e in chain.iter().rev() {
                read = decode(*e, &read)
                    .unwrap_or_else(|| panic!("{case} -> {sent:?}: {e:?} cannot read {read:?}"));
            }
            assert!(
                !read.contains(fragment),
                "{case} -> {sent:?}: the consumers read {read:?}"
            );
            assert_gone(&case, sent.as_bytes(), fragment);
        }
    }
    tally.sent += 1;
}

/// Acceptance: every value × every encoder chain of one or two encoders ×
/// every declared type.
#[test]
fn differential_readings_chains_of_one_and_two() {
    let dir = tempfile::tempdir().unwrap();
    let t = transform(&engine(dir.path()), |_| {});
    let mut chains: Vec<Vec<Enc>> = ENCODERS.iter().map(|e| vec![*e]).collect();
    for a in ENCODERS {
        for b in ENCODERS {
            chains.push(vec![a, b]);
        }
    }
    let mut tally = Tally::default();
    for chain in &chains {
        for v in VALUES {
            for carrier in CARRIERS {
                for ty in TYPES {
                    differential(&t, chain, v, carrier, ty, &mut tally);
                }
            }
        }
    }
    eprintln!(
        "differential: {} requests, {} refused",
        tally.sent,
        tally.refused.len()
    );
    if std::env::var_os("PARDA_PRINT_REFUSALS").is_some() {
        for r in &tally.refused {
            eprintln!("{r}");
        }
    }
}

mod generated {
    use super::*;
    use proptest::prelude::*;

    fn enc() -> impl Strategy<Value = Enc> {
        proptest::sample::select(ENCODERS.to_vec())
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

        /// Chains of three encoders, any value, carrier and type.
        #[test]
        fn differential_readings_chains_of_three(
            chain in proptest::collection::vec(enc(), 3),
            v in proptest::sample::select(VALUES.to_vec()),
            carrier in proptest::sample::select(CARRIERS.to_vec()),
            ty in proptest::sample::select(TYPES.to_vec()),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let t = transform(&engine(dir.path()), |_| {});
            differential(&t, &chain, v, carrier, ty, &mut Tally::default());
        }
    }
}

/// Scan on 31c4d85, ruling 1, and the follow-up ruling: numbers under
/// identifier keys still meet the rules. One that is certainly a value (an
/// Aadhaar number by Verhoeff, a card by Luhn, a valid Indian mobile)
/// refuses the request, as a string would break its type. A bare 10-digit
/// run is not enough, and an epoch time under a timestamp-like key is never
/// refused or rewritten.
#[test]
fn identifier_numbers_meet_the_rules() {
    let dir = tempfile::tempdir().unwrap();
    let t = transform(&engine(dir.path()), |_| {});
    for body in [
        "{\"id\":234567890124}",
        "{\"order_id\":4111111111111111}",
        "{\"user_id\":9876543210}",
    ] {
        for ct in ["application/json", "text/plain"] {
            assert_unparseable(body, &send(&t, ct, body).unwrap_err());
        }
    }
    for body in [
        "{\"timestamp\":1760000000}",
        "{\"created_at\":1760000000123}",
        "{\"expires\":1760000000.5}",
        "{\"ts\":1760000000123456,\"updatedAt\":1760000000}",
        "{\"create_time\":1760000000.123,\"parent_message_id\":\"client-created-root\"}",
        // Not certainly a value: a bare 10-digit run (no mobile prefix),
        // digits that fail the checksum.
        "{\"id\":1234567890}",
        "{\"conversation_id\":234567890125}",
        "{\"order_id\":4111111111111112}",
    ] {
        for ct in ["application/json", "text/plain"] {
            let out = send(&t, ct, body).unwrap_or_else(|r| panic!("{body}: {}", r.message));
            assert_eq!(out.body, body, "{ct}");
        }
    }
    // Outside identifier keys a number is text: a phone there is redacted.
    let out = send(&t, "application/json", "{\"phone\":9876543210}").unwrap();
    assert_gone("phone", &out.body, "9876543210");
}

/// Scan on 31c4d85, ruling 2: past the reading depth parda fails closed.
/// Text still encoded there (JSON-looking, escapes, `%XX`, `+`) is refused;
/// anything else is read literally and counted as unscanned.
#[test]
fn past_the_depth_limit_parda_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let t = transform(&engine(dir.path()), |_| {});
    let nest = |inner: &str, levels: usize| {
        let mut s = inner.to_string();
        for _ in 0..levels {
            s = Value::String(s).to_string();
        }
        format!("{{\"blob\":{s}}}")
    };
    // Four JSON-in-string levels hold a still-encoded text: refused.
    for inner in ["{\"m\":\"x\"}", "\"x\"", "a\\nb", "a%20b", "a+b"] {
        let body = nest(inner, 4);
        assert_unparseable(&body, &send(&t, "application/json", &body).unwrap_err());
    }
    // Plain text there: read literally, counted unscanned (refused under
    // "block").
    let body = nest("hello Ravi Kumar", 4);
    let out = send(&t, "application/json", &body).unwrap();
    assert_gone(&body, &out.body, "Kumar");
    assert_eq!(out.unscanned, 1);
    let block = transform(&engine(dir.path()), |c| {
        c.unscanned = parda_core::UnscannedMedia::Block
    });
    assert_eq!(
        send(&block, "application/json", &body).unwrap_err().status,
        415
    );
    // Two levels are read in full.
    let body = nest("{\"m\":\"Contact:\\n9876543210\"}", 2);
    let out = send(&t, "application/json", &body).unwrap();
    assert_gone(&body, &out.body, "9876543210");
    assert_eq!(out.unscanned, 0);
}
