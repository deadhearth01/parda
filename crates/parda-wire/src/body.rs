//! Request bodies on routes parda rewrites: undo `Content-Encoding`, then
//! parse leniently but never fail open. A body that still cannot be read as
//! JSON is refused instead of being forwarded unredacted.

use std::io::Read;

use bytes::Bytes;
use http::HeaderMap;
use http::header::CONTENT_ENCODING;
use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

#[derive(Debug, PartialEq, Eq)]
pub enum BodyError {
    /// A `Content-Encoding` parda cannot decode (415).
    UnsupportedEncoding(String),
    /// The decoded body is larger than `proxy.max_body_bytes` (413).
    TooLarge,
    /// Corrupt compressed data or text that is not JSON (400).
    Unparseable(String),
}

/// Largest zstd window accepted (RFC 8878 recommends decoders support 8 MiB).
const ZSTD_MAX_WINDOW: u64 = 8 * 1024 * 1024;

/// The codings listed in `Content-Encoding`, in the order they were applied.
fn codings(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .flat_map(|v| {
            String::from_utf8_lossy(v.as_bytes())
                .split(',')
                .map(|c| c.trim().to_ascii_lowercase())
                .filter(|c| !c.is_empty() && c != "identity")
                .collect::<Vec<_>>()
        })
        .collect()
}

/// True if the request declares a `Content-Encoding` other than identity.
pub fn is_encoded(headers: &HeaderMap) -> bool {
    !codings(headers).is_empty()
}

/// Undo every `Content-Encoding` (gzip, deflate, br, zstd), never producing
/// more than `max` bytes.
pub fn decode(headers: &HeaderMap, body: Bytes, max: usize) -> Result<Bytes, BodyError> {
    let mut data = body;
    for coding in codings(headers).iter().rev() {
        data = decode_one(coding, &data, max)?;
    }
    Ok(data)
}

fn decode_one(coding: &str, data: &[u8], max: usize) -> Result<Bytes, BodyError> {
    let corrupt = |e: std::io::Error| BodyError::Unparseable(format!("invalid {coding} data: {e}"));
    let reader: Box<dyn Read + '_> = match coding {
        "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(data)),
        // HTTP "deflate" is zlib-wrapped; some clients send raw deflate.
        "deflate" => {
            if data.len() >= 2
                && data[0] & 0x0f == 8
                && (u16::from(data[0]) << 8 | u16::from(data[1])) % 31 == 0
            {
                Box::new(flate2::read::ZlibDecoder::new(data))
            } else {
                Box::new(flate2::read::DeflateDecoder::new(data))
            }
        }
        "br" => Box::new(brotli_decompressor::Decompressor::new(data, 4096)),
        "zstd" => Box::new(
            ruzstd::decoding::StreamingDecoder::new_with_max_window_size(data, ZSTD_MAX_WINDOW)
                .map_err(|e| BodyError::Unparseable(format!("invalid zstd data: {e}")))?,
        ),
        other => return Err(BodyError::UnsupportedEncoding(other.to_string())),
    };
    let mut out = Vec::new();
    reader
        .take(max as u64 + 1)
        .read_to_end(&mut out)
        .map_err(corrupt)?;
    if out.len() > max {
        return Err(BodyError::TooLarge);
    }
    Ok(Bytes::from(out))
}

/// Parse a JSON request body. A leading UTF-8 byte-order mark is skipped and
/// lone UTF-16 surrogate escapes (`"\ud83d"` from a JS client that cut an
/// emoji in half) become U+FFFD; anything else that is not JSON — including
/// nesting deeper than serde_json's limit — is an error.
pub fn parse_json(body: &[u8]) -> Result<Value, BodyError> {
    let body = body.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(body);
    match serde_json::from_slice(body) {
        Ok(v) => Ok(v),
        Err(first) => match replace_lone_surrogates(body) {
            Some(fixed) => {
                serde_json::from_slice(&fixed).map_err(|e| BodyError::Unparseable(e.to_string()))
            }
            None => Err(BodyError::Unparseable(first.to_string())),
        },
    }
}

/// [`parse_json`] for the bodies of routes parda rewrites: every one of them
/// is a JSON object, so any other value (`["text"]`, a bare string, …) is
/// refused rather than walked as if it held no text.
pub fn parse_object(body: &[u8]) -> Result<Value, BodyError> {
    let v = parse_json(body)?;
    if v.is_object() {
        return Ok(v);
    }
    let found = match v {
        Value::Array(_) => "an array",
        Value::String(_) => "a string",
        Value::Number(_) => "a number",
        Value::Bool(_) => "a boolean",
        _ => "null",
    };
    Err(BodyError::Unparseable(format!(
        "the top-level value must be a JSON object, not {found}"
    )))
}

/// Why [`parse_json_unique`] refused a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    /// Not JSON, even read leniently.
    Invalid,
    /// JSON with an object that names the same key twice. Parsers keep one
    /// of the two values (serde the last, others the first), so a filter
    /// that reads one could forward the other unread.
    DuplicateKey,
}

/// [`parse_json`] (BOM and lone surrogates tolerated), but an object that
/// names a key twice is an error rather than silently keeping the last.
pub fn parse_json_unique(body: &[u8]) -> Result<Value, JsonError> {
    fn parse(body: &[u8]) -> Result<Value, JsonError> {
        serde_json::from_slice::<Unique>(body)
            .map(|u| u.0)
            .map_err(|e| {
                // Only the visitor raises data errors: a repeated key.
                if e.is_data() {
                    JsonError::DuplicateKey
                } else {
                    JsonError::Invalid
                }
            })
    }
    let body = body.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(body);
    match parse(body) {
        Err(JsonError::Invalid) => match replace_lone_surrogates(body) {
            Some(fixed) => parse(&fixed),
            None => Err(JsonError::Invalid),
        },
        other => other,
    }
}

/// A JSON value whose objects have distinct keys.
struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(UniqueVisitor).map(Unique)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Number::from_f64(v).map_or(Value::Null, Value::Number))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Unique(v)) = seq.next_element()? {
            items.push(v);
        }
        Ok(Value::Array(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(A::Error::custom("duplicate object key"));
            }
            let Unique(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}

fn hex4(b: &[u8]) -> Option<u16> {
    let s = std::str::from_utf8(b.get(..4)?).ok()?;
    u16::from_str_radix(s, 16).ok()
}

/// Rewrite unpaired `\uD800`–`\uDFFF` escapes inside JSON strings as
/// `\ufffd`. Returns `None` when there is nothing to replace.
fn replace_lone_surrogates(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut changed = false;
    let mut in_string = false;
    let mut i = 0;
    while i < body.len() {
        let b = body[i];
        if !in_string {
            in_string = b == b'"';
            out.push(b);
            i += 1;
            continue;
        }
        match b {
            b'"' => {
                in_string = false;
                out.push(b);
                i += 1;
            }
            b'\\' if body.get(i + 1) == Some(&b'u') => {
                let Some(unit) = hex4(&body[i + 2..]) else {
                    out.push(b);
                    i += 1;
                    continue;
                };
                match unit {
                    0xD800..=0xDBFF => {
                        let low = (body.get(i + 6) == Some(&b'\\')
                            && body.get(i + 7) == Some(&b'u'))
                        .then(|| hex4(&body[i + 8..]))
                        .flatten()
                        .filter(|u| (0xDC00..=0xDFFF).contains(u));
                        if low.is_some() {
                            out.extend_from_slice(&body[i..i + 12]);
                            i += 12;
                        } else {
                            out.extend_from_slice(br"\ufffd");
                            changed = true;
                            i += 6;
                        }
                    }
                    0xDC00..=0xDFFF => {
                        out.extend_from_slice(br"\ufffd");
                        changed = true;
                        i += 6;
                    }
                    _ => {
                        out.extend_from_slice(&body[i..i + 6]);
                        i += 6;
                    }
                }
            }
            b'\\' => {
                // Any other escape: copy it whole so `\\` and `\"` never
                // start a fake escape or end the string.
                out.push(b);
                if let Some(&next) = body.get(i + 1) {
                    out.push(next);
                }
                i += 2;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    changed.then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_parse_refuses_repeated_keys() {
        let ok = br#"{"a":[1,-2,3.5,true,null,{"b":"\u0061"}],"c":{"a":1}}"#;
        assert_eq!(
            parse_json_unique(ok).unwrap(),
            serde_json::from_slice::<Value>(ok).unwrap()
        );
        assert_eq!(
            parse_json_unique(b"\xEF\xBB\xBF[\"\\ud83d x\"]").unwrap(),
            serde_json::json!(["\u{fffd} x"])
        );
        for dup in [
            &br#"{"a":1,"a":2}"#[..],
            br#"[{"x":{"a":1,"b":2,"a":3}}]"#,
            br#"{"a":1,"\u0061":2}"#,
            b"{\"a\":\"\\ud83d\",\"a\":1}",
        ] {
            assert_eq!(
                parse_json_unique(dup),
                Err(JsonError::DuplicateKey),
                "{}",
                String::from_utf8_lossy(dup)
            );
        }
        for bad in [&b"{"[..], b"Ravi", b"{\"a\":1}x", b""] {
            assert_eq!(parse_json_unique(bad), Err(JsonError::Invalid));
        }
    }

    fn fix(s: &str) -> Option<String> {
        replace_lone_surrogates(s.as_bytes()).map(|v| String::from_utf8(v).unwrap())
    }

    #[test]
    fn lone_surrogates() {
        assert_eq!(fix(r#"{"a":"x"}"#), None);
        assert_eq!(
            fix(r#"{"a":"\ud83d"}"#).as_deref(),
            Some(r#"{"a":"\ufffd"}"#)
        );
        assert_eq!(fix(r#"["\ud83d\ude00"]"#), None);
        assert_eq!(
            fix(r#"["\udc00\ud800\u0041"]"#).as_deref(),
            Some(r#"["\ufffd\ufffd\u0041"]"#)
        );
        assert_eq!(fix(r#"["\\ud800"]"#), None);
        assert_eq!(fix(r#"["\"\ud800"]"#).as_deref(), Some(r#"["\"\ufffd"]"#));
        // Outside strings nothing is touched (and the parse still fails).
        assert_eq!(fix(r#"\ud800"#), None);
        // Truncated escapes are left for the parser to reject.
        assert_eq!(fix(r#"["\ud8"#), None);
    }

    #[test]
    fn codings_parse_in_order() {
        let mut h = HeaderMap::new();
        assert!(!is_encoded(&h));
        h.insert(CONTENT_ENCODING, "identity".parse().unwrap());
        assert!(!is_encoded(&h));
        h.insert(CONTENT_ENCODING, "GZIP, br".parse().unwrap());
        assert_eq!(codings(&h), ["gzip", "br"]);
    }
}
