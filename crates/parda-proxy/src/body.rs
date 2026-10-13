//! Request bodies on routes parda rewrites: undo `Content-Encoding`, then
//! parse leniently but never fail open. A body that still cannot be read as
//! JSON is refused instead of being forwarded unredacted.

use std::io::Read;

use bytes::Bytes;
use http::HeaderMap;
use http::header::CONTENT_ENCODING;
use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BodyError {
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
pub(crate) fn is_encoded(headers: &HeaderMap) -> bool {
    !codings(headers).is_empty()
}

/// Undo every `Content-Encoding` (gzip, deflate, br, zstd), never producing
/// more than `max` bytes.
pub(crate) fn decode(headers: &HeaderMap, body: Bytes, max: usize) -> Result<Bytes, BodyError> {
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
pub(crate) fn parse_json(body: &[u8]) -> Result<Value, BodyError> {
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
