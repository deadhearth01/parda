//! Versioned NDJSON messages. Variant names are case-sensitive on the wire.
//!
//! Requests are internally tagged by `op`, responses by `kind`:
//!
//! ```text
//! {"op":"Redact","text":"...","scope":null}
//! {"kind":"Ok","ready":true}
//! {"kind":"Err","code":"version_mismatch","message":"..."}
//! {"kind":"Event","ts_ms":1,"surface":"proxy","summary":"...","counts":{},"latency_ms":null,"level":"info"}
//! ```

use std::{collections::BTreeMap, time::SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Request {
    Hello { version: u32 },
    Status,
    Redact { text: String, scope: Option<String> },
    Restore { text: String, scope: Option<String> },
    Scan { text: String },
    PasteSafe,
    Subscribe,
    RulesGet,
    RulesSet { rules_toml: String },
    VaultStats,
    VaultWipe { scope: Option<String> },
    ConfigGet,
    ConfigSet { toml: String },
    Reload,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Response {
    /// A JSON object, flattened next to `kind` on the wire. [`Response::ok`]
    /// and the transport normalize other values into objects (see there), and
    /// the key `kind` is reserved.
    Ok(Value),
    Err {
        code: String,
        message: String,
    },
    Event(Event),
}

impl Response {
    /// Build a success response from any serializable payload.
    ///
    /// The wire form is `{"kind":"Ok", ...fields}`, so the payload must end up
    /// a JSON object: a struct or map is used as is, `()`/`null` becomes an
    /// empty object, and any other value (array, string, number, bool) is
    /// wrapped as `{"value": <v>}`. An object that already has a `kind` key
    /// would shadow the tag and yields an `invalid_response` error instead, as
    /// does a payload that fails to serialize.
    pub fn ok<T: Serialize>(v: T) -> Self {
        match serde_json::to_value(v) {
            Ok(value) => Self::Ok(value).normalized(),
            Err(_) => Self::err("invalid_response", "response payload is not serializable"),
        }
    }

    pub fn err(code: &str, msg: impl Into<String>) -> Self {
        Self::Err {
            code: code.into(),
            message: msg.into(),
        }
    }

    /// Apply the [`Response::ok`] payload rules to a directly built `Ok`.
    pub(crate) fn normalized(self) -> Self {
        let Self::Ok(value) = self else {
            return self;
        };
        match value {
            Value::Object(map) if map.contains_key("kind") => Self::err(
                "invalid_response",
                "Ok payload must not contain a `kind` key",
            ),
            Value::Object(map) => Self::Ok(Value::Object(map)),
            Value::Null => Self::Ok(Value::Object(Map::new())),
            other => Self::Ok(Value::Object(Map::from_iter([("value".to_owned(), other)]))),
        }
    }
}

/// A summary for clients. Producers must omit raw PII unless explicitly enabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub ts_ms: u64,
    pub surface: String,
    pub summary: String,
    pub counts: BTreeMap<String, u32>,
    pub latency_ms: Option<u64>,
    pub level: String,
}

impl Event {
    /// Timestamp a summary with empty counts, unknown latency, and level `info`.
    pub fn now(surface: impl Into<String>, summary: impl Into<String>) -> Self {
        let millis = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        Self {
            ts_ms: u64::try_from(millis).unwrap_or(u64::MAX),
            surface: surface.into(),
            summary: summary.into(),
            counts: BTreeMap::new(),
            latency_ms: None,
            level: "info".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn redact_serializes_with_op_tag_and_flat_fields() {
        let req = Request::Redact {
            text: "mail ana@example.com".into(),
            scope: Some("chat".into()),
        };
        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({"op": "Redact", "text": "mail ana@example.com", "scope": "chat"})
        );
        let no_scope = Request::Redact {
            text: "x".into(),
            scope: None,
        };
        assert_eq!(
            serde_json::to_value(&no_scope).unwrap(),
            json!({"op": "Redact", "text": "x", "scope": null})
        );
        // A client may omit an absent scope entirely.
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"op":"Redact","text":"x"}"#).unwrap(),
            no_scope
        );
    }

    #[test]
    fn unit_and_struct_requests_use_op_only() {
        assert_eq!(
            serde_json::to_string(&Request::Status).unwrap(),
            r#"{"op":"Status"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::Hello {
                version: PROTOCOL_VERSION
            })
            .unwrap(),
            r#"{"op":"Hello","version":1}"#
        );
        assert_eq!(
            serde_json::to_value(Request::RulesSet {
                rules_toml: "r".into()
            })
            .unwrap(),
            json!({"op": "RulesSet", "rules_toml": "r"})
        );
    }

    #[test]
    fn err_serializes_with_kind_tag_and_flat_fields() {
        assert_eq!(
            serde_json::to_value(Response::err("version_mismatch", "nope")).unwrap(),
            json!({"kind": "Err", "code": "version_mismatch", "message": "nope"})
        );
        let back: Response =
            serde_json::from_str(r#"{"kind":"Err","code":"c","message":"m"}"#).unwrap();
        assert_eq!(back, Response::err("c", "m"));
    }

    #[test]
    fn ok_flattens_its_object_next_to_kind() {
        let response = Response::ok(json!({"ready": true, "n": 2}));
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value, json!({"kind": "Ok", "ready": true, "n": 2}));
        assert_eq!(serde_json::from_value::<Response>(value).unwrap(), response);
    }

    #[test]
    fn ok_payloads_are_normalized_to_objects() {
        assert_eq!(Response::ok(()), Response::Ok(json!({})));
        assert_eq!(Response::ok(7), Response::Ok(json!({"value": 7})));
        assert_eq!(
            Response::ok(vec!["a", "b"]),
            Response::Ok(json!({"value": ["a", "b"]}))
        );
        assert_eq!(
            Response::Ok(json!("raw")).normalized(),
            Response::Ok(json!({"value": "raw"}))
        );
        // The result always serializes, which a bare tagged scalar would not.
        for response in [Response::ok(()), Response::ok("s"), Response::ok([1, 2])] {
            assert!(serde_json::to_string(&response).is_ok());
        }
    }

    #[test]
    fn ok_payload_may_not_shadow_the_tag() {
        let response = Response::ok(json!({"kind": "Event"}));
        assert!(matches!(response, Response::Err { ref code, .. } if code == "invalid_response"));
        // Errors and events pass through unchanged.
        let err = Response::err("a", "b");
        assert_eq!(err.clone().normalized(), err);
    }

    #[test]
    fn event_shape_and_builder() {
        let event = Event::now("proxy", "redacted 2 values");
        assert!(event.ts_ms > 1_700_000_000_000, "milliseconds since epoch");
        assert_eq!(event.level, "info");
        assert!(event.counts.is_empty());
        assert_eq!(event.latency_ms, None);

        let event = Event {
            counts: BTreeMap::from([("EMAIL".to_owned(), 2)]),
            latency_ms: Some(3),
            ..event
        };
        let value = serde_json::to_value(Response::Event(event.clone())).unwrap();
        assert_eq!(
            value,
            json!({
                "kind": "Event",
                "ts_ms": event.ts_ms,
                "surface": "proxy",
                "summary": "redacted 2 values",
                "counts": {"EMAIL": 2},
                "latency_ms": 3,
                "level": "info",
            })
        );
        assert_eq!(
            serde_json::from_value::<Response>(value).unwrap(),
            Response::Event(event)
        );
    }
}
