//! The engine-backed [`BodyTransform`]: personal data in requests to AI
//! sites is replaced by tags (or stand-ins, per `replace.style`) before it
//! leaves, and answers get the real values back.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use http::HeaderMap;
use http::header::CONTENT_TYPE;
use parda_core::{INTERCEPT_SCOPE_PER_HOST, InterceptConfig, UnscannedMedia};
use parda_engine::{Engine, EngineError};
use parda_wire::body::{self, BodyError};
use parda_wire::walk::preserve_numbers;
use serde_json::Value;

use crate::hosts::HostList;
use crate::server::MAX_REQUEST_BODY;
use crate::sites;
use crate::transform::RequestOutcome;
use crate::walk::{Rules, Tier, Visit, walk_form, walk_json, walk_multipart};
use crate::{BodyTransform, Refusal, StreamTransform};

/// The settings one request uses (a snapshot of `[intercept]`).
struct Settings {
    /// A fixed vault scope, or `None` for one scope per site.
    scope: Option<String>,
    unscanned: UnscannedMedia,
    skip_keys: Vec<String>,
    hosts: HostList,
}

impl Settings {
    /// The vault scope of `host`: `intercept:<listed host>` per site, so a
    /// site's answers only restore tags issued for text sent to it.
    fn scope_for(&self, host: &str) -> String {
        match &self.scope {
            Some(fixed) => fixed.clone(),
            None => {
                let site = self.hosts.entry_for(host).map_or_else(
                    || host.trim_end_matches('.').to_ascii_lowercase(),
                    str::to_string,
                );
                format!("intercept:{site}")
            }
        }
    }

    fn from_config(cfg: &InterceptConfig) -> Self {
        Settings {
            scope: (cfg.scope != INTERCEPT_SCOPE_PER_HOST).then(|| cfg.scope.clone()),
            unscanned: cfg.unscanned,
            skip_keys: cfg.skip_keys.clone(),
            hosts: HostList::new(&cfg.hosts),
        }
    }
}

/// Redacts requests and restores responses with the parda engine.
pub struct EngineTransform {
    engine: Engine,
    settings: RwLock<Arc<Settings>>,
}

impl EngineTransform {
    pub fn new(engine: Engine, cfg: &InterceptConfig) -> Self {
        EngineTransform {
            engine,
            settings: RwLock::new(Arc::new(Settings::from_config(cfg))),
        }
    }

    /// Apply new settings; the next request uses them. (`listen` and
    /// `hosts` also need the listener restarted to change what is
    /// decrypted.)
    pub fn set_config(&self, cfg: &InterceptConfig) {
        *self.settings.write().unwrap_or_else(|e| e.into_inner()) =
            Arc::new(Settings::from_config(cfg));
    }

    fn settings(&self) -> Arc<Settings> {
        self.settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Redact one request: its query string and its body, all texts in one
    /// engine batch.
    fn rewrite(
        &self,
        host: &str,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<RequestOutcome, Refusal> {
        let st = self.settings();
        let rules = Rules {
            hosts: &st.hosts,
            extra: &st.skip_keys,
            site: sites::for_host(host),
        };
        let (path, query) = match path_and_query.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path_and_query, None),
        };
        let mut body = ReqBody::prepare(headers, body)?;

        // Pass 1: collect the texts (identifiers skip only the ML model).
        let mut texts = Vec::new();
        let mut rules_only = Vec::new();
        let mut collect = |s: &mut String, tier: Tier| {
            texts.push(s.clone());
            rules_only.push(tier == Tier::Identifier);
        };
        if let Some(q) = query {
            walk_form(q, &rules, &mut collect);
        }
        let (_, unscanned) = body.walk(&rules, &mut collect)?;
        if unscanned > 0 && st.unscanned == UnscannedMedia::Block {
            return Err(refusal(
                415,
                "parda_unscanned_blocked",
                &format!(
                    "the request has {unscanned} part(s) parda cannot scan (files or binary \
                     data) and intercept.unscanned = \"block\"; it was not sent"
                ),
            ));
        }
        if texts.is_empty() {
            return Ok(RequestOutcome {
                body: body.into_bytes(),
                unscanned,
                ..RequestOutcome::default()
            });
        }

        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        let reds = self
            .engine
            .redact_many_tiered(&refs, &rules_only, &st.scope_for(host))
            .map_err(engine_refusal)?;
        let mut counts = BTreeMap::new();
        for r in &reds {
            for (k, n) in r.counts() {
                *counts.entry(k).or_insert(0) += n;
            }
        }

        // Pass 2: write the results back, in the same order.
        let mut results = reds.into_iter().map(|r| r.text);
        let mut assign = |s: &mut String, _: Tier| {
            if let Some(t) = results.next() {
                *s = t;
            }
        };
        let target = query
            .and_then(|q| walk_form(q, &rules, &mut assign))
            .map(|q| format!("{path}?{q}"));
        let (new_body, _) = body.walk(&rules, &mut assign)?;
        Ok(RequestOutcome {
            body: new_body.unwrap_or_else(|| body.into_bytes()),
            counts,
            unscanned,
            target,
        })
    }
}

/// A request body, decoded and classified by its content type.
enum ReqBody {
    Empty,
    Json {
        raw: Bytes,
        value: Value,
    },
    /// `application/x-www-form-urlencoded`.
    Form(String),
    Text(String),
    Multipart {
        raw: Bytes,
        boundary: String,
    },
    /// Forwarded unchanged, counted as unscanned.
    Opaque(Bytes),
}

impl ReqBody {
    fn prepare(headers: &HeaderMap, body: Bytes) -> Result<ReqBody, Refusal> {
        if body.is_empty() {
            return Ok(ReqBody::Empty);
        }
        let raw = body::decode(headers, body, MAX_REQUEST_BODY).map_err(|e| match e {
            BodyError::UnsupportedEncoding(_) => refusal(
                415,
                "parda_unsupported_encoding",
                "parda cannot decode this request's content-encoding; it was not sent",
            ),
            BodyError::TooLarge => refusal(
                413,
                "parda_body_too_large",
                "the request body is too large for parda to filter; it was not sent",
            ),
            BodyError::Unparseable(_) => unparseable(),
        })?;
        if raw.is_empty() {
            return Ok(ReqBody::Empty);
        }
        let (media, boundary) = media_type(headers);
        let text = || String::from_utf8(raw.to_vec()).ok();
        Ok(match media.as_str() {
            m if is_json(m) => {
                let value = body::parse_json(&raw).map_err(|_| unparseable())?;
                ReqBody::Json { raw, value }
            }
            "application/x-www-form-urlencoded" => match text() {
                Some(t) => ReqBody::Form(t),
                None => ReqBody::Opaque(raw),
            },
            "multipart/form-data" => match boundary {
                Some(boundary) => ReqBody::Multipart { raw, boundary },
                None => return Err(unparseable()),
            },
            // No type, or text: JSON is walked by the JSON rules (sites post
            // JSON as text/plain to avoid CORS preflights), other text whole.
            m if m.is_empty() || m.starts_with("text/") => match json_container(&raw) {
                Some(value) => ReqBody::Json { raw, value },
                None => match text() {
                    Some(t) => ReqBody::Text(t),
                    None => ReqBody::Opaque(raw),
                },
            },
            _ => ReqBody::Opaque(raw),
        })
    }

    /// Visit the texts; returns the rewritten body (when a text changed) and
    /// the number of unscanned parts.
    fn walk(&mut self, rules: &Rules<'_>, f: Visit<'_>) -> Result<(Option<Bytes>, u32), Refusal> {
        Ok(match self {
            ReqBody::Empty => (None, 0),
            ReqBody::Json { raw, value } => {
                let mut changed = false;
                walk_json(value, rules, &mut |t: &mut String, tier| {
                    let before = t.clone();
                    f(t, tier);
                    changed |= *t != before;
                });
                let out = changed.then(|| {
                    let json = serde_json::to_vec(value).unwrap_or_default();
                    Bytes::from(preserve_numbers(raw, json))
                });
                (out, 0)
            }
            ReqBody::Form(text) => (walk_form(text, rules, f).map(Bytes::from), 0),
            ReqBody::Text(text) => {
                if text.trim().is_empty() {
                    return Ok((None, 0));
                }
                let mut t = text.clone();
                f(&mut t, Tier::Text);
                ((t != *text).then(|| Bytes::from(t)), 0)
            }
            ReqBody::Multipart { raw, boundary } => {
                let w = walk_multipart(raw, boundary, rules, f).map_err(|_| unparseable())?;
                (w.body.map(Bytes::from), w.unscanned)
            }
            ReqBody::Opaque(_) => (None, 1),
        })
    }

    /// The decoded (identity) body.
    fn into_bytes(self) -> Bytes {
        match self {
            ReqBody::Empty => Bytes::new(),
            ReqBody::Json { raw, .. } | ReqBody::Multipart { raw, .. } | ReqBody::Opaque(raw) => {
                raw
            }
            ReqBody::Form(t) | ReqBody::Text(t) => Bytes::from(t),
        }
    }
}

fn is_json(media: &str) -> bool {
    media == "application/json" || media == "text/json" || media.ends_with("+json")
}

/// A JSON object or array, if `raw` is one.
fn json_container(raw: &[u8]) -> Option<Value> {
    let start = raw.iter().find(|b| !b.is_ascii_whitespace())?;
    if !matches!(start, b'{' | b'[') {
        return None;
    }
    body::parse_json(raw).ok()
}

/// The media type (lower-case, without parameters) and the multipart
/// boundary, from `Content-Type`.
fn media_type(headers: &HeaderMap) -> (String, Option<String>) {
    let Some(ct) = headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()) else {
        return (String::new(), None);
    };
    let mut parts = ct.split(';');
    let media = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    let boundary = parts
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("boundary"))
        .map(|(_, v)| v.trim().trim_matches('"').to_string())
        .filter(|b| !b.is_empty() && b.len() <= 200);
    (media, boundary)
}

/// A refusal; `code` first so clients and the event feed can match on it.
/// Messages never quote the request.
fn refusal(status: u16, code: &str, message: &str) -> Refusal {
    Refusal {
        status,
        message: format!("{code}: {message}"),
    }
}

fn unparseable() -> Refusal {
    refusal(
        400,
        "parda_unparseable_body",
        "parda could not read the request body, so it could not be filtered; it was not sent",
    )
}

fn engine_refusal(e: EngineError) -> Refusal {
    match e {
        EngineError::MlUnavailable(_) => refusal(
            503,
            "parda_ml_unavailable",
            "parda could not run its name detector; the message was not sent. Run `parda \
             doctor`, or set detect.mode = \"fast\" to allow rules-only redaction",
        ),
        EngineError::Blocked(kinds) => {
            let list = kinds
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            refusal(
                403,
                "parda_blocked",
                &format!("the message was blocked by parda policy (contains: {list})"),
            )
        }
        other => {
            tracing::error!(error = %other, "intercept: redaction failed");
            refusal(
                500,
                "parda_internal",
                "parda failed to filter the request; it was not sent",
            )
        }
    }
}

impl BodyTransform for EngineTransform {
    fn request(
        &self,
        host: &str,
        path: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<Bytes, Refusal> {
        self.rewrite(host, path, headers, body).map(|o| o.body)
    }

    /// As for the answer to a POST (see
    /// [`BodyTransform::response_stream_for`]).
    fn response_stream(
        &self,
        host: &str,
        path: &str,
        content_type: &str,
    ) -> Box<dyn StreamTransform> {
        self.response_stream_for(&http::Method::POST, host, path, content_type)
    }

    /// Answers are restored only for the user's own sends (POST) and own
    /// history (allowlisted GET endpoints per site); everything else passes
    /// through, so a page someone else wrote never gets the viewer's values.
    fn response_stream_for(
        &self,
        method: &http::Method,
        host: &str,
        path: &str,
        content_type: &str,
    ) -> Box<dyn StreamTransform> {
        let own = *method == http::Method::POST
            || (*method == http::Method::GET && sites::restores_get(host, path));
        if !own {
            return crate::restore::passthrough();
        }
        let scope = self.settings().scope_for(host);
        crate::restore::for_content_type(&self.engine, &scope, content_type)
    }

    fn request_outcome(
        &self,
        host: &str,
        path: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<RequestOutcome, Refusal> {
        self.rewrite(host, path, headers, body)
    }

    fn request_target(&self, host: &str, path_and_query: &str) -> Result<String, Refusal> {
        let out = self.rewrite(host, path_and_query, &HeaderMap::new(), Bytes::new())?;
        Ok(out.target.unwrap_or_else(|| path_and_query.to_string()))
    }

    fn rewrite_request(
        &self,
        host: &str,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<RequestOutcome, Refusal> {
        self.rewrite(host, path_and_query, headers, body)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write;
    use std::sync::Mutex;

    use super::*;
    use parda_core::{Config, Detection, MlDetector};
    use parda_detect::{PersonBlock, RulesFile};
    use parda_engine::EngineOptions;
    use serde_json::{Value, json};

    pub(crate) const UUID: &str = "aaa2b8c1-55f4-4bd2-9a1c-0123456789ab";
    /// A value that needs JSON escaping.
    pub(crate) const QUOTED: &str = "Flat 4\\B, \"Lotus\" Pune";
    /// A value outside the Basic Multilingual Plane (two UTF-16 units).
    pub(crate) const EMOJI: &str = "Lotus \u{1f600} Society";

    /// An engine that knows "Ravi Kumar" (no ML model unless `ml`).
    pub(crate) fn engine_with(
        dir: &std::path::Path,
        ml: Option<Arc<dyn MlDetector>>,
        tweak: impl FnOnce(&mut Config),
    ) -> Engine {
        let mut config = Config::default();
        config.detect.model = "none".into();
        tweak(&mut config);
        Engine::open(
            EngineOptions {
                config,
                rules: RulesFile {
                    person: vec![PersonBlock {
                        name: "Ravi Kumar".into(),
                        ..Default::default()
                    }],
                    term: vec![
                        parda_detect::Term {
                            text: QUOTED.into(),
                            ..Default::default()
                        },
                        parda_detect::Term {
                            text: EMOJI.into(),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
                data_dir: dir.join("data"),
                use_keyring: false,
            },
            ml,
        )
        .unwrap()
    }

    pub(crate) fn engine(dir: &std::path::Path) -> Engine {
        engine_with(dir, None, |_| {})
    }

    fn transform(e: &Engine, tweak: impl FnOnce(&mut InterceptConfig)) -> EngineTransform {
        let mut cfg = InterceptConfig::default();
        tweak(&mut cfg);
        EngineTransform::new(e.clone(), &cfg)
    }

    fn headers(content_type: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        if !content_type.is_empty() {
            h.insert(http::header::CONTENT_TYPE, content_type.parse().unwrap());
        }
        h
    }

    fn json_body(v: &Value) -> Bytes {
        Bytes::from(serde_json::to_vec(v).unwrap())
    }

    fn rewrite(t: &EngineTransform, host: &str, ct: &str, body: Bytes) -> RequestOutcome {
        t.rewrite_request(host, "/x", &headers(ct), body).unwrap()
    }

    fn refusal(t: &EngineTransform, ct: &str, body: impl Into<Bytes>) -> Refusal {
        t.rewrite_request("chatgpt.com", "/x", &headers(ct), body.into())
            .unwrap_err()
    }

    #[test]
    fn json_text_gets_tags_and_identifiers_stay() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let t = transform(&e, |_| {});
        let body = json!({
            "action": "next",
            "messages": [{
                "id": UUID,
                "author": {"role": "user"},
                "content": {"content_type": "text",
                            "parts": ["Email Ravi Kumar at ravi.kumar@example.com"]},
            }],
            "parent_message_id": "client-created-root",
            "model": "auto",
        });
        // A number serde_json cannot hold exactly is forwarded as written.
        let raw = serde_json::to_string(&body).unwrap();
        let raw = format!(
            "{},\"big\":123456789012345678901234567890}}",
            &raw[..raw.len() - 1]
        );
        let out = rewrite(
            &t,
            "chatgpt.com",
            "application/json",
            Bytes::from(raw.clone()),
        );
        let text = String::from_utf8(out.body.to_vec()).unwrap();
        assert_eq!(
            text,
            raw.replace(
                "Email Ravi Kumar at ravi.kumar@example.com",
                "Email [NAME_1] at [EMAIL_1]"
            )
        );
        assert_eq!(out.counts.get("Person"), Some(&1));
        assert_eq!(out.counts.get("Email"), Some(&1));
        assert_eq!(out.unscanned, 0);
        assert_eq!(out.target, None);
        // The same value gets the same tag again; a lower-case echo of the
        // tag restores too.
        assert_eq!(
            e.restore("[NAME_1] / [name_1]", "intercept:chatgpt.com"),
            "Ravi Kumar / Ravi Kumar"
        );
    }

    #[test]
    fn nothing_to_redact_forwards_the_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let t = transform(&engine(dir.path()), |_| {});
        let raw = "{ \"q\" : \"hello there\",\n \"n\": 1.50 }";
        let out = rewrite(
            &t,
            "claude.ai",
            "application/json; charset=utf-8",
            Bytes::from(raw),
        );
        assert_eq!(out.body, raw);
        assert!(out.counts.is_empty());
    }

    #[test]
    fn compressed_bodies_are_decoded() {
        let dir = tempfile::tempdir().unwrap();
        let t = transform(&engine(dir.path()), |_| {});
        let plain = json_body(&json!({"prompt": "I am Ravi Kumar"}));
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&plain).unwrap();
        let mut h = headers("application/json");
        h.insert(http::header::CONTENT_ENCODING, "gzip".parse().unwrap());
        let out = t
            .rewrite_request("claude.ai", "/x", &h, Bytes::from(gz.finish().unwrap()))
            .unwrap();
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(v["prompt"], "I am [NAME_1]");
        // An encoding parda cannot read is refused, never forwarded.
        h.insert(http::header::CONTENT_ENCODING, "compress".parse().unwrap());
        let r = t
            .rewrite_request("claude.ai", "/x", &h, plain.clone())
            .unwrap_err();
        assert_eq!(r.status, 415);
        // Corrupt data too.
        h.insert(http::header::CONTENT_ENCODING, "gzip".parse().unwrap());
        let r = t.rewrite_request("claude.ai", "/x", &h, plain).unwrap_err();
        assert_eq!(r.status, 400);
        assert!(
            r.message.starts_with("parda_unparseable_body"),
            "{}",
            r.message
        );
    }

    #[test]
    fn unparseable_json_is_refused_without_echoing_it() {
        let dir = tempfile::tempdir().unwrap();
        let t = transform(&engine(dir.path()), |_| {});
        for body in [
            &b"{\"prompt\": \"Ravi Kumar"[..],
            b"Ravi Kumar",
            b"\xff\xfe",
        ] {
            let r = refusal(&t, "application/json", Bytes::copy_from_slice(body));
            assert_eq!(r.status, 400);
            assert!(
                r.message.starts_with("parda_unparseable_body"),
                "{}",
                r.message
            );
            assert!(!r.message.contains("Ravi"));
        }
        // `+json` types are JSON too.
        let r = refusal(&t, "application/vnd.api+json", "nope");
        assert_eq!(r.status, 400);
    }

    #[test]
    fn form_bodies_and_query_strings_are_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let t = transform(&engine(dir.path()), |_| {});
        let out = rewrite(
            &t,
            "example.com",
            "application/x-www-form-urlencoded",
            Bytes::from("q=Ravi+Kumar&conversation_id=abc-123&n=1"),
        );
        assert_eq!(out.body, "q=%5BNAME_1%5D&conversation_id=abc-123&n=1");
        let out = t
            .rewrite_request(
                "example.com",
                &format!("/search?q=Ravi%20Kumar&chat_id={UUID}&x"),
                &HeaderMap::new(),
                Bytes::new(),
            )
            .unwrap();
        assert_eq!(
            out.target.as_deref(),
            Some(format!("/search?q=%5BNAME_1%5D&chat_id={UUID}&x").as_str())
        );
        assert_eq!(out.counts.get("Person"), Some(&1));
        assert_eq!(t.request_target("example.com", "/a?b=c").unwrap(), "/a?b=c");
    }

    #[test]
    fn plain_text_is_redacted_whole_and_json_text_by_the_json_rules() {
        let dir = tempfile::tempdir().unwrap();
        let t = transform(&engine(dir.path()), |_| {});
        let out = rewrite(
            &t,
            "example.com",
            "text/plain;charset=UTF-8",
            Bytes::from("hi Ravi Kumar"),
        );
        assert_eq!(out.body, "hi [NAME_1]");
        // Sites post JSON as text/plain to skip CORS preflights.
        let body = json!({"id": "Ravi Kumar", "msg": "Ravi Kumar", "chat_id": "abc-123"});
        let out = rewrite(&t, "example.com", "text/plain", json_body(&body));
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        // (`id` is an identifier key, but a name is never an identifier.)
        assert_eq!(
            v,
            json!({"id": "[NAME_1]", "msg": "[NAME_1]", "chat_id": "abc-123"})
        );
        // No content type at all: sniffed.
        let out = rewrite(&t, "example.com", "", Bytes::from("Ravi Kumar"));
        assert_eq!(out.body, "[NAME_1]");
    }

    #[test]
    fn skipping_never_hides_personal_data() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let t = transform(&e, |_| {});
        let send = |v: Value| -> Value {
            let out = rewrite(&t, "chatgpt.com", "application/json", json_body(&v));
            serde_json::from_slice(&out.body).unwrap()
        };
        // Identifier keys hold identifiers; anything else under them is
        // redacted like any text.
        assert_eq!(
            send(json!({"author": "Ravi Kumar"})),
            json!({"author": "[NAME_1]"})
        );
        assert_eq!(
            send(json!({"model": "ravi.k@gmail.com"})),
            json!({"model": "[EMAIL_1]"})
        );
        // Identifier-shaped values still meet the rule tier: the rules
        // decide about a phone-shaped id.
        let rules_say = e.redact("9876543210", "global").unwrap().text;
        assert_eq!(send(json!({"id": "9876543210"})), json!({"id": rules_say}));
        assert_eq!(
            send(json!({"type": "ravi.kumar@example.com"})),
            json!({"type": "[EMAIL_2]"})
        );
        // Genuine identifiers stay byte-identical.
        let ids = json_body(&json!({
            "id": UUID, "conversation_id": UUID, "parent_message_id": "client-created-root",
            "model": "gpt-4o", "type": "text", "role": "user", "nonce": "deadbeef00112233",
            "token": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3ODk",
            "link": "https://chatgpt.com/c/0123abcd", "prompt": "hi there"
        }));
        assert_eq!(
            rewrite(&t, "chatgpt.com", "application/json", ids.clone()).body,
            ids
        );
        // Beyond the JSON-in-string depth limit the rest is redacted as text.
        let mut s = json!({"note": "Ravi Kumar, ravi@example.com"}).to_string();
        for _ in 0..6 {
            s = json!([s]).to_string();
        }
        let out = rewrite(
            &t,
            "chatgpt.com",
            "application/json",
            json_body(&json!({"blob": s})),
        );
        let text = String::from_utf8(out.body.to_vec()).unwrap();
        assert!(!text.contains("Ravi") && !text.contains("ravi@"), "{text}");
        // A string that only looks like JSON is text.
        let v = send(json!({"blob": "[Ravi Kumar, ravi@example.com"}));
        assert_eq!(v["blob"], "[[NAME_1], [EMAIL_3]");
        // Forms, queries and multipart follow the same rule.
        let out = rewrite(
            &t,
            "gemini.google.com",
            "application/x-www-form-urlencoded",
            Bytes::from(
                "conversation_id=Ravi+Kumar&at=AJvLN6M%3A1697000000000&type=ravi%40example.com",
            ),
        );
        assert_eq!(
            out.body,
            "conversation_id=%5BNAME_1%5D&at=AJvLN6M%3A1697000000000&type=%5BEMAIL_1%5D"
        );
        let out = t
            .rewrite_request(
                "example.com",
                "/s?chat_id=Ravi%20Kumar",
                &HeaderMap::new(),
                Bytes::new(),
            )
            .unwrap();
        assert_eq!(out.target.as_deref(), Some("/s?chat_id=%5BNAME_1%5D"));
        let mp = "--b\r\nContent-Disposition: form-data; name=\"conversation_id\"\r\n\r\n\
                  Ravi Kumar\r\n--b--\r\n";
        let out = rewrite(
            &t,
            "example.com",
            "multipart/form-data; boundary=b",
            Bytes::from(mp),
        );
        assert_eq!(out.body, mp.replace("Ravi Kumar", "[NAME_1]"));
    }

    /// Restore `body` as the answer of `host`.
    fn answer(t: &EngineTransform, host: &str, body: &str) -> String {
        let mut r = t.response_stream(host, "/", "text/plain");
        let mut out = r.push(body.as_bytes()).to_vec();
        out.extend_from_slice(&r.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn only_post_answers_and_own_history_are_restored() {
        let dir = tempfile::tempdir().unwrap();
        let t = transform(&engine(dir.path()), |_| {});
        let restores = |method: http::Method, host: &str, path: &str| {
            !t.response_stream_for(&method, host, path, "application/json")
                .is_passthrough()
        };
        use http::Method;
        // The user's own sends.
        assert!(restores(
            Method::POST,
            "chatgpt.com",
            "/backend-api/conversation"
        ));
        assert!(restores(
            Method::POST,
            "gemini.google.com",
            "/_/BardChatUi/data/batchexecute"
        ));
        // The user's own history.
        assert!(restores(
            Method::GET,
            "chatgpt.com",
            "/backend-api/conversation/6f1c2a9e"
        ));
        assert!(restores(
            Method::GET,
            "chatgpt.com",
            "/backend-api/conversations"
        ));
        assert!(restores(
            Method::GET,
            "claude.ai",
            "/api/organizations/o1/chat_conversations/c1"
        ));
        assert!(restores(
            Method::GET,
            "claude.ai",
            "/api/organizations/o1/chat_conversations"
        ));
        // Everything else: shared pages, GPTs, snapshots, other methods.
        assert!(!restores(
            Method::GET,
            "chatgpt.com",
            "/backend-api/share/abc"
        ));
        assert!(!restores(
            Method::GET,
            "chatgpt.com",
            "/backend-api/gizmos/g-1"
        ));
        assert!(!restores(
            Method::GET,
            "chatgpt.com",
            "/backend-api/conversation/a/b"
        ));
        assert!(!restores(
            Method::GET,
            "claude.ai",
            "/api/chat_snapshots/s1"
        ));
        assert!(!restores(Method::GET, "perplexity.ai", "/rest/thread/x"));
        assert!(!restores(
            Method::PUT,
            "chatgpt.com",
            "/backend-api/conversation"
        ));
        assert!(!restores(
            Method::PATCH,
            "chatgpt.com",
            "/backend-api/conversation/x"
        ));
    }

    #[test]
    fn scopes_are_per_site_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let t = transform(&e, |_| {});
        let out = rewrite(
            &t,
            "chatgpt.com",
            "text/plain",
            Bytes::from("I am Ravi Kumar"),
        );
        assert_eq!(out.body, "I am [NAME_1]");
        // Only the site the tag was issued for gets the value back
        // (subdomains are the same site).
        assert_eq!(answer(&t, "chatgpt.com", "hi [NAME_1]"), "hi Ravi Kumar");
        assert_eq!(answer(&t, "ab.chatgpt.com", "hi [NAME_1]"), "hi Ravi Kumar");
        assert_eq!(answer(&t, "claude.ai", "hi [NAME_1]"), "hi [NAME_1]");
        assert_eq!(e.restore("[NAME_1]", "intercept:chatgpt.com"), "Ravi Kumar");
        // Tags from other surfaces (the clipboard, the agent proxy) are not
        // restored on any site.
        let dir2 = tempfile::tempdir().unwrap();
        let e2 = engine(dir2.path());
        assert_eq!(e2.redact("Ravi Kumar", "global").unwrap().text, "[NAME_1]");
        let t2 = transform(&e2, |_| {});
        assert_eq!(answer(&t2, "claude.ai", "hi [NAME_1]"), "hi [NAME_1]");
        // A fixed scope name is shared by every site.
        let t3 = transform(&e2, |c| c.scope = "global".into());
        assert_eq!(answer(&t3, "claude.ai", "hi [NAME_1]"), "hi Ravi Kumar");
        let out = rewrite(&t3, "claude.ai", "text/plain", Bytes::from("Ravi Kumar"));
        assert_eq!(out.body, "[NAME_1]");
    }

    fn multipart_body() -> Bytes {
        Bytes::from(
            "--b0\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nI am Ravi Kumar\r\n\
             --b0\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\
             Content-Type: text/plain\r\n\r\nRavi Kumar\r\n--b0--\r\n",
        )
    }

    #[test]
    fn multipart_files_and_binary_bodies_are_unscanned() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let t = transform(&e, |_| {});
        let ct = "multipart/form-data; boundary=\"b0\"";
        let out = rewrite(&t, "example.com", ct, multipart_body());
        assert_eq!(
            out.body,
            String::from_utf8(multipart_body().to_vec())
                .unwrap()
                .replace("I am Ravi Kumar", "I am [NAME_1]")
        );
        assert_eq!(out.unscanned, 1);
        let out = rewrite(
            &t,
            "example.com",
            "application/octet-stream",
            Bytes::from("Ravi Kumar"),
        );
        assert_eq!((out.body.as_ref(), out.unscanned), (&b"Ravi Kumar"[..], 1));
        // A multipart body without a usable boundary is refused.
        let r = refusal(&t, "multipart/form-data", multipart_body());
        assert_eq!(r.status, 400);

        let t = transform(&e, |c| c.unscanned = UnscannedMedia::Block);
        let r = refusal(&t, ct, multipart_body());
        assert_eq!(r.status, 415);
        assert!(
            r.message.starts_with("parda_unscanned_blocked"),
            "{}",
            r.message
        );
        assert_eq!(refusal(&t, "image/png", "x").status, 415);
        // Text-only multipart is fine in block mode.
        let text_only =
            "--b0\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nhi\r\n--b0--\r\n";
        assert_eq!(
            rewrite(&t, "example.com", ct, Bytes::from(text_only)).unscanned,
            0
        );
    }

    /// Fails every batch (strict mode refuses the send).
    pub(crate) struct FailingMl;

    impl MlDetector for FailingMl {
        fn name(&self) -> &str {
            "failing"
        }
        fn detect_batch(&self, _: &[&str]) -> anyhow::Result<Vec<Vec<Detection>>> {
            anyhow::bail!("model crashed")
        }
    }

    /// Records the size of every batch.
    struct CountingMl(Mutex<Vec<usize>>);

    impl MlDetector for CountingMl {
        fn name(&self) -> &str {
            "counting"
        }
        fn detect_batch(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<Detection>>> {
            self.0.lock().unwrap().push(texts.len());
            Ok(vec![Vec::new(); texts.len()])
        }
    }

    #[test]
    fn engine_failures_refuse_without_values() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine_with(dir.path(), Some(Arc::new(FailingMl)), |c| {
            c.detect.model = "failing".into()
        });
        let t = transform(&e, |_| {});
        let r = refusal(
            &t,
            "application/json",
            json_body(&json!({"prompt": "Ravi Kumar"})),
        );
        assert_eq!(r.status, 503);
        assert!(
            r.message.starts_with("parda_ml_unavailable"),
            "{}",
            r.message
        );
        assert!(!r.message.contains("Ravi"));

        let dir = tempfile::tempdir().unwrap();
        let e = engine_with(dir.path(), None, |c| {
            c.detect
                .actions
                .insert(parda_core::EntityKind::Email, parda_core::Action::Block);
        });
        let t = transform(&e, |_| {});
        let r = refusal(
            &t,
            "application/json",
            json_body(&json!({"prompt": "mail ravi@example.com"})),
        );
        assert_eq!(r.status, 403);
        assert!(r.message.starts_with("parda_blocked") && r.message.contains("Email"));
        assert!(!r.message.contains("ravi@"));
    }

    #[test]
    fn one_request_is_one_engine_batch() {
        let dir = tempfile::tempdir().unwrap();
        let ml = Arc::new(CountingMl(Mutex::new(Vec::new())));
        let e = engine_with(dir.path(), Some(ml.clone()), |c| {
            c.detect.model = "counting".into()
        });
        let t = transform(&e, |_| {});
        let body = json_body(&json!({"a": "first text here", "b": ["second text", "third one"]}));
        t.rewrite_request(
            "example.com",
            "/x?q=fourth+text",
            &headers("application/json"),
            body,
        )
        .unwrap();
        let batches = ml.0.lock().unwrap().clone();
        assert_eq!(batches.len(), 1, "{batches:?}");
    }
}
