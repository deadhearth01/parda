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
use crate::walk::{
    Found, JsonLine, Rules, Sink, Tier, Tracking, Visit, escaped_like_json, json_lines,
    utf8_charset, visit_body_text, walk_form, walk_json, walk_json_lines, walk_multipart,
};
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

    /// Apply new settings; the next request uses them, and the next CONNECT
    /// and PAC request use the new `hosts` (see [`BodyTransform::hosts`]).
    /// Only `listen` needs the listener restarted.
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
        let mut collect = Collect::default();
        if let Some(q) = query {
            walk_form(q, &rules, &mut collect).map_err(|_| unparseable())?;
        }
        let (_, mut unscanned) = body.walk(&rules, &mut collect)?;
        // An upgrade (WebSocket) tunnels its frames unread: one unscanned
        // part, refused before the handshake leaves under "block".
        if crate::server::is_upgrade(headers) {
            unscanned += 1;
        }
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
        let Collect { texts, rules_only } = collect;
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

        // Pass 2: write the results back, in the same order.
        let mut assign = Assign {
            results: reds.into_iter(),
            found: Vec::new(),
            counts: BTreeMap::new(),
        };
        let target = match query {
            Some(q) => walk_form(q, &rules, &mut assign)
                .map_err(|_| unparseable())?
                .map(|q| format!("{path}?{q}")),
            None => None,
        };
        let (new_body, _) = body.walk(&rules, &mut assign)?;
        Ok(RequestOutcome {
            body: new_body.unwrap_or_else(|| body.into_bytes()),
            counts: assign.counts,
            unscanned,
            target,
        })
    }
}

/// Pass 1: the texts of a request, and which skip the ML model.
#[derive(Default)]
struct Collect {
    texts: Vec<String>,
    rules_only: Vec<bool>,
}

impl Sink for Collect {
    fn visit(&mut self, s: &mut String, tier: Tier) {
        self.texts.push(s.clone());
        self.rules_only.push(tier == Tier::Identifier);
    }

    fn found(&self) -> Option<&[Found]> {
        Some(&[])
    }
}

/// Pass 2: the engine's results written back in the same order, with what
/// each replaced and the counts by kind.
struct Assign {
    results: std::vec::IntoIter<parda_engine::Redaction>,
    found: Vec<Found>,
    counts: BTreeMap<String, u32>,
}

impl Sink for Assign {
    fn visit(&mut self, s: &mut String, _: Tier) {
        self.found.clear();
        let Some(r) = self.results.next() else {
            return;
        };
        for x in &r.replaced {
            *self.counts.entry(x.kind.to_string()).or_insert(0) += 1;
            self.found.push(Found {
                start: x.original_span.start,
                end: x.original_span.end,
                surrogate: x.surrogate.clone(),
                kind: x.kind.to_string(),
            });
        }
        *s = r.text;
    }

    fn found(&self) -> Option<&[Found]> {
        Some(&self.found)
    }

    fn forget(&mut self, kind: &str) {
        if let Some(n) = self.counts.get_mut(kind) {
            *n -= 1;
            if *n == 0 {
                self.counts.remove(kind);
            }
        }
    }
}

/// A request body, decoded and classified by its content type.
enum ReqBody {
    Empty,
    Json {
        raw: Bytes,
        value: Value,
    },
    /// JSON values one per line (NDJSON), or one JSON value that is not an
    /// object or array, in a body not declared as JSON. Besides each line
    /// read as JSON, the readings a text body gets are kept (R8.2): strings
    /// and keys are also read decoded as a form, and numbers as the text
    /// they are, so a value survives no reading.
    JsonLines {
        text: String,
        lines: Vec<JsonLine>,
    },
    /// Declared `application/x-www-form-urlencoded`.
    Form(String),
    /// Any other text: redacted as it reads literally and as it reads
    /// decoded as a form.
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
        let form = media == "application/x-www-form-urlencoded";
        let typed_text = media.starts_with("text/");
        let not_utf8 = || {
            refusal(
                400,
                "parda_not_utf8",
                "the request body is not UTF-8 text, so parda could not filter it; it was not sent",
            )
        };
        // A body declared in another charset (UTF-16 of ASCII text is valid
        // UTF-8, NULs interleaved) cannot be read as text here.
        let declared = headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if (is_json(&media) || form || typed_text) && !utf8_charset(declared) {
            return Err(not_utf8());
        }
        if is_json(&media) {
            let value = body::parse_json_unique(&raw).map_err(|_| unparseable())?;
            return Ok(ReqBody::Json { raw, value });
        }
        if media == "multipart/form-data" {
            return match boundary {
                Some(boundary) => Ok(ReqBody::Multipart { raw, boundary }),
                None => Err(unparseable()),
            };
        }
        // Whatever the type says, a JSON object or array is walked as JSON:
        // sites post JSON as text/plain to skip CORS preflights, jQuery
        // labels it as a form, others as octet-stream.
        if let Some(value) = json_container(&raw)? {
            return Ok(ReqBody::Json { raw, value });
        }
        // So are JSON values one per line (batched telemetry, a Sentry
        // envelope), and a lone JSON string: a server parses each line, so
        // reading `\n9876543210` literally would miss the number.
        if !form
            && let Ok(text) = std::str::from_utf8(&raw)
            && let Some(lines) = json_lines(text).map_err(|_| unparseable())?
        {
            let text = text.to_string();
            return Ok(ReqBody::JsonLines { text, lines });
        }
        if !(form || typed_text || media.is_empty()) {
            return Ok(ReqBody::Opaque(raw));
        }
        // A form or text in another charset (or holding NULs, as UTF-16
        // does) cannot be filtered; an untyped body like that is binary data.
        let text = match String::from_utf8(raw.to_vec()) {
            Ok(text) if !text.contains('\0') => text,
            _ if form || typed_text => return Err(not_utf8()),
            _ => return Ok(ReqBody::Opaque(raw)),
        };
        if !form && escaped_like_json(&text) {
            return Err(unparseable());
        }
        Ok(if form {
            ReqBody::Form(text)
        } else {
            ReqBody::Text(text)
        })
    }

    /// Visit the texts; returns the rewritten body (when a text changed) and
    /// the number of unscanned parts.
    fn walk(&mut self, rules: &Rules<'_>, f: Visit<'_>) -> Result<(Option<Bytes>, u32), Refusal> {
        Ok(match self {
            ReqBody::Empty => (None, 0),
            ReqBody::Json { raw, value } => {
                let mut track = Tracking {
                    inner: f,
                    changed: false,
                };
                walk_json(value, rules, &mut track).map_err(|_| unparseable())?;
                let out = track.changed.then(|| {
                    let json = serde_json::to_vec(value).unwrap_or_default();
                    Bytes::from(preserve_numbers(raw, json))
                });
                (out, 0)
            }
            ReqBody::JsonLines { text, lines } => (
                walk_json_lines(text, lines, true, false, 0, rules, f)
                    .map_err(|_| unparseable())?
                    .map(Bytes::from),
                0,
            ),
            ReqBody::Form(text) => (
                walk_form(text, rules, f)
                    .map_err(|_| unparseable())?
                    .map(Bytes::from),
                0,
            ),
            ReqBody::Text(text) => {
                let mut t = text.clone();
                visit_body_text(&mut t, rules, f).map_err(|_| unparseable())?;
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
            ReqBody::Form(t) | ReqBody::Text(t) | ReqBody::JsonLines { text: t, .. } => {
                Bytes::from(t)
            }
        }
    }
}

fn is_json(media: &str) -> bool {
    media == "application/json" || media == "text/json" || media.ends_with("+json")
}

/// A JSON object or array, if `raw` is one (after a BOM and whitespace).
/// JSON that names a key twice is refused.
fn json_container(raw: &[u8]) -> Result<Option<Value>, Refusal> {
    let start = raw
        .strip_prefix(b"\xEF\xBB\xBF")
        .unwrap_or(raw)
        .iter()
        .find(|b| !b.is_ascii_whitespace());
    if !matches!(start, Some(b'{' | b'[')) {
        return Ok(None);
    }
    match body::parse_json_unique(raw) {
        Ok(v) => Ok(Some(v)),
        Err(body::JsonError::Invalid) => Ok(None),
        Err(body::JsonError::DuplicateKey) => Err(unparseable()),
    }
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
    fn hosts(&self) -> Option<HostList> {
        Some(self.settings().hosts.clone())
    }

    fn request(
        &self,
        host: &str,
        path: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<Bytes, Refusal> {
        self.rewrite(host, path, headers, body).map(|o| o.body)
    }

    /// Answers are restored only where they are the user's own (see
    /// `sites::restore_rule`): on chatgpt.com, claude.ai and Gemini the
    /// allowlisted send (POST) and history (GET) endpoints; on any other
    /// listed host streamed answers to POST requests. Everything else
    /// passes through with its tags, so a page someone else wrote never
    /// gets the viewer's values.
    fn response_stream(
        &self,
        method: &http::Method,
        host: &str,
        path: &str,
        content_type: &str,
    ) -> Box<dyn StreamTransform> {
        let rule = sites::restore_rule(host, method, path);
        let scope = || self.settings().scope_for(host);
        match rule {
            sites::Restore::Never => crate::restore::passthrough(),
            sites::Restore::Answer => {
                crate::restore::for_content_type(&self.engine, &scope(), content_type)
            }
            sites::Restore::Streamed => {
                crate::restore::for_stream_only(&self.engine, &scope(), content_type)
            }
        }
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

    /// Final review: JSON values one per line (NDJSON: batched telemetry, a
    /// Sentry envelope through a site's tunnel) or a bare JSON string, posted
    /// as text/plain or untyped, were redacted as literal text, where a JSON
    /// escape glues its letter to the value (`\n9876543210`). Each line is
    /// read as JSON now; text that starts like JSON, holds escapes and is
    /// not JSON is refused.
    #[test]
    fn json_lines_and_json_strings_in_text_bodies_are_read_as_json() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let t = transform(&e, |_| {});
        let values = [
            ("Phone:\n9876543210", "9876543210"),
            ("Card:\t4111111111111111", "4111111111111111"),
            ("PAN:\nABCDE1234F", "ABCDE1234F"),
            ("Aadhaar:\n2345 6789 0124", "2345 6789 0124"),
            ("Mail:\nravi@example.com", "ravi@example.com"),
            ("Hi\nRavi Kumar", "Kumar"),
            ("Jos\u{e9} Ravi Kumar", "Kumar"),
        ];
        for ct in [
            "text/plain;charset=UTF-8",
            "text/plain",
            "",
            "application/x-ndjson",
        ] {
            for (v, secret) in values {
                let one = json!({"m": v}).to_string();
                for (body, lines) in [
                    (format!("{{\"t\":1}}\n{one}\n"), 2),
                    (format!("{{\"t\":1}}\r\n\r\n{one}"), 2),
                    // A bare JSON string, \u-escaped.
                    (json_ascii(&json!(v)), 1),
                ] {
                    let out = rewrite(&t, "chatgpt.com", ct, Bytes::from(body.clone()));
                    let text = String::from_utf8(out.body.to_vec()).unwrap();
                    let parsed: Vec<Value> = text
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .map(|l| serde_json::from_str(l).unwrap_or_else(|_| panic!("{ct}: {text}")))
                        .collect();
                    assert_eq!(parsed.len(), lines, "{ct}: {text}");
                    let all = parsed.iter().map(Value::to_string).collect::<String>();
                    let decoded: String = parsed
                        .iter()
                        .map(|p| p.as_str().or(p["m"].as_str()).unwrap_or("").to_string())
                        .collect();
                    assert!(
                        !decoded.contains(secret) && !all.contains(secret),
                        "{ct} {v:?}: {text}"
                    );
                    assert!(!out.counts.is_empty(), "{ct} {v:?}: {text}");
                    // Separators are kept.
                    assert_eq!(
                        text.matches('\n').count(),
                        body.matches('\n').count(),
                        "{ct}: {text:?}"
                    );
                }
            }
        }
        // Text that starts like JSON and holds JSON escapes, but is not
        // JSON: refused, never read with its escapes literally.
        for body in [
            "{\"t\":1}\n{\"m\":\"Phone:\\n9876543210\"\n",
            "[\"Phone:\\n9876543210\"",
            "\"Phone:\\n9876543210",
        ] {
            for ct in ["text/plain", ""] {
                let r = refusal(&t, ct, body.to_string());
                assert_eq!(r.status, 400, "{body}");
                assert!(r.message.starts_with("parda_unparseable_body"), "{body}");
            }
        }
        // Plain text is still text, brackets and escapes included.
        for body in [
            "[Draft] Ravi Kumar",
            "{ hi } Ravi Kumar",
            "C:\\new Ravi Kumar",
            "9876543210",
        ] {
            let out = rewrite(&t, "chatgpt.com", "text/plain", Bytes::from(body));
            let text = String::from_utf8(out.body.to_vec()).unwrap();
            assert!(
                !text.contains("Kumar") && !text.contains("9876543210"),
                "{text}"
            );
        }
        // A JSON number line is read as the text it is too.
        let out = rewrite(
            &t,
            "chatgpt.com",
            "text/plain",
            Bytes::from("{\"t\":1}\n9876543210\n"),
        );
        assert!(!String::from_utf8_lossy(&out.body).contains("9876543210"));
    }

    /// R8.1 (scan on 21de04b): the escape check read only the body's first
    /// character, so a text body whose later line starts like JSON and holds
    /// JSON escapes was redacted literally (`\n9876543210` glues the `n` to
    /// the number). Any such line in a text body is refused now, whether it
    /// parses on its own or not: the body is read literally, never with the
    /// line's escapes decoded.
    #[test]
    fn later_lines_that_look_like_escaped_json_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let t = transform(&e, |_| {});
        for body in [
            "hello there\n{\"m\":\"Phone:\\n9876543210\", bad}\n",
            "note\n  [\"Phone:\\n9876543210\"\n",
            "note\r\n\"Phone:\\n9876543210\r\n",
            "note\n{\"m\":\"Phone:\\n9876543210\"}\n",
            "a=1\n\t\"Phone:\\t9876543210\"",
        ] {
            for ct in ["text/plain", "text/plain;charset=utf-8", ""] {
                let r = refusal(&t, ct, body.to_string());
                assert_eq!(r.status, 400, "{ct} {body:?}");
                assert!(
                    r.message.starts_with("parda_unparseable_body"),
                    "{ct} {body:?}"
                );
            }
        }
        // Lines that start like JSON without a backslash, or hold one but
        // do not start like JSON, are text as before.
        for body in [
            "Hi\n[Draft] Ravi Kumar\n{ hi }",
            "Hi\nC:\\new Ravi Kumar\n\"quoted\" too",
        ] {
            let out = rewrite(&t, "chatgpt.com", "text/plain", Bytes::from(body));
            let text = String::from_utf8(out.body.to_vec()).unwrap();
            assert!(!text.contains("Kumar"), "{text}");
        }
    }

    /// R8.2 (scan on 21de04b): JSON lines in a body not declared as JSON were
    /// only walked line by line, dropping the readings a text body gets: the
    /// whole body read literally (a number in a JSON line is text to a
    /// server that reads the body as text) and decoded as a form (`+` is a
    /// space). Those readings are kept as well: a value survives none, and
    /// is counted once.
    #[test]
    fn json_lines_in_undeclared_bodies_keep_the_whole_body_readings() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let t = transform(&e, |_| {});
        for ct in ["text/plain", "", "application/x-ndjson"] {
            for (body, secret) in [
                // Literally `2345+6789+0124` is no Aadhaar number; decoded
                // as a form it is.
                ("{\"t\":1}\n{\"m\":\"id 2345+6789+0124 x\"}\n", "6789"),
                ("{\"t\":1}\n{\"m\":\"call 98765+43210 now\"}\n", "43210"),
                ("\"hi\"\n{\"note\":\"card 4111+1111+1111+1111 x\"}", "4111"),
                ("{\"t\":1}\n{\"id 2345+6789+0124\":1}\n", "6789"),
                // Numbers are text read literally.
                ("{\"t\":1}\n{\"phone\":9876543210}\n", "9876543210"),
                ("[1]\n[\"x\", 9876543210, 2.5]\n", "9876543210"),
                // Found by the JSON walk: tagged there, not again.
                ("{\"t\":1}\n{\"m\":\"Hi\\nRavi Kumar\"}\n", "Kumar"),
            ] {
                let out = rewrite(&t, "chatgpt.com", ct, Bytes::from(body));
                let text = String::from_utf8(out.body.to_vec()).unwrap();
                assert!(!text.contains(secret), "{ct}: {text}");
                assert_eq!(out.counts.values().sum::<u32>(), 1, "{ct}: {text}");
                // Each line still parses (a number became a string).
                for line in text.lines().filter(|l| !l.trim().is_empty()) {
                    serde_json::from_str::<Value>(line).unwrap_or_else(|_| panic!("{ct}: {text}"));
                }
            }
            // Nothing found in any reading: the exact bytes go on.
            let body = "{\"t\":1}\n{\"m\":\"hello there\", \"n\": 1.50e3}\n";
            let out = rewrite(&t, "chatgpt.com", ct, Bytes::from(body));
            assert_eq!(out.body, body, "{ct}");
            assert!(out.counts.is_empty(), "{ct}");
        }
    }

    /// Everything a server reads in `v`: its strings and keys, and the JSON
    /// in strings (a document, or JSON lines) decoded again, as deep as it
    /// goes.
    fn fully_decoded(v: &Value) -> String {
        match v {
            Value::String(s) => {
                let inner = match serde_json::from_str::<Value>(s.trim()) {
                    Ok(inner) => fully_decoded(&inner),
                    Err(_) => s
                        .lines()
                        .filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
                        .map(|l| fully_decoded(&l))
                        .collect::<Vec<_>>()
                        .join(" "),
                };
                format!("{s} {inner}")
            }
            Value::Array(items) => items
                .iter()
                .map(fully_decoded)
                .collect::<Vec<_>>()
                .join(" "),
            Value::Object(map) => map
                .iter()
                .map(|(k, x)| format!("{k} {}", fully_decoded(x)))
                .collect::<Vec<_>>()
                .join(" "),
            other => other.to_string(),
        }
    }

    /// Final review 3, finding 1: a lone JSON string line was read as text,
    /// never opened, so the JSON inside a double-encoded body
    /// (`JSON.stringify(JSON.stringify(obj))`) was read with its escapes
    /// taken literally (`\n9876543210`). The JSON in a lone string is read as
    /// JSON now (an object or array, JSON lines, or another string), with
    /// the readings an undeclared body gets; escaped JSON-looking text in it
    /// that is not JSON is refused.
    #[test]
    fn lone_json_strings_holding_json_are_read_as_json() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let t = transform(&e, |_| {});
        let values = [
            ("Contact:\n9876543210", "9876543210"),
            ("Card:\t4111111111111111", "4111111111111111"),
            ("Hi\nRavi Kumar", "Kumar"),
            ("PAN:\nABCDE1234F", "ABCDE1234F"),
        ];
        let twice = |v: &Value| Value::String(v.to_string()).to_string();
        for ct in [
            "text/plain;charset=UTF-8",
            "text/plain",
            "",
            "application/x-ndjson",
        ] {
            for (v, secret) in values {
                let obj = json!({"m": v});
                for body in [
                    twice(&obj),
                    json_ascii(&Value::String(obj.to_string())),
                    format!("{}\n\"x\"\n", twice(&obj)),
                    // Three times encoded.
                    Value::String(twice(&obj)).to_string(),
                    // JSON lines inside the string.
                    Value::String(format!("{{\"t\":1}}\n{obj}")).to_string(),
                ] {
                    let out = rewrite(&t, "chatgpt.com", ct, Bytes::from(body.clone()));
                    let text = String::from_utf8(out.body.to_vec()).unwrap();
                    let read: String = text
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .map(|l| {
                            let v = serde_json::from_str::<Value>(l)
                                .unwrap_or_else(|_| panic!("{ct}: {text}"));
                            fully_decoded(&v)
                        })
                        .collect();
                    assert!(
                        !read.contains(secret) && !text.contains(secret),
                        "{ct} {v:?}: {body} -> {text}"
                    );
                    assert!(!out.counts.is_empty(), "{ct} {v:?}: {text}");
                }
            }
            // A number inside a double-encoded object is text too, as in
            // JSON lines.
            let body = twice(&json!({"p": 9876543210u64}));
            let out = rewrite(&t, "chatgpt.com", ct, Bytes::from(body.clone()));
            assert!(
                !String::from_utf8_lossy(&out.body).contains("9876543210"),
                "{ct}: {body}"
            );
            // Escaped JSON-looking text in a lone string that is not JSON.
            let body = Value::String("{\"m\":\"Phone:\\n9876543210\", bad}".into()).to_string();
            let r = refusal(&t, ct, body.clone());
            assert_eq!(r.status, 400, "{ct} {body}");
            assert!(r.message.starts_with("parda_unparseable_body"), "{body}");
        }
        // Nothing found: the exact bytes go on.
        let body = twice(&json!({"m": "hello\nthere", "n": 1.50e3}));
        let out = rewrite(&t, "chatgpt.com", "text/plain", Bytes::from(body.clone()));
        assert_eq!(out.body, body);
    }

    /// `v` as JSON with every non-ASCII character `\u`-escaped.
    fn json_ascii(v: &Value) -> String {
        v.to_string()
            .chars()
            .map(|c| {
                if c.is_ascii() {
                    c.to_string()
                } else {
                    format!("\\u{:04x}", c as u32)
                }
            })
            .collect()
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

    fn body_text(out: &RequestOutcome) -> String {
        String::from_utf8(out.body.to_vec()).unwrap()
    }

    fn assert_unparseable(r: &Refusal) {
        assert_eq!(r.status, 400, "{}", r.message);
        assert!(
            r.message.starts_with("parda_unparseable_body"),
            "{}",
            r.message
        );
        assert!(!r.message.contains("Ravi") && !r.message.contains("ravi"));
    }

    /// Reviewer probes (I3): keys and value-less pieces of forms and query
    /// strings, and JSON object keys, are text like any value.
    #[test]
    fn keys_and_bare_pieces_are_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let t = transform(&engine(dir.path()), |_| {});
        let form = "application/x-www-form-urlencoded";
        let out = rewrite(&t, "chatgpt.com", form, Bytes::from("q=hi&Ravi%20Kumar"));
        assert_eq!(body_text(&out), "q=hi&%5BNAME_1%5D");
        assert_eq!(out.counts.get("Person"), Some(&1));
        let out = rewrite(&t, "chatgpt.com", form, Bytes::from("Ravi+Kumar=1&n=2"));
        assert_eq!(body_text(&out), "%5BNAME_1%5D=1&n=2");
        let out = t
            .rewrite_request(
                "chatgpt.com",
                "/search?Ravi%20Kumar",
                &HeaderMap::new(),
                Bytes::new(),
            )
            .unwrap();
        assert_eq!(out.target.as_deref(), Some("/search?%5BNAME_1%5D"));
        let out = t
            .rewrite_request(
                "chatgpt.com",
                "/s?Ravi+Kumar=x&ravi%40example.com",
                &HeaderMap::new(),
                Bytes::new(),
            )
            .unwrap();
        assert_eq!(
            out.target.as_deref(),
            Some("/s?%5BNAME_1%5D=x&%5BEMAIL_1%5D")
        );
        // JSON object keys, at any depth and inside JSON-in-strings; the
        // order of the keys is kept.
        let out = rewrite(
            &t,
            "chatgpt.com",
            "application/json",
            Bytes::from(r#"{"a":1,"Ravi Kumar":"x","m":{"ravi@example.com":[1]},"z":2}"#),
        );
        assert_eq!(
            body_text(&out),
            r#"{"a":1,"[NAME_1]":"x","m":{"[EMAIL_1]":[1]},"z":2}"#
        );
        let inner = r#"{"Ravi Kumar":0}"#;
        let out = rewrite(
            &t,
            "chatgpt.com",
            "application/json",
            json_body(&json!({ "blob": inner })),
        );
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(v["blob"], r#"{"[NAME_1]":0}"#);
        // Identifier keys and values stay byte-identical.
        let ids =
            format!(r#"{{"conversation_id":"{UUID}","parent_message_id":"client-created-root"}}"#);
        assert_eq!(
            body_text(&rewrite(
                &t,
                "chatgpt.com",
                "application/json",
                Bytes::from(ids.clone())
            )),
            ids
        );
        let plain = "f.req=x&at=AJvLN6M%3A1697000000000&flag&e=%E2%9C%93";
        assert_eq!(
            body_text(&rewrite(&t, "chatgpt.com", form, Bytes::from(plain))),
            plain
        );
    }

    /// Reviewer probes (I3, M5): a JSON object or array is walked as JSON
    /// whatever the request says its type is.
    #[test]
    fn json_bodies_are_sniffed_under_any_content_type() {
        let dir = tempfile::tempdir().unwrap();
        let t = transform(&engine(dir.path()), |_| {});
        let body =
            format!(r#"{{"prompt":"Ravi Kumar, mail ravi@example.com","id":"{UUID}","n":1.50}}"#);
        let want = body.replace(
            "Ravi Kumar, mail ravi@example.com",
            "[NAME_1], mail [EMAIL_1]",
        );
        for ct in [
            "application/x-www-form-urlencoded",
            "application/x-www-form-urlencoded; charset=UTF-8",
            "application/octet-stream",
            "application/x-json",
            "application/javascript",
            "image/png",
            "text/plain",
            "",
        ] {
            let out = rewrite(&t, "chatgpt.com", ct, Bytes::from(body.clone()));
            assert_eq!(body_text(&out), want, "{ct}");
            assert_eq!(out.unscanned, 0, "{ct}");
        }
        let arr = "\u{feff}[\"Ravi Kumar\"]";
        let out = rewrite(
            &t,
            "chatgpt.com",
            "application/octet-stream",
            Bytes::from(arr),
        );
        assert_eq!(body_text(&out), "[\"[NAME_1]\"]");
        // Anything else of an opaque type is still forwarded unscanned.
        let out = rewrite(
            &t,
            "chatgpt.com",
            "application/octet-stream",
            Bytes::from("{x"),
        );
        assert_eq!((body_text(&out).as_str(), out.unscanned), ("{x", 1));
    }

    /// Reviewer probes (I3, M4): a form or text body that is not UTF-8
    /// cannot be filtered, so it is refused.
    #[test]
    fn non_utf8_form_and_text_bodies_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let t = transform(&engine(dir.path()), |_| {});
        for (ct, body) in [
            (
                "application/x-www-form-urlencoded",
                &b"q=Ravi+Kumar&x=\xff"[..],
            ),
            ("text/plain; charset=iso-8859-1", b"Ravi Kumar caf\xe9"),
            ("text/plain", b"Ravi Kumar \xc3"),
        ] {
            let r = refusal(&t, ct, Bytes::copy_from_slice(body));
            assert_eq!(r.status, 400, "{ct}: {}", r.message);
            assert!(r.message.starts_with("parda_not_utf8"), "{}", r.message);
            assert!(!r.message.contains("Ravi"));
        }
        // An untyped binary body is not text: forwarded, counted unscanned.
        let out = rewrite(&t, "chatgpt.com", "", Bytes::from_static(b"\x89PNG\xff"));
        assert_eq!(out.unscanned, 1);
    }

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// Review finding (fix round 1b): a declared charset other than UTF-8
    /// (UTF-16 of ASCII text is valid UTF-8, NULs interleaved) is refused
    /// for text, form and JSON bodies; text and form bodies holding NUL
    /// bytes are too; a multipart field in another charset or holding NULs
    /// is counted unscanned; an untyped body with NULs is binary.
    #[test]
    fn declared_charsets_other_than_utf8_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let t = transform(&engine(dir.path()), |_| {});
        let text = utf16le("hello Ravi Kumar, mail ravi@example.com");
        let form = utf16le("q=Ravi+Kumar&m=ravi%40example.com");
        for (ct, body) in [
            ("text/plain; charset=utf-16le", &text),
            ("text/plain;charset=\"UTF-16\"", &text),
            ("application/x-www-form-urlencoded; charset=utf-16le", &form),
            (
                "application/json; charset=utf-16",
                &utf16le("{\"a\":\"Ravi Kumar\"}"),
            ),
            ("text/plain", &text),
            ("application/x-www-form-urlencoded", &form),
            ("text/plain; charset=iso-8859-1", &b"Ravi Kumar".to_vec()),
        ] {
            let r = refusal(&t, ct, Bytes::copy_from_slice(body));
            assert_eq!(r.status, 400, "{ct}: {}", r.message);
            assert!(
                r.message.starts_with("parda_not_utf8"),
                "{ct}: {}",
                r.message
            );
        }
        // UTF-8 and US-ASCII are text.
        for ct in ["text/plain; charset=UTF-8", "text/plain; charset=us-ascii"] {
            let out = rewrite(&t, "chatgpt.com", ct, Bytes::from_static(b"hi Ravi Kumar"));
            assert_eq!(out.counts.get("Person"), Some(&1), "{ct}");
        }
        // Untyped, with NULs: binary, forwarded and counted unscanned.
        let out = rewrite(&t, "chatgpt.com", "", Bytes::from(text.clone()));
        assert_eq!((out.unscanned, out.body.as_ref()), (1, text.as_slice()));
        // Multipart text fields in UTF-16 (declared or not) are unscanned.
        for part_ct in ["text/plain; charset=utf-16le", "text/plain"] {
            let mut mp = format!(
                "--BB\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\
                 Content-Type: {part_ct}\r\n\r\n"
            )
            .into_bytes();
            mp.extend(utf16le("Ravi Kumar ravi@example.com"));
            mp.extend_from_slice(b"\r\n--BB--\r\n");
            let out = rewrite(
                &t,
                "chatgpt.com",
                "multipart/form-data; boundary=BB",
                Bytes::from(mp.clone()),
            );
            assert_eq!(
                (out.unscanned, out.body.as_ref()),
                (1, mp.as_slice()),
                "{part_ct}"
            );
        }
    }

    /// Reviewer probe (M1): serde keeps the last of two equal keys, so the
    /// first would go out unvisited. Such JSON is refused, also inside
    /// strings and forms.
    #[test]
    fn duplicate_json_keys_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let t = transform(&engine(dir.path()), |_| {});
        let dup = r#"{"prompt":"Ravi Kumar","prompt":"hello"}"#;
        for (ct, body) in [
            ("application/json", dup.to_string()),
            ("text/plain", dup.to_string()),
            ("application/octet-stream", dup.to_string()),
            ("application/json", r#"{"m":[{"a":1,"a":2}]}"#.to_string()),
            ("application/json", json!({ "blob": dup }).to_string()),
            (
                "application/json",
                json!([[null, json!([dup]).to_string()]]).to_string(),
            ),
            (
                "application/x-www-form-urlencoded",
                format!(
                    "f.req={}",
                    form_urlencoded::byte_serialize(json!([null, dup]).to_string().as_bytes())
                        .collect::<String>()
                ),
            ),
            (
                "application/json",
                json!({"u": format!("https://x.example/?d={}",
                    form_urlencoded::byte_serialize(dup.as_bytes()).collect::<String>())})
                .to_string(),
            ),
        ] {
            assert_unparseable(&refusal(&t, ct, Bytes::from(body)));
        }
        // Typed into a message, JSON is text: redacted as written.
        let out = rewrite(
            &t,
            "chatgpt.com",
            "application/json",
            json_body(&json!({ "prompt": dup })),
        );
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(v["prompt"], dup.replace("Ravi Kumar", "[NAME_1]"));
    }

    /// Reviewer probes (I4, M4): percent-encoding hides an e-mail from the
    /// rules, so URL queries inside bodies are decoded and redacted like
    /// the request target, and form-encoded text bodies are walked as forms.
    #[test]
    fn url_queries_and_form_encoded_text_are_decoded() {
        let dir = tempfile::tempdir().unwrap();
        let t = transform(&engine(dir.path()), |_| {});
        let out = rewrite(
            &t,
            "chatgpt.com",
            "application/json",
            Bytes::from(
                r#"{"href":"https://www.perplexity.ai/search?q=mail%20jdoe%40corp.example%20about%20it#x","id":"https://chatgpt.com/c/1?r=2"}"#,
            ),
        );
        assert_eq!(
            body_text(&out),
            r#"{"href":"https://www.perplexity.ai/search?q=mail+%5BEMAIL_1%5D+about+it#x","id":"https://chatgpt.com/c/1?r=2"}"#
        );
        // A URL inside prose, in a JSON string or a text body.
        let out = rewrite(
            &t,
            "chatgpt.com",
            "text/plain",
            Bytes::from("see https://x.example/p?n=Ravi+Kumar&m=ravi%40example.com#top now"),
        );
        assert_eq!(
            body_text(&out),
            "see https://x.example/p?n=%5BNAME_1%5D&m=%5BEMAIL_2%5D#top now"
        );
        let out = rewrite(
            &t,
            "chatgpt.com",
            "application/json",
            json_body(&json!({"prompt": "read HTTPS://x.example/?q=ravi%40example.com please"})),
        );
        let v: Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            v["prompt"],
            "read HTTPS://x.example/?q=%5BEMAIL_2%5D please"
        );
        // Form-encoded text, with or without a content type.
        for ct in ["text/plain", "text/plain;charset=UTF-8", ""] {
            let out = rewrite(
                &t,
                "chatgpt.com",
                ct,
                Bytes::from("prompt=Ravi+Kumar&mail=ravi%40example.com"),
            );
            assert_eq!(
                body_text(&out),
                "prompt=%5BNAME_1%5D&mail=%5BEMAIL_2%5D",
                "{ct}"
            );
            let out = rewrite(&t, "chatgpt.com", ct, Bytes::from("ravi%40example.com"));
            assert_eq!(body_text(&out), "%5BEMAIL_2%5D", "{ct}");
        }
        // Prose stays prose.
        let out = rewrite(
            &t,
            "chatgpt.com",
            "text/plain",
            Bytes::from("1+1=2, Ravi Kumar"),
        );
        assert_eq!(body_text(&out), "1+1=2, [NAME_1]");
    }

    /// `s` read literally and read as form/URL-encoded (`+` a space, `%XX`
    /// a byte): a value must survive in neither.
    fn readings(s: &str) -> [String; 2] {
        let spaced = s.replace('+', " ");
        let decoded = percent_encoding::percent_decode_str(&spaced)
            .decode_utf8_lossy()
            .into_owned();
        [s.to_string(), decoded]
    }

    #[track_caller]
    fn assert_gone(sent: &str, out: &str, values: &[&str]) {
        for reading in readings(out) {
            for v in values {
                assert!(
                    !reading.contains(v),
                    "{sent:?} -> {out:?}: {v:?} survives in {reading:?}"
                );
            }
        }
    }

    /// Scan R5.2: percent-encoding anywhere in a URL hides an e-mail or a
    /// name from the rules: fragments, path segments, relative and
    /// scheme-relative URLs and bare query strings are decoded too.
    #[test]
    fn url_fragments_paths_and_relative_urls_are_decoded() {
        let dir = tempfile::tempdir().unwrap();
        let t = transform(&engine(dir.path()), |_| {});
        for url in [
            "https://www.perplexity.ai/search#q=jdoe%40corp.example",
            "https://www.perplexity.ai/search#jdoe%40corp.example",
            "https://x.example/u/jdoe%40corp.example/",
            "https://x.example/u/jdoe%40corp.example/?n=1#top",
            "/search?q=mail%20jdoe%40corp.example",
            "//x.example/?q=mail%20jdoe%40corp.example",
            "?q=mail%20jdoe%40corp.example",
            "email=jdoe%40corp.example&n=1",
            "see /u/jdoe%40corp.example/ today",
        ] {
            let body = json!({ "href": url }).to_string();
            let out = rewrite(&t, "chatgpt.com", "application/json", Bytes::from(body));
            let v: Value = serde_json::from_slice(&out.body).unwrap();
            let href = v["href"].as_str().unwrap();
            assert_gone(url, href, &["jdoe", "corp.example"]);
            assert_eq!(out.counts.get("Email"), Some(&1), "{url} -> {href}");
        }
        for url in [
            "https://www.perplexity.ai/search#q=Ravi%20Kumar",
            "https://www.perplexity.ai/search#Ravi%20Kumar",
            "https://x.example/u/Ravi%20Kumar/",
            "/u/Ravi+Kumar?x=1",
        ] {
            let body = json!({ "href": url }).to_string();
            let out = rewrite(&t, "chatgpt.com", "application/json", Bytes::from(body));
            let v: Value = serde_json::from_slice(&out.body).unwrap();
            let href = v["href"].as_str().unwrap();
            assert_gone(url, href, &["Ravi", "Kumar"]);
            assert_eq!(out.counts.get("Person"), Some(&1), "{url} -> {href}");
        }
        // Re-encoded where it changed; untouched URLs keep their bytes.
        let out = rewrite(
            &t,
            "chatgpt.com",
            "application/json",
            Bytes::from(
                r#"{"a":"https://x.example/u/ravi%40example.com/","b":"https://x.example/a%20b/#c%20d"}"#,
            ),
        );
        assert_eq!(
            body_text(&out),
            r#"{"a":"https://x.example/u/%5BEMAIL_2%5D/","b":"https://x.example/a%20b/#c%20d"}"#
        );
    }

    /// Scan R5.3 and the form-sniff finding: a body not declared as a form
    /// is read literally by some servers and decoded by others, so both
    /// readings are redacted, whatever else the text holds (a trailing
    /// newline, brackets, non-ASCII).
    #[test]
    fn text_bodies_are_redacted_in_both_readings() {
        let dir = tempfile::tempdir().unwrap();
        let t = transform(&engine(dir.path()), |_| {});
        let name = ["Ravi", "Kumar"];
        let mail = ["jdoe", "corp.example"];
        for (body, values) in [
            ("a=Ravi+Kumar", &name[..]),
            ("a=b Ravi Kumar", &name),
            ("x%20Ravi%20Kumar", &name),
            ("prompt=Ravi%20Kumar&n=1\n", &name),
            ("prompt=Ravi%20Kumar&tags[]=x", &name),
            ("x.y+tag@corp.example", &["x.y", "tag@", "corp.example"]),
            ("jdoe.smith+work@corp.example", &mail),
            ("prompt=hi&mail=jdoe%40corp.example\n", &mail),
            ("prompt=hi&mail=jdoe%40corp.example\r\n", &mail),
            ("prompt=hi&mail=jdoe%40corp.example&tags[]=x", &mail),
            ("prompt=café&mail=jdoe%40corp.example", &mail),
            ("{x}&m=jdoe%40corp.example", &mail),
        ] {
            for ct in ["text/plain", "text/plain;charset=UTF-8", ""] {
                let out = rewrite(&t, "chatgpt.com", ct, Bytes::from(body));
                let text = body_text(&out);
                assert_gone(body, &text, values);
                assert_eq!(out.unscanned, 0, "{ct} {body:?}");
                assert_eq!(
                    out.counts.values().sum::<u32>(),
                    1,
                    "{ct} {body:?} -> {text:?}"
                );
            }
        }
        // Multipart text fields are bodies of their own.
        let mp = "--b\r\nContent-Disposition: form-data; name=\"payload\"\r\n\r\n\
                  m=jdoe%40corp.example&n=Ravi+Kumar\r\n--b--\r\n";
        let out = rewrite(
            &t,
            "chatgpt.com",
            "multipart/form-data; boundary=b",
            Bytes::from(mp),
        );
        let text = body_text(&out);
        assert_gone(mp, &text, &["jdoe", "Ravi", "Kumar"]);
        // A name only the model knows, under form keys that would skip it
        // in a declared form, is found in a text body.
        let dir = tempfile::tempdir().unwrap();
        let (_ml, t) = with_names(dir.path());
        for body in ["id=Priya", "token=Priya&q=hi", "x%20Priya"] {
            for ct in ["text/plain", ""] {
                let out = rewrite(&t, "chatgpt.com", ct, Bytes::from(body));
                assert_gone(body, &body_text(&out), &["Priya"]);
            }
        }
    }

    /// Restore `body` as the answer of `host`.
    fn answer(t: &EngineTransform, host: &str, body: &str) -> String {
        let path = if host.ends_with("claude.ai") {
            "/api/organizations/o1/chat_conversations/c1/completion"
        } else {
            "/backend-api/conversation"
        };
        let mut r = t.response_stream(&http::Method::POST, host, path, "text/plain");
        let mut out = r.push(body.as_bytes()).to_vec();
        out.extend_from_slice(&r.finish());
        String::from_utf8(out).unwrap()
    }

    /// Is a `[NAME_1]` in an answer of `content_type` to `method host path`
    /// restored? (One scope for every site, so only the endpoint rule
    /// decides.)
    fn restored(
        t: &EngineTransform,
        method: &http::Method,
        host: &str,
        path: &str,
        content_type: &str,
    ) -> bool {
        let body = match content_type {
            "text/event-stream" => "data: {\"t\":\"hi [NAME_1]\"}\n\n",
            "application/x-ndjson" | "application/json; lines" => {
                "{\"t\":\"a [NAME_1]\"}\n{\"t\":\"b\"}\n"
            }
            "application/json" => "{\"t\":\"hi [NAME_1]\"}",
            _ => "hi [NAME_1]",
        };
        let ct = content_type.trim_end_matches("; lines");
        let mut r = t.response_stream(method, host, path, ct);
        let mut out = Vec::new();
        for b in body.as_bytes().chunks(5) {
            out.extend_from_slice(&r.push(b));
        }
        out.extend_from_slice(&r.finish());
        let out = String::from_utf8(out).unwrap();
        if out.contains("Ravi Kumar") {
            return true;
        }
        assert_eq!(out, body, "{method} {host}{path} {content_type}");
        false
    }

    fn global(dir: &std::path::Path) -> EngineTransform {
        let e = engine(dir);
        assert_eq!(e.redact("Ravi Kumar", "global").unwrap().text, "[NAME_1]");
        transform(&e, |c| c.scope = "global".into())
    }

    const ALL_TYPES: [&str; 5] = [
        "text/event-stream",
        "application/x-ndjson",
        "application/json; lines",
        "application/json",
        "text/plain",
    ];

    #[test]
    fn known_sites_restore_only_their_send_and_history_endpoints() {
        use http::Method;
        let dir = tempfile::tempdir().unwrap();
        let t = global(dir.path());
        let sends = [
            ("chatgpt.com", "/backend-api/conversation"),
            ("chatgpt.com", "/backend-api/f/conversation"),
            ("chat.openai.com", "/backend-api/conversation"),
            ("chatgpt.com", "/Backend-API/Conversation"),
            ("chatgpt.com", "/backend-api/conversation?x=1"),
            (
                "claude.ai",
                "/api/organizations/o1/chat_conversations/c1/completion",
            ),
            (
                "claude.ai",
                "/api/organizations/o1/chat_conversations/c1/retry_completion",
            ),
            (
                "gemini.google.com",
                "/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate",
            ),
        ];
        let history = [
            ("chatgpt.com", "/backend-api/conversation/6f1c2a9e"),
            ("chatgpt.com", "/backend-api/conversations"),
            ("claude.ai", "/api/organizations/o1/chat_conversations"),
            ("claude.ai", "/api/organizations/o1/chat_conversations/c1"),
        ];
        for ct in ALL_TYPES {
            for (host, path) in sends {
                assert!(
                    restored(&t, &Method::POST, host, path, ct),
                    "{host}{path} {ct}"
                );
                assert!(
                    !restored(&t, &Method::GET, host, path, ct),
                    "{host}{path} {ct}"
                );
            }
            for (host, path) in history {
                assert!(
                    restored(&t, &Method::GET, host, path, ct),
                    "{host}{path} {ct}"
                );
                assert!(
                    !restored(&t, &Method::POST, host, path, ct),
                    "{host}{path} {ct}"
                );
                assert!(
                    !restored(&t, &Method::PUT, host, path, ct),
                    "{host}{path} {ct}"
                );
                assert!(
                    !restored(&t, &Method::PATCH, host, path, ct),
                    "{host}{path} {ct}"
                );
            }
            // Shared pages, GPTs, snapshots, Gemini's batchexecute, any
            // other endpoint of these sites: tags stay, whatever the
            // method or format.
            for (host, path) in [
                ("chatgpt.com", "/backend-api/share/x"),
                ("chatgpt.com", "/backend-api/gizmos/x"),
                ("chatgpt.com", "/backend-api/conversation/a/b"),
                ("chatgpt.com", "/echo"),
                ("claude.ai", "/api/chat_snapshots/s1"),
                ("claude.ai", "/api/organizations/o1/chat_conversations/c1/x"),
                ("gemini.google.com", "/_/BardChatUi/data/batchexecute"),
            ] {
                for m in [Method::GET, Method::POST] {
                    assert!(!restored(&t, &m, host, path, ct), "{m} {host}{path} {ct}");
                }
            }
        }
    }

    #[test]
    fn path_tricks_never_reach_an_allowlisted_endpoint() {
        use http::Method;
        let dir = tempfile::tempdir().unwrap();
        let t = global(dir.path());
        let ct = "application/json";
        for (m, path) in [
            (Method::GET, "/backend-api/conversation/.."),
            (Method::GET, "/backend-api/conversation/%2e%2e"),
            (Method::GET, "/backend-api/conversation/%2E%2E"),
            (Method::GET, "/backend-api/conversation/."),
            (Method::GET, "/backend-api/conversation/%2e"),
            (Method::GET, "//backend-api/conversation/x"),
            (Method::GET, "/backend-api//conversation/x"),
            (Method::GET, "/backend-api/conversation/x/"),
            (Method::GET, "/backend-api/conversation/%252e%252e"),
            (Method::GET, "/backend-api/conversation/%zz"),
            (Method::GET, "/backend-api/conversation/a%2F..%2Fshare"),
            (Method::GET, "/backend-api/conversation/x;.."),
            (Method::GET, "/backend-api/conversation/x\\..\\..\\share"),
            (Method::GET, "backend-api/conversation/x"),
            (Method::POST, "/backend-api/conversation/.."),
            (Method::POST, "/backend-api/conversation/x/.."),
            (Method::POST, "/backend-api/share/../conversation"),
            (Method::POST, "/backend-api/share/%2e%2e/conversation"),
            (Method::POST, "//backend-api/conversation"),
            (Method::POST, "/backend-api/conversation/"),
        ] {
            assert!(!restored(&t, &m, "chatgpt.com", path, ct), "{m} {path}");
        }
        // Percent-encoded literals are decoded once and still match.
        assert!(restored(
            &t,
            &Method::POST,
            "chatgpt.com",
            "/backend-api/%63onversation",
            ct
        ));
    }

    #[test]
    fn other_sites_restore_only_streamed_answers_to_posts() {
        use http::Method;
        let dir = tempfile::tempdir().unwrap();
        let t = global(dir.path());
        for host in [
            "chat.deepseek.com",
            "meta.ai",
            "perplexity.ai",
            "example.com",
        ] {
            for path in ["/api/v0/chat/completion", "/api/graphql/", "/"] {
                // Streamed answers to the user's sends.
                for ct in ["text/event-stream", "application/x-ndjson"] {
                    assert!(
                        restored(&t, &Method::POST, host, path, ct),
                        "{host}{path} {ct}"
                    );
                    assert!(
                        !restored(&t, &Method::GET, host, path, ct),
                        "{host}{path} {ct}"
                    );
                    assert!(
                        !restored(&t, &Method::PUT, host, path, ct),
                        "{host}{path} {ct}"
                    );
                }
                // A single document (a GraphQL answer, a page) never, nor
                // JSON values one per line under a JSON type.
                for ct in ["application/json", "application/json; lines", "text/plain"] {
                    for m in [Method::POST, Method::GET] {
                        assert!(!restored(&t, &m, host, path, ct), "{m} {host}{path} {ct}");
                    }
                }
            }
        }
        // Google-framed JSON on another site is a document too.
        let mut r = t.response_stream(&Method::POST, "meta.ai", "/x", "application/json");
        let framed = ")]}'\n\n23\n[[\"a\",\"hi [NAME_1]\"]]\n";
        let mut out = r.push(framed.as_bytes()).to_vec();
        out.extend_from_slice(&r.finish());
        assert_eq!(out, framed.as_bytes());
    }

    /// Review F2: on a site restored only where it streams, a JSON
    /// document followed by another line (meta.ai's GraphQL answers end in
    /// `{"extensions":{"is_final":true}}`) was read as a stream of JSON
    /// values and restored. Only event streams and NDJSON types stream
    /// there; JSON values one per line stay a stream on a known site's own
    /// endpoints.
    #[test]
    fn json_documents_with_trailing_lines_are_not_streams_on_other_sites() {
        use http::Method;
        let dir = tempfile::tempdir().unwrap();
        let t = global(dir.path());
        let run = |host: &str, path: &str, ct: &str, body: &str| {
            let mut r = t.response_stream(&Method::POST, host, path, ct);
            let mut out = Vec::new();
            for b in body.as_bytes().chunks(9) {
                out.extend_from_slice(&r.push(b));
            }
            out.extend_from_slice(&r.finish());
            String::from_utf8(out).unwrap()
        };
        let doc = json!({"data": {"bot": {"description": "Public bot: hi [NAME_1]"}}}).to_string();
        let fin = "{\"extensions\":{\"is_final\":true}}";
        for body in [
            doc.clone(),
            format!("{doc}\r\n{fin}"),
            format!("{doc}\n{fin}\n"),
            format!("{doc}\n{doc}\n"),
            format!("{doc}\nx"),
            format!("{doc}\n0"),
        ] {
            for host in ["meta.ai", "poe.com", "chat.deepseek.com"] {
                for ct in [
                    "application/json",
                    "application/json; charset=utf-8",
                    "text/json",
                    "application/graphql-response+json",
                    "text/plain",
                ] {
                    assert_eq!(run(host, "/api/graphql/", ct, &body), body, "{host} {ct}");
                }
            }
        }
        // The same lines as NDJSON or events do stream.
        let nd = format!("{doc}\n{fin}\n");
        assert!(
            run("meta.ai", "/api/graphql/", "application/x-ndjson", &nd).contains("Ravi Kumar")
        );
        let ev = format!("data: {doc}\n\n");
        assert!(run("meta.ai", "/api/graphql/", "text/event-stream", &ev).contains("Ravi Kumar"));
        // A known site's send endpoint still reads JSON lines as a stream.
        let out = run(
            "chatgpt.com",
            "/backend-api/conversation",
            "application/json",
            &nd,
        );
        assert!(out.contains("Ravi Kumar"), "{out}");
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

    /// Review M6: a look-alike delimiter cannot turn text into an
    /// unscanned "file", and base64 text parts are redacted.
    #[test]
    fn multipart_look_alike_delimiters_and_base64_parts_are_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let e = engine(dir.path());
        let t = transform(&e, |c| c.unscanned = UnscannedMedia::Block);
        let ct = "multipart/form-data; boundary=b0";
        let body = "--b0\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nhi\r\n\
                    --b0x\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\n\
                    I am Ravi Kumar\r\n\
                    --b0\r\nContent-Disposition: form-data; name=\"q\"\r\n\
                    Content-Transfer-Encoding: base64\r\n\r\nSSBhbSBSYXZpIEt1bWFy\r\n--b0--\r\n";
        let out = rewrite(&t, "example.com", ct, Bytes::from(body));
        assert_eq!(out.unscanned, 0);
        assert_eq!(
            out.body,
            body.replace("I am Ravi Kumar", "I am [NAME_1]")
                .replace("SSBhbSBSYXZpIEt1bWFy", "SSBhbSBbTkFNRV8xXQ==")
        );
        // A text part parda cannot decode is unscanned (refused in block mode).
        let qp = "--b0\r\nContent-Disposition: form-data; name=\"q\"\r\n\
                  Content-Transfer-Encoding: quoted-printable\r\n\r\nRavi=20Kumar\r\n--b0--\r\n";
        assert_eq!(refusal(&t, ct, qp).status, 415);
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

    /// Flags every "Priya" as a person (a name only the ML model knows) and
    /// records each text it was shown.
    pub(crate) struct NameMl(pub(crate) Mutex<Vec<String>>);

    impl MlDetector for NameMl {
        fn name(&self) -> &str {
            "names"
        }
        fn detect_batch(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<Detection>>> {
            let mut seen = self.0.lock().unwrap();
            Ok(texts
                .iter()
                .map(|t| {
                    seen.push(t.to_string());
                    t.match_indices("Priya")
                        .map(|(i, m)| Detection {
                            span: parda_core::Span::new(i, i + m.len()),
                            kind: parda_core::EntityKind::Person,
                            score: 0.99,
                            source: parda_core::Source::Ml,
                        })
                        .collect()
                })
                .collect())
        }
    }

    fn with_names(dir: &std::path::Path) -> (Arc<NameMl>, EngineTransform) {
        let ml = Arc::new(NameMl(Mutex::new(Vec::new())));
        let e = engine_with(dir, Some(ml.clone()), |c| c.detect.model = "names".into());
        (ml, transform(&e, |_| {}))
    }

    /// Scan R5.1: a key skips the name model only when a value would (it is
    /// identifier-shaped and looks like an id, or it is a known protocol
    /// key); a one-word name used as a key is found like any text.
    #[test]
    fn name_like_keys_reach_the_name_model() {
        let dir = tempfile::tempdir().unwrap();
        let (ml, t) = with_names(dir.path());
        let out = rewrite(
            &t,
            "chatgpt.com",
            "application/json",
            Bytes::from(r#"{"prompt":"hi","Priya":"x","m":{"PriyaSharma":1}}"#),
        );
        assert_eq!(
            body_text(&out),
            r#"{"prompt":"hi","[NAME_1]":"x","m":{"[NAME_1]Sharma":1}}"#
        );
        let form = "application/x-www-form-urlencoded";
        let out = rewrite(&t, "chatgpt.com", form, Bytes::from("Priya_Sharma=1&q=hi"));
        assert_eq!(body_text(&out), "%5BNAME_1%5D_Sharma=1&q=hi");
        let out = t
            .rewrite_request(
                "chatgpt.com",
                "/x?PriyaSharma=1",
                &HeaderMap::new(),
                Bytes::new(),
            )
            .unwrap();
        assert_eq!(out.target.as_deref(), Some("/x?%5BNAME_1%5DSharma=1"));
        // Known protocol keys (built-in, site and `skip_keys` lists) and
        // id-looking keys still skip only the model.
        ml.0.lock().unwrap().clear();
        let ids = format!(r#"{{"conversation_id":"{UUID}","model":"auto","{UUID}":1}}"#);
        let out = rewrite(
            &t,
            "chatgpt.com",
            "application/json",
            Bytes::from(ids.clone()),
        );
        assert_eq!(body_text(&out), ids);
        let seen = ml.0.lock().unwrap().clone();
        assert!(seen.is_empty(), "{seen:?}");
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
