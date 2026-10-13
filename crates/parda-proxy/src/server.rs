//! The request handler: guard → route → redact → forward → restore.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::response::Response;
use bytes::Bytes;
use futures::StreamExt;
use http::header::{self, HeaderName};
use http::{HeaderMap, StatusCode};
use parda_core::{ProxyConfig, UnscannedMedia};
use parda_engine::{Engine, EngineError};
use serde_json::Value;

use crate::body::{self, BodyError};
use crate::error::error_response;
use crate::route::{Provider, route};
use crate::route::{SUPPORTED, normalize_path};
use crate::sse::{Restorers, StreamRewriter};
use crate::walk::{Unscanned, Visit, leaves, preserve_numbers};
use crate::{
    DEFAULT_SCOPE, ProxyEvent, ProxyState, anthropic, guard, legacy, openai_chat, openai_responses,
    sse,
};

/// Header naming the vault scope of a request (default `global`).
pub const SCOPE_HEADER: &str = "x-parda-scope";

pub fn router(state: Arc<ProxyState>) -> Router {
    Router::new().fallback(handle).with_state(state)
}

/// Bind `cfg.listen`, refusing any non-loopback address unless
/// `proxy.allow_non_loopback` is set (the proxy holds no credentials of its
/// own: anyone who can reach it can send through it and read restored
/// answers).
pub async fn bind(cfg: &ProxyConfig) -> anyhow::Result<tokio::net::TcpListener> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&cfg.listen)
        .await
        .with_context(|| format!("resolving proxy.listen = {}", cfg.listen))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("proxy.listen = {} resolves to no address", cfg.listen);
    }
    if !cfg.allow_non_loopback
        && let Some(a) = addrs.iter().find(|a| !a.ip().to_canonical().is_loopback())
    {
        anyhow::bail!(
            "proxy.listen = {} resolves to {a}, which is not a loopback address; parda only \
             serves this machine unless proxy.allow_non_loopback = true",
            cfg.listen
        );
    }
    let mut last = None;
    for a in addrs {
        match tokio::net::TcpListener::bind(a).await {
            Ok(l) => return Ok(l),
            Err(e) => last = Some(e),
        }
    }
    Err(anyhow::Error::from(last.expect("at least one address"))
        .context(format!("binding the proxy on {}", cfg.listen)))
}

/// Serve until the listener fails.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<ProxyState>,
) -> anyhow::Result<()> {
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Serve until `shutdown` completes, then finish in-flight requests.
pub async fn serve_with_shutdown(
    listener: tokio::net::TcpListener,
    state: Arc<ProxyState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;
    Ok(())
}

type Walker = fn(&mut Value, Visit<'_>) -> Unscanned;

fn request_walker(p: Provider) -> Option<Walker> {
    match p {
        Provider::Anthropic => Some(anthropic::walk_request),
        Provider::AnthropicBatches => Some(legacy::walk_batch_request),
        Provider::AnthropicComplete => Some(legacy::walk_complete_request),
        Provider::OpenAiChat => Some(openai_chat::walk_request),
        Provider::OpenAiResponses => Some(openai_responses::walk_request),
        Provider::OpenAiCompletions => Some(legacy::walk_completions_request),
        Provider::OpenAiEmbeddings => Some(legacy::walk_embeddings_request),
        Provider::OpenAiConversations => Some(openai_responses::walk_conversation_request),
        Provider::PassAnthropic | Provider::PassOpenAi => None,
    }
}

/// True if a body sent to an endpoint parda does not know holds no text at
/// all: JSON with no strings (keys included), e.g. `{}` for a cancel call.
fn carries_no_text(headers: &HeaderMap, body: &Bytes, max: usize) -> bool {
    fn has_text(v: &Value) -> bool {
        match v {
            Value::String(_) => true,
            Value::Array(a) => a.iter().any(has_text),
            Value::Object(m) => !m.is_empty(),
            _ => false,
        }
    }
    body::decode(headers, body.clone(), max)
        .and_then(|raw| body::parse_json(&raw))
        .is_ok_and(|v| !has_text(&v))
}

fn scope_of(headers: &HeaderMap) -> String {
    headers
        .get(SCOPE_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 64
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c))
        })
        .unwrap_or(DEFAULT_SCOPE)
        .to_string()
}

fn forward_request_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "accept-encoding"
            | SCOPE_HEADER
    )
}

fn response_headers(upstream: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (k, v) in upstream {
        if !matches!(
            k.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-connection"
                | "transfer-encoding"
                | "content-length"
                | "content-encoding"
                | "trailer"
                | "upgrade"
        ) {
            out.append(k.clone(), v.clone());
        }
    }
    out
}

struct Redacted {
    body: Vec<u8>,
    counts: BTreeMap<String, u32>,
    ml_ms: u64,
    unscanned: Unscanned,
    paused: bool,
}

fn redact_body(
    engine: &Engine,
    walker: Walker,
    raw: &[u8],
    mut v: Value,
    scope: &str,
) -> Result<Redacted, EngineError> {
    let mut texts = Vec::new();
    let unscanned = walker(&mut v, &mut |s: &mut String| texts.push(s.clone()));
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let reds = engine.redact_many(&refs, scope)?;
    let mut counts = BTreeMap::new();
    let mut ml_ms = 0;
    let paused = reds.iter().any(|r| r.paused);
    for r in &reds {
        for (k, n) in r.counts() {
            *counts.entry(k).or_insert(0) += n;
        }
        ml_ms = ml_ms.max(r.ml_ms);
    }
    let mut it = reds.into_iter();
    walker(&mut v, &mut |s: &mut String| {
        if let Some(r) = it.next() {
            *s = r.text;
        }
    });
    let body = serde_json::to_vec(&v).map_err(|e| EngineError::Other(e.to_string()))?;
    let body = preserve_numbers(raw, body);
    Ok(Redacted {
        body,
        counts,
        ml_ms,
        unscanned,
        paused,
    })
}

/// Why a request body could not be turned into a redacted one.
enum PrepareError {
    Body(BodyError),
    TooManyScopes,
    Engine(EngineError),
}

/// Everything CPU-heavy that happens to a request body, for a blocking
/// thread: undo `Content-Encoding` (up to `max` bytes), parse, check it is a
/// JSON object, admit its scope (only now that it is a valid request), then
/// redact.
fn prepare_body(
    state: &ProxyState,
    walker: Walker,
    headers: &HeaderMap,
    body: Bytes,
    max: usize,
    scope: &str,
) -> Result<Redacted, PrepareError> {
    let raw = body::decode(headers, body, max).map_err(PrepareError::Body)?;
    let v = body::parse_object(&raw).map_err(PrepareError::Body)?;
    if !state.admit_scope(scope) {
        return Err(PrepareError::TooManyScopes);
    }
    redact_body(&state.engine, walker, &raw, v, scope).map_err(PrepareError::Engine)
}

fn restore_body(
    engine: &Engine,
    provider: Provider,
    raw: &[u8],
    mut v: Value,
    scope: &str,
    success: bool,
) -> Vec<u8> {
    let mut f = |s: &mut String| {
        if !s.is_empty() {
            *s = engine.restore(s, scope);
        }
    };
    if success {
        match provider {
            Provider::Anthropic => anthropic::walk_response(&mut v, &mut f),
            Provider::AnthropicComplete => legacy::walk_complete_response(&mut v, &mut f),
            Provider::OpenAiChat => openai_chat::walk_response(&mut v, &mut f),
            Provider::OpenAiResponses => openai_responses::walk_response(&mut v, &mut f),
            Provider::OpenAiCompletions => legacy::walk_completions_response(&mut v, &mut f),
            _ => {}
        }
    } else {
        // Error bodies may quote the request; restore every string.
        leaves(&mut v, &mut f);
    }
    preserve_numbers(raw, serde_json::to_vec(&v).unwrap_or_default())
}

fn engine_error(provider: Provider, e: &EngineError) -> (Response, String) {
    match e {
        EngineError::MlUnavailable(why) => (
            error_response(
                provider,
                StatusCode::SERVICE_UNAVAILABLE,
                "parda_ml_unavailable",
                &format!(
                    "parda could not run its name detector ({why}); the request was not sent. \
                     Run `parda doctor`, or set detect.mode = \"fast\" to allow rules-only redaction."
                ),
            ),
            "parda_ml_unavailable".into(),
        ),
        EngineError::Blocked(kinds) => {
            let list = kinds
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            (
                error_response(
                    provider,
                    StatusCode::BAD_REQUEST,
                    "parda_blocked",
                    &format!("the request was blocked by parda policy (contains: {list})"),
                ),
                "parda_blocked".into(),
            )
        }
        other => {
            tracing::error!(error = %other, "redaction failed");
            (
                error_response(
                    provider,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "parda_internal",
                    "parda failed to redact the request; it was not sent",
                ),
                "parda_internal".into(),
            )
        }
    }
}

enum ReadError {
    TooLarge,
    Io(reqwest::Error),
}

/// Buffer an upstream answer (to restore it), at most `cap` bytes.
async fn read_capped(upstream: reqwest::Response, cap: usize) -> Result<Bytes, ReadError> {
    if upstream.content_length().is_some_and(|n| n > cap as u64) {
        return Err(ReadError::TooLarge);
    }
    let mut stream = upstream.bytes_stream();
    let mut buf = bytes::BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(ReadError::Io)?;
        if buf.len() + chunk.len() > cap {
            return Err(ReadError::TooLarge);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}

fn body_error(provider: Provider, e: &BodyError) -> (Response, String) {
    let (status, code, message) = match e {
        BodyError::UnsupportedEncoding(coding) => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "parda_unsupported_encoding",
            format!(
                "parda cannot decode Content-Encoding `{coding}` (supported: gzip, deflate, br, \
                 zstd); the request was not sent"
            ),
        ),
        BodyError::TooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "parda_body_too_large",
            "the decoded request body exceeds proxy.max_body_bytes".to_string(),
        ),
        BodyError::Unparseable(why) => (
            StatusCode::BAD_REQUEST,
            "parda_unparseable_body",
            format!(
                "parda could not read the request body as JSON ({why}), so it could not \
                 redact it; the request was not sent"
            ),
        ),
    };
    (
        error_response(provider, status, code, &message),
        code.into(),
    )
}

fn finish(
    state: &ProxyState,
    mut event: ProxyEvent,
    resp: Response,
    error: Option<String>,
) -> Response {
    event.status = resp.status().as_u16();
    event.error = error;
    tracing::info!(
        provider = event.provider,
        path = %event.path,
        status = event.status,
        added_ms = event.added_ms,
        ml_ms = event.ml_ms,
        entities = event.counts.values().sum::<u32>(),
        unscanned = event.unscanned_media,
        unknown_parts = event.unknown_parts,
        streaming = event.streaming,
        "proxied request"
    );
    let _ = state.events.send(event);
    resp
}

async fn handle(State(state): State<Arc<ProxyState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let cfg = state.config();
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(a)| *a);
    // Route (and forward) the path the way the upstream will read it, so
    // `/v1//messages` or `/v1/%6Dessages` cannot slip past the walkers.
    let path = normalize_path(parts.uri.path());
    let provider = route(&parts.method, &path, &parts.headers);
    let mut event = ProxyEvent {
        provider: provider.name(),
        path: path.clone(),
        counts: BTreeMap::new(),
        ml_ms: 0,
        added_ms: 0,
        unscanned_media: 0,
        unknown_parts: 0,
        status: 0,
        streaming: false,
        paused: false,
        error: None,
    };

    if let Err(msg) = guard::check(&parts.headers, &parts.uri, peer, &cfg) {
        let resp = error_response(provider, StatusCode::FORBIDDEN, "parda_forbidden", msg);
        return finish(&state, event, resp, Some("parda_forbidden".into()));
    }
    let scope = scope_of(&parts.headers);
    let body = match axum::body::to_bytes(body, cfg.max_body_bytes).await {
        Ok(b) => b,
        Err(_) => {
            let resp = error_response(
                provider,
                StatusCode::PAYLOAD_TOO_LARGE,
                "parda_body_too_large",
                "request body exceeds proxy.max_body_bytes",
            );
            return finish(&state, event, resp, Some("parda_body_too_large".into()));
        }
    };

    // An endpoint parda cannot redact may only carry bodies without text.
    if !provider.rewrites() && !body.is_empty() {
        let (headers, body2, max) = (parts.headers.clone(), body.clone(), cfg.max_body_bytes);
        let no_text = tokio::task::spawn_blocking(move || carries_no_text(&headers, &body2, max))
            .await
            .unwrap_or(false);
        if !no_text {
            let resp = error_response(
                provider,
                StatusCode::BAD_REQUEST,
                "parda_unknown_endpoint",
                &format!(
                    "parda does not know which fields of {} {path} carry text, so it cannot \
                     redact them; the request was not sent. Endpoints parda redacts: {SUPPORTED}",
                    parts.method
                ),
            );
            return finish(&state, event, resp, Some("parda_unknown_endpoint".into()));
        }
    }

    // Redact the request. A body parda cannot read is refused, never
    // forwarded as is. Decoding, parsing and redacting all happen on a
    // blocking thread: a 64 MiB inflate must not stall the async workers.
    let mut out_body = body.clone();
    let mut redact_ms = 0;
    let mut decoded = false;
    let had_body = !body.is_empty();
    if let Some(walker) = request_walker(provider)
        && had_body
    {
        let started = Instant::now();
        let st = state.clone();
        let headers = parts.headers.clone();
        let (max, scope2) = (cfg.max_body_bytes, scope.clone());
        let res = tokio::task::spawn_blocking(move || {
            prepare_body(&st, walker, &headers, body, max, &scope2)
        })
        .await;
        redact_ms = started.elapsed().as_millis() as u64;
        match res {
            Ok(Ok(r)) => {
                decoded = body::is_encoded(&parts.headers);
                event.counts = r.counts;
                event.ml_ms = r.ml_ms;
                event.unscanned_media = r.unscanned.media;
                event.unknown_parts = r.unscanned.unknown;
                event.paused = r.paused;
                event.added_ms = redact_ms;
                if r.unscanned.total() > 0 && cfg.unscanned_media == UnscannedMedia::Block {
                    let resp = error_response(
                        provider,
                        StatusCode::BAD_REQUEST,
                        "parda_unscanned_media",
                        "the request contains images, binary documents, token ids or content \
                         of a type parda does not know, which it cannot scan \
                         (proxy.unscanned_media = \"block\")",
                    );
                    return finish(&state, event, resp, Some("parda_unscanned_media".into()));
                }
                out_body = Bytes::from(r.body);
            }
            Ok(Err(PrepareError::Body(e))) => {
                let (resp, code) = body_error(provider, &e);
                return finish(&state, event, resp, Some(code));
            }
            Ok(Err(PrepareError::TooManyScopes)) => {
                let resp = error_response(
                    provider,
                    StatusCode::TOO_MANY_REQUESTS,
                    "parda_too_many_scopes",
                    &format!(
                        "this proxy already serves {} vault scopes (x-parda-scope), so the \
                         scope `{scope}` was not added and the request was not sent; use one \
                         of the existing scopes or restart the daemon to reset them",
                        crate::MAX_SCOPES
                    ),
                );
                return finish(&state, event, resp, Some("parda_too_many_scopes".into()));
            }
            Ok(Err(PrepareError::Engine(e))) => {
                let (resp, code) = engine_error(provider, &e);
                return finish(&state, event, resp, Some(code));
            }
            Err(_) => {
                let resp = error_response(
                    provider,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "parda_internal",
                    "parda failed to redact the request; it was not sent",
                );
                return finish(&state, event, resp, Some("parda_internal".into()));
            }
        }
    }
    // A request with no body used no scope (none was admitted for it), so
    // there is nothing of that scope to restore in the answer.
    let scope_usable = had_body || state.scope_known(&scope);

    // Forward.
    let base = if provider.is_anthropic() {
        &cfg.anthropic_upstream
    } else {
        &cfg.openai_upstream
    };
    let url = match parts.uri.query() {
        Some(q) => format!("{}{path}?{q}", base.trim_end_matches('/')),
        None => format!("{}{path}", base.trim_end_matches('/')),
    };
    let mut rb = state.http.request(parts.method.clone(), &url);
    for (k, v) in &parts.headers {
        if forward_request_header(k) && !(decoded && k == header::CONTENT_ENCODING) {
            rb = rb.header(k, v);
        }
    }
    let rb = rb
        .header(header::ACCEPT_ENCODING, "identity")
        .body(out_body);
    let upstream = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "upstream request failed");
            let resp = error_response(
                provider,
                StatusCode::BAD_GATEWAY,
                "parda_upstream_unreachable",
                "parda could not reach the upstream API",
            );
            return finish(
                &state,
                event,
                resp,
                Some("parda_upstream_unreachable".into()),
            );
        }
    };
    let status = upstream.status();
    let headers = response_headers(upstream.headers());
    let is_sse = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| c.starts_with("text/event-stream"));

    if is_sse && provider.restores() && scope_usable {
        let restorers = Restorers::new(state.engine.clone(), &scope);
        let rw: Box<dyn StreamRewriter> = match provider {
            Provider::Anthropic => Box::new(anthropic::AnthropicStream::new(restorers)),
            Provider::AnthropicComplete => Box::new(legacy::CompleteStream::new(restorers)),
            Provider::OpenAiChat => Box::new(openai_chat::ChatStream::new(restorers)),
            Provider::OpenAiCompletions => Box::new(legacy::CompletionsStream::new(restorers)),
            _ => Box::new(openai_responses::ResponsesStream::new(restorers)),
        };
        let (tx, rx) = futures::channel::mpsc::channel(32);
        tokio::spawn(sse::pump(upstream, rw, tx));
        event.streaming = true;
        let mut resp = Response::new(Body::from_stream(rx));
        *resp.status_mut() = status;
        *resp.headers_mut() = headers;
        return finish(&state, event, resp, None);
    }

    let restore = scope_usable
        && if status.is_success() {
            provider.restores()
        } else {
            provider.rewrites()
        };
    if !restore {
        // Nothing to restore: pass the body through as it arrives.
        event.added_ms = redact_ms;
        let mut resp = Response::new(Body::from_stream(upstream.bytes_stream()));
        *resp.status_mut() = status;
        *resp.headers_mut() = headers;
        return finish(&state, event, resp, None);
    }
    let bytes = match read_capped(upstream, cfg.max_body_bytes).await {
        Ok(b) => b,
        Err(ReadError::TooLarge) => {
            let resp = error_response(
                provider,
                StatusCode::BAD_GATEWAY,
                "parda_upstream_too_large",
                "the upstream answer exceeds proxy.max_body_bytes, so parda could not \
                 restore it",
            );
            return finish(&state, event, resp, Some("parda_upstream_too_large".into()));
        }
        Err(ReadError::Io(e)) => {
            tracing::warn!(error = %e, "reading upstream body failed");
            let resp = error_response(
                provider,
                StatusCode::BAD_GATEWAY,
                "parda_upstream_error",
                "the upstream response could not be read",
            );
            return finish(&state, event, resp, Some("parda_upstream_error".into()));
        }
    };
    let mut restore_ms = 0;
    let body = if restore && !bytes.is_empty() {
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) => {
                let started = Instant::now();
                let engine = state.engine.clone();
                let scope2 = scope.clone();
                let ok = status.is_success();
                let raw = bytes.clone();
                let res = tokio::task::spawn_blocking(move || {
                    restore_body(&engine, provider, &raw, v, &scope2, ok)
                })
                .await;
                restore_ms = started.elapsed().as_millis() as u64;
                res.map(Bytes::from).unwrap_or(bytes)
            }
            Err(_) => bytes,
        }
    } else {
        bytes
    };
    event.added_ms = redact_ms + restore_ms;
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    finish(&state, event, resp, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_header_validation() {
        let mut h = HeaderMap::new();
        assert_eq!(scope_of(&h), "global");
        h.insert(SCOPE_HEADER, "project-a".parse().unwrap());
        assert_eq!(scope_of(&h), "project-a");
        h.insert(SCOPE_HEADER, "bad scope!".parse().unwrap());
        assert_eq!(scope_of(&h), "global");
    }
}
