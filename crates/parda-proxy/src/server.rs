//! The request handler: guard → route → redact → forward → restore.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use bytes::Bytes;
use http::header::{self, HeaderName};
use http::{HeaderMap, StatusCode};
use parda_core::UnscannedMedia;
use parda_engine::{Engine, EngineError};
use serde_json::Value;

use crate::body::{self, BodyError};
use crate::error::error_response;
use crate::route::{Provider, route};
use crate::route::{SUPPORTED, normalize_path};
use crate::sse::{Restorers, StreamRewriter};
use crate::walk::{Visit, leaves};
use crate::{ProxyEvent, ProxyState, anthropic, guard, legacy, openai_chat, openai_responses, sse};

/// Header naming the vault scope of a request (default `global`).
pub const SCOPE_HEADER: &str = "x-parda-scope";

pub fn router(state: Arc<ProxyState>) -> Router {
    Router::new().fallback(handle).with_state(state)
}

/// Serve until the listener fails.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<ProxyState>,
) -> anyhow::Result<()> {
    axum::serve(listener, router(state)).await?;
    Ok(())
}

/// Serve until `shutdown` completes, then finish in-flight requests.
pub async fn serve_with_shutdown(
    listener: tokio::net::TcpListener,
    state: Arc<ProxyState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

type Walker = fn(&mut Value, Visit<'_>) -> u32;

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
        .unwrap_or("global")
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
    unscanned: u32,
    paused: bool,
}

fn redact_body(
    engine: &Engine,
    walker: Walker,
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
    Ok(Redacted {
        body,
        counts,
        ml_ms,
        unscanned,
        paused,
    })
}

fn restore_body(
    engine: &Engine,
    provider: Provider,
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
    serde_json::to_vec(&v).unwrap_or_default()
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
        streaming = event.streaming,
        "proxied request"
    );
    let _ = state.events.send(event);
    resp
}

async fn handle(State(state): State<Arc<ProxyState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
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
        status: 0,
        streaming: false,
        paused: false,
        error: None,
    };

    if let Err(msg) = guard::check(&parts.headers, &state.cfg) {
        let resp = error_response(provider, StatusCode::FORBIDDEN, "parda_forbidden", msg);
        return finish(&state, event, resp, Some("parda_forbidden".into()));
    }
    let scope = scope_of(&parts.headers);
    let body = match axum::body::to_bytes(body, state.cfg.max_body_bytes).await {
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
    if !provider.rewrites()
        && !body.is_empty()
        && !carries_no_text(&parts.headers, &body, state.cfg.max_body_bytes)
    {
        let resp = error_response(
            provider,
            StatusCode::BAD_REQUEST,
            "parda_unknown_endpoint",
            &format!(
                "parda does not know which fields of {} {path} carry text, so it cannot redact \
                 them; the request was not sent. Endpoints parda redacts: {SUPPORTED}",
                parts.method
            ),
        );
        return finish(&state, event, resp, Some("parda_unknown_endpoint".into()));
    }

    // Redact the request. A body parda cannot read is refused, never
    // forwarded as is.
    let mut out_body = body.clone();
    let mut redact_ms = 0;
    let mut decoded = false;
    if let Some(walker) = request_walker(provider)
        && !body.is_empty()
    {
        let v = match body::decode(&parts.headers, body, state.cfg.max_body_bytes)
            .and_then(|raw| body::parse_json(&raw))
        {
            Ok(v) => v,
            Err(e) => {
                let (resp, code) = body_error(provider, &e);
                return finish(&state, event, resp, Some(code));
            }
        };
        decoded = body::is_encoded(&parts.headers);
        let started = Instant::now();
        let engine = state.engine.clone();
        let scope2 = scope.clone();
        let res =
            tokio::task::spawn_blocking(move || redact_body(&engine, walker, v, &scope2)).await;
        redact_ms = started.elapsed().as_millis() as u64;
        match res {
            Ok(Ok(r)) => {
                event.counts = r.counts;
                event.ml_ms = r.ml_ms;
                event.unscanned_media = r.unscanned;
                event.paused = r.paused;
                event.added_ms = redact_ms;
                if r.unscanned > 0 && state.cfg.unscanned_media == UnscannedMedia::Block {
                    let resp = error_response(
                        provider,
                        StatusCode::BAD_REQUEST,
                        "parda_unscanned_media",
                        "the request contains images or binary documents, which parda cannot \
                         scan yet (proxy.unscanned_media = \"block\")",
                    );
                    return finish(&state, event, resp, Some("parda_unscanned_media".into()));
                }
                out_body = Bytes::from(r.body);
            }
            Ok(Err(e)) => {
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

    // Forward.
    let base = if provider.is_anthropic() {
        &state.cfg.anthropic_upstream
    } else {
        &state.cfg.openai_upstream
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

    if is_sse && provider.restores() {
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

    let bytes = match upstream.bytes().await {
        Ok(b) => b,
        Err(e) => {
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
    let restore = if status.is_success() {
        provider.restores()
    } else {
        provider.rewrites()
    };
    let body = if restore && !bytes.is_empty() {
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) => {
                let started = Instant::now();
                let engine = state.engine.clone();
                let scope2 = scope.clone();
                let ok = status.is_success();
                let res = tokio::task::spawn_blocking(move || {
                    restore_body(&engine, provider, v, &scope2, ok)
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
