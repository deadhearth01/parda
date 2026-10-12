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

use crate::error::error_response;
use crate::route::{Provider, route};
use crate::sse::{Restorers, StreamRewriter};
use crate::walk::{Visit, leaves};
use crate::{ProxyEvent, ProxyState, anthropic, guard, openai_chat, openai_responses, sse};

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
        Provider::OpenAiChat => Some(openai_chat::walk_request),
        Provider::OpenAiResponses => Some(openai_responses::walk_request),
        _ => None,
    }
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
            Provider::OpenAiChat => openai_chat::walk_response(&mut v, &mut f),
            Provider::OpenAiResponses => openai_responses::walk_response(&mut v, &mut f),
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
    let provider = route(&parts.method, parts.uri.path(), &parts.headers);
    let mut event = ProxyEvent {
        provider: provider.name(),
        path: parts.uri.path().to_string(),
        counts: BTreeMap::new(),
        ml_ms: 0,
        added_ms: 0,
        unscanned_media: 0,
        status: 0,
        streaming: false,
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

    // Redact the request.
    let mut out_body = body.clone();
    let mut redact_ms = 0;
    if let Some(walker) = request_walker(provider)
        && !body.is_empty()
        && let Ok(v) = serde_json::from_slice::<Value>(&body)
    {
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
    let pq = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let url = format!("{}{pq}", base.trim_end_matches('/'));
    let mut rb = state.http.request(parts.method.clone(), &url);
    for (k, v) in &parts.headers {
        if forward_request_header(k) {
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

    if is_sse && provider.rewrites() {
        let restorers = Restorers::new(state.engine.clone(), &scope);
        let rw: Box<dyn StreamRewriter> = match provider {
            Provider::Anthropic => Box::new(anthropic::AnthropicStream::new(restorers)),
            Provider::OpenAiChat => Box::new(openai_chat::ChatStream::new(restorers)),
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
    let body = if provider.rewrites() && !bytes.is_empty() {
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
