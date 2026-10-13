//! Proxy settings apply to the running proxy; it only listens where allowed.

mod common;

use common::*;
use http::StatusCode;
use parda_core::{ProxyConfig, UnscannedMedia};
use serde_json::{Value, json};

#[tokio::test]
async fn config_changes_apply_to_the_running_proxy() {
    let s = setup(responder(|_| {
        Reply::Json(StatusCode::OK, json!({"ok": true}))
    }))
    .await;
    let req = json!({"model": "m", "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}
    ]}]});
    assert_eq!(s.post("/v1/messages", &req).await.status(), 200);

    let mut cfg: ProxyConfig = (*s.state.config()).clone();
    cfg.unscanned_media = UnscannedMedia::Block;
    cfg.allowed_origins = vec!["https://ok.example".into()];
    s.state.set_config(cfg);

    let resp = s.post("/v1/messages", &req).await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "parda_unscanned_media");
    let resp = s
        .client
        .post(s.url("/v1/messages"))
        .header("origin", "https://ok.example")
        .json(&json!({"model": "m", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn non_loopback_listen_needs_the_flag() {
    let mut cfg = ProxyConfig {
        listen: "0.0.0.0:0".into(),
        ..Default::default()
    };
    let err = parda_proxy::bind(&cfg).await.unwrap_err();
    assert!(format!("{err:#}").contains("allow_non_loopback"), "{err:#}");
    cfg.allow_non_loopback = true;
    assert!(parda_proxy::bind(&cfg).await.is_ok());
    for ok in ["127.0.0.1:0", "localhost:0", "[::1]:0"] {
        let cfg = ProxyConfig {
            listen: ok.into(),
            ..Default::default()
        };
        // IPv6 may be unavailable on CI hosts; only the policy is checked.
        if let Err(e) = parda_proxy::bind(&cfg).await {
            assert!(
                !format!("{e:#}").contains("allow_non_loopback"),
                "{ok}: {e:#}"
            );
        }
    }
}

#[tokio::test]
async fn request_without_any_host_is_refused() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let s = setup(responder(|_| {
        Reply::Json(StatusCode::OK, json!({"ok": true}))
    }))
    .await;
    // HTTP/1.0 without a Host header.
    let mut tcp = tokio::net::TcpStream::connect(s.proxy).await.unwrap();
    tcp.write_all(b"GET /v1/models HTTP/1.0\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.starts_with("HTTP/1.0 403") || text.starts_with("HTTP/1.1 403"),
        "{text}"
    );
    assert_eq!(s.mock.count(), 0);
}

fn messages(text: &str) -> Value {
    json!({"model": "m", "messages": [{"role": "user", "content": text}]})
}

#[tokio::test]
async fn distinct_scopes_are_capped_but_the_default_scope_is_never_locked_out() {
    let s = setup(responder(|_| {
        Reply::Json(StatusCode::OK, json!({"ok": true}))
    }))
    .await;
    let send = |scope: Option<String>| {
        let mut rb = s.client.post(s.url("/v1/messages"));
        if let Some(scope) = scope {
            rb = rb.header("x-parda-scope", scope);
        }
        rb.json(&messages("hi")).send()
    };
    // The default scope ("global") holds one of the slots from the start.
    for i in 0..parda_proxy::MAX_SCOPES - 1 {
        assert_eq!(send(Some(format!("s{i}"))).await.unwrap().status(), 200);
    }
    let resp = send(Some("one-too-many".into())).await.unwrap();
    assert_eq!(resp.status(), 429);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "parda_too_many_scopes");
    assert_eq!(s.mock.count(), parda_proxy::MAX_SCOPES - 1);
    // Scopes already in use keep working, and so does the default one,
    // with or without the header.
    assert_eq!(send(Some("s0".into())).await.unwrap().status(), 200);
    assert_eq!(send(None).await.unwrap().status(), 200);
    assert_eq!(send(Some("global".into())).await.unwrap().status(), 200);
}

#[tokio::test]
async fn refused_requests_do_not_use_up_scopes() {
    let s = setup(responder(|_| {
        Reply::Json(StatusCode::OK, json!({"ok": true}))
    }))
    .await;
    let n = parda_proxy::MAX_SCOPES + 20;
    for i in 0..n {
        let scope = format!("junk{i}");
        // Not JSON, not an object, a browser origin: all refused up front.
        let resp = s
            .client
            .post(s.url("/v1/messages"))
            .header("x-parda-scope", &scope)
            .body("not json")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "{scope}");
        let resp = s
            .client
            .post(s.url("/v1/chat/completions"))
            .header("x-parda-scope", &scope)
            .body("[1]")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "{scope}");
        let resp = s
            .client
            .post(s.url("/v1/messages"))
            .header("x-parda-scope", &scope)
            .header("origin", "https://evil.example")
            .json(&messages("hi"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "{scope}");
        let resp = s
            .client
            .post(s.url("/v1/messages"))
            .header("x-parda-scope", &scope)
            .send()
            .await
            .unwrap();
        // No body at all: nothing to redact, nothing to remember.
        assert_ne!(resp.status(), 429, "{scope}");
    }
    let resp = s
        .client
        .post(s.url("/v1/messages"))
        .header("x-parda-scope", "real-project")
        .json(&messages("hi"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(s.mock.count(), n + 1);
}

#[tokio::test]
async fn passthrough_responses_are_streamed_not_buffered() {
    use std::time::{Duration, Instant};
    let s = setup(responder(|_| {
        Reply::Sse(vec![
            (0, "data: first\n\n".into()),
            (600, "data: second\n\n".into()),
        ])
    }))
    .await;
    let started = Instant::now();
    let mut resp = s
        .client
        .get(s.url("/v1/files/f1/content"))
        .send()
        .await
        .unwrap();
    let first = resp.chunk().await.unwrap().unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "first bytes after {:?}",
        started.elapsed()
    );
    assert!(String::from_utf8_lossy(&first).contains("first"));
}

#[tokio::test]
async fn buffered_answers_are_capped() {
    let big = "x".repeat(8192);
    let s = setup_with(
        responder(move |_| {
            Reply::Json(
                StatusCode::OK,
                json!({"type": "message", "content": [{"type": "text", "text": big}]}),
            )
        }),
        |c| c.proxy.max_body_bytes = 4096,
        None,
    )
    .await;
    let resp = s
        .post(
            "/v1/messages",
            &json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]}),
        )
        .await;
    assert_eq!(resp.status(), 502);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "parda_upstream_too_large");
}
