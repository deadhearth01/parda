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

#[tokio::test]
async fn distinct_scopes_are_capped() {
    let s = setup(responder(|_| {
        Reply::Json(StatusCode::OK, json!({"ok": true}))
    }))
    .await;
    let send = |scope: String| {
        s.client
            .post(s.url("/v1/messages"))
            .header("x-parda-scope", scope)
            .json(&json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]}))
            .send()
    };
    for i in 0..parda_proxy::MAX_SCOPES {
        assert_eq!(send(format!("s{i}")).await.unwrap().status(), 200);
    }
    let resp = send("one-too-many".into()).await.unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "parda_too_many_scopes");
    // Scopes already in use keep working.
    assert_eq!(send("s0".into()).await.unwrap().status(), 200);
}
