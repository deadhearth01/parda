mod common;

use std::sync::Arc;

use common::*;
use http::StatusCode;
use parda_core::{MlDetector, Mode, UnscannedMedia};
use serde_json::{Value, json};

fn echo_first_user_text() -> Responder {
    responder(|seen| {
        let v = seen.json();
        let text = v["messages"][0]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        Reply::Json(
            StatusCode::OK,
            json!({"id": "msg_1", "type": "message", "role": "assistant",
                   "content": [{"type": "text", "text": text}], "stop_reason": "end_turn"}),
        )
    })
}

#[tokio::test]
async fn upstream_never_sees_real_values_and_client_gets_them_back() {
    let s = setup(echo_first_user_text()).await;
    let resp = s
        .post(
            "/v1/messages",
            &json!({"model": "m", "max_tokens": 10, "system": "You help Ravi Kumar",
                    "messages": [{"role": "user", "content": "Email ravi.k@gmail.com"}]}),
        )
        .await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let seen = s.mock.last();
    let up = seen.text();
    assert!(
        !up.contains("Ravi") && !up.contains("ravi.k@gmail.com"),
        "{up}"
    );
    assert!(
        seen.json()["system"]
            .as_str()
            .unwrap()
            .starts_with("You help ")
    );
    assert_eq!(body["content"][0]["text"], "Email ravi.k@gmail.com");
    assert_eq!(seen.path, "/v1/messages");
}

#[tokio::test]
async fn tool_use_input_restored_and_tool_result_redacted() {
    let s = setup(responder(|seen| {
        let v = seen.json();
        let email = find_email(&v.to_string());
        Reply::Json(
            StatusCode::OK,
            json!({"type": "message", "role": "assistant", "content": [
                {"type": "text", "text": "Sending."},
                {"type": "tool_use", "id": "tu_1", "name": "send_mail", "input": {"to": email, "n": 1}}
            ]}),
        )
    }))
    .await;
    let resp = s
        .post(
            "/v1/messages",
            &json!({"model": "m", "messages": [{"role": "user", "content": "Mail ravi.k@gmail.com"}]}),
        )
        .await;
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["content"][1]["input"]["to"], "ravi.k@gmail.com");
    assert_eq!(body["content"][1]["input"]["n"], 1);

    let resp = s
        .post(
            "/v1/messages",
            &json!({"model": "m", "messages": [
                {"role": "user", "content": "Mail ravi.k@gmail.com"},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "tu_1", "name": "send_mail", "input": {"to": "ravi.k@gmail.com"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "tu_1", "content": "Delivered. Call +91 98765 43210"}]}
            ]}),
        )
        .await;
    assert_eq!(resp.status(), 200);
    let up = s.mock.last().text();
    assert!(
        !up.contains("98765") && !up.contains("ravi.k@gmail.com"),
        "{up}"
    );
}

#[tokio::test]
async fn thinking_blocks_untouched() {
    let s = setup(responder(|seen| {
        let v = seen.json();
        let name = v["messages"][2]["content"].as_str().unwrap().to_string();
        Reply::Json(
            StatusCode::OK,
            json!({"type": "message", "role": "assistant", "content": [
                {"type": "thinking", "thinking": format!("User means {name}"), "signature": "s"},
                {"type": "text", "text": name}
            ]}),
        )
    }))
    .await;
    let thinking =
        json!({"type": "thinking", "thinking": "Ravi Kumar asked earlier", "signature": "sig=="});
    let resp = s
        .post(
            "/v1/messages",
            &json!({"model": "m", "messages": [
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": [thinking.clone(), {"type": "text", "text": "Hello"}]},
                {"role": "user", "content": "Ravi Kumar"}
            ]}),
        )
        .await;
    let body: Value = resp.json().await.unwrap();
    let seen = s.mock.last().json();
    assert_eq!(seen["messages"][1]["content"][0], thinking);
    assert_eq!(body["content"][1]["text"], "Ravi Kumar");
    // The thinking block of the answer is signed: left exactly as sent.
    assert!(
        !body["content"][0]["thinking"]
            .as_str()
            .unwrap()
            .contains("Ravi")
    );
}

#[tokio::test]
async fn unknown_block_types_pass_through() {
    let s = setup(echo_first_user_text()).await;
    let future = json!({"type": "future_block", "x": 1, "note": "Ravi Kumar"});
    let thinking = json!({"type": "redacted_thinking", "data": "Ravi Kumar"});
    s.post(
        "/v1/messages",
        &json!({"model": "m", "messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": [future.clone(), thinking.clone()]}
        ]}),
    )
    .await;
    let seen = s.mock.last().json();
    assert_eq!(seen["messages"][1]["content"][0], future);
    assert_eq!(seen["messages"][1]["content"][1], thinking);
}

#[tokio::test]
async fn server_and_mcp_tool_use_inputs_are_redacted_and_restored() {
    // The answer echoes the (redacted) query back in a server tool call.
    let s = setup(responder(|seen| {
        let v = seen.json();
        let q = v["messages"][0]["content"].as_str().unwrap().to_string();
        Reply::Json(
            StatusCode::OK,
            json!({"type": "message", "role": "assistant", "content": [
                {"type": "server_tool_use", "id": "s1", "name": "web_search", "input": {"query": q}},
                {"type": "mcp_tool_use", "id": "m1", "name": "crm", "server_name": "crm", "input": {"who": q}}
            ]}),
        )
    }))
    .await;
    let resp = s
        .post(
            "/v1/messages",
            &json!({"model": "m", "messages": [{"role": "user", "content": "Ravi Kumar"}]}),
        )
        .await;
    let body: Value = resp.json().await.unwrap();
    // Restored for the client ...
    assert_eq!(body["content"][0]["input"]["query"], "Ravi Kumar");
    assert_eq!(body["content"][1]["input"]["who"], "Ravi Kumar");

    // ... so the next turn carries the real name back, and parda must
    // redact it again.
    s.post(
        "/v1/messages",
        &json!({"model": "m", "messages": [
            {"role": "user", "content": "Ravi Kumar"},
            {"role": "assistant", "content": body["content"].clone()},
            {"role": "user", "content": "thanks"}
        ]}),
    )
    .await;
    let up = s.mock.last().text();
    assert!(!up.contains("Ravi"), "{up}");
}

#[tokio::test]
async fn auth_headers_forwarded_verbatim() {
    let s = setup(echo_first_user_text()).await;
    s.client
        .post(s.url("/v1/messages"))
        .header("x-api-key", "sk-ant-secret")
        .header("authorization", "Bearer tok")
        .header("anthropic-version", "2023-06-01")
        .header("anthropic-beta", "tools-2024")
        .header("x-parda-scope", "proj")
        .json(&json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    let h = s.mock.last().headers;
    assert_eq!(h["x-api-key"], "sk-ant-secret");
    assert_eq!(h["authorization"], "Bearer tok");
    assert_eq!(h["anthropic-version"], "2023-06-01");
    assert_eq!(h["anthropic-beta"], "tools-2024");
    assert!(h.get("x-parda-scope").is_none());
    assert_eq!(h["accept-encoding"], "identity");
}

#[tokio::test]
async fn origin_header_rejected() {
    let s = setup(echo_first_user_text()).await;
    let resp = s
        .client
        .post(s.url("/v1/messages"))
        .header("origin", "https://evil.example")
        .json(&json!({"model": "m", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "parda_forbidden");
    assert_eq!(s.mock.count(), 0);
}

#[tokio::test]
async fn non_loopback_host_rejected() {
    let s = setup(echo_first_user_text()).await;
    let resp = s
        .client
        .post(s.url("/v1/messages"))
        .header("host", "attacker.example:8787")
        .json(&json!({"model": "m", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(s.mock.count(), 0);
}

#[tokio::test]
async fn image_block_counts_unscanned_and_block_policy() {
    let req = json!({"model": "m", "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}},
        {"type": "text", "text": "what is this"}
    ]}]});
    let mut s = setup(echo_first_user_text()).await;
    assert_eq!(s.post("/v1/messages", &req).await.status(), 200);
    let ev = s.events.recv().await.unwrap();
    assert_eq!(ev.unscanned_media, 1);
    assert_eq!(ev.provider, "anthropic");

    let s = setup_with(
        echo_first_user_text(),
        |c| c.proxy.unscanned_media = UnscannedMedia::Block,
        None,
    )
    .await;
    let resp = s.post("/v1/messages", &req).await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "parda_unscanned_media");
    assert_eq!(s.mock.count(), 0);
}

#[tokio::test]
async fn strict_ml_failure_returns_503() {
    let s = setup_with(
        echo_first_user_text(),
        |c| {
            c.detect.model = "failing".into();
            c.detect.mode = Mode::Strict;
        },
        Some(Arc::new(FailingMl) as Arc<dyn MlDetector>),
    )
    .await;
    let resp = s
        .post(
            "/v1/messages",
            &json!({"model": "m", "messages": [{"role": "user", "content": "Ravi Kumar here"}]}),
        )
        .await;
    assert_eq!(resp.status(), 503);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["type"], "error");
    assert_eq!(body["error"]["type"], "parda_ml_unavailable");
    assert_eq!(s.mock.count(), 0);
}

#[tokio::test]
async fn upstream_error_body_restored_passthrough() {
    let s = setup(responder(|seen| {
        let email = find_email(&seen.text());
        Reply::Json(
            StatusCode::BAD_REQUEST,
            json!({"type": "error", "error": {"type": "invalid_request_error",
                   "message": format!("bad recipient {email}")}}),
        )
    }))
    .await;
    let resp = s
        .post(
            "/v1/messages",
            &json!({"model": "m", "messages": [{"role": "user", "content": "to ravi.k@gmail.com"}]}),
        )
        .await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["message"], "bad recipient ravi.k@gmail.com");
}

#[tokio::test]
async fn count_tokens_is_redacted_and_other_paths_pass_through() {
    let s = setup(responder(|_| {
        Reply::Json(StatusCode::OK, json!({"input_tokens": 7}))
    }))
    .await;
    let resp = s
        .post(
            "/v1/messages/count_tokens",
            &json!({"model": "m", "messages": [{"role": "user", "content": "Ravi Kumar"}]}),
        )
        .await;
    assert_eq!(resp.status(), 200);
    assert!(!s.mock.last().text().contains("Ravi"));

    let resp = s
        .client
        .get(s.url("/v1/models?limit=2"))
        .header("x-api-key", "k")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(s.mock.last().path, "/v1/models");
}

#[tokio::test]
async fn blocked_kind_returns_400_and_is_not_forwarded() {
    let s = setup_with(
        echo_first_user_text(),
        |c| {
            c.detect
                .actions
                .insert(parda_core::EntityKind::Secret, parda_core::Action::Block);
        },
        None,
    )
    .await;
    let resp = s
        .post(
            "/v1/messages",
            &json!({"model": "m", "messages": [{"role": "user",
                "content": "key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789abcd"}]}),
        )
        .await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "parda_blocked");
    assert_eq!(s.mock.count(), 0);
}

#[tokio::test]
async fn unknown_parts_are_unscanned_and_blocked_by_policy() {
    let req = json!({"model": "m", "messages": [{"role": "user", "content": [
        {"type": "future_part", "x": "Ravi Kumar"},
        {"type": "text", "text": "hi"}
    ]}]});
    // Allowed by default, with a warning in the event.
    let mut s = setup(echo_first_user_text()).await;
    assert_eq!(s.post("/v1/messages", &req).await.status(), 200);
    let ev = s.events.recv().await.unwrap();
    assert_eq!((ev.unknown_parts, ev.unscanned_media), (1, 0));

    let s = setup_with(
        echo_first_user_text(),
        |c| c.proxy.unscanned_media = UnscannedMedia::Block,
        None,
    )
    .await;
    let resp = s.post("/v1/messages", &req).await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "parda_unscanned_media");
    assert_eq!(s.mock.count(), 0);
}
