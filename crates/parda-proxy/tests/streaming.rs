mod common;

use std::time::{Duration, Instant};

use common::*;
use http::StatusCode;
use serde_json::{Value, json};

/// The surrogate the mock received in place of "Ravi Kumar" in "Say hi to Ravi Kumar".
fn sur_from(seen: &Seen) -> String {
    let v = seen.json();
    v["messages"][0]["content"]
        .as_str()
        .unwrap()
        .strip_prefix("Say hi to ")
        .unwrap()
        .to_string()
}

fn text_delta(index: u64, text: &str) -> String {
    sse(
        Some("content_block_delta"),
        &json!({"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": text}}),
    )
}

fn anthropic_stream(parts: Vec<(u64, String)>) -> Reply {
    let mut events = vec![
        (
            0,
            sse(
                Some("message_start"),
                &json!({"type": "message_start", "message": {"id": "m", "content": []}}),
            ),
        ),
        (
            0,
            sse(
                Some("content_block_start"),
                &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ),
        ),
    ];
    events.extend(parts);
    events.push((
        0,
        sse(
            Some("content_block_stop"),
            &json!({"type": "content_block_stop", "index": 0}),
        ),
    ));
    events.push((
        0,
        sse(
            Some("message_delta"),
            &json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}}),
        ),
    ));
    events.push((
        0,
        sse(Some("message_stop"), &json!({"type": "message_stop"})),
    ));
    Reply::Sse(events)
}

fn collect_text(events: &[parda_proxy::SseEvent], delta_type: &str, field: &str) -> String {
    events
        .iter()
        .filter_map(|e| serde_json::from_str::<Value>(&e.data).ok())
        .filter(|v| v["type"] == "content_block_delta" && v["delta"]["type"] == delta_type)
        .map(|v| v["delta"][field].as_str().unwrap_or("").to_string())
        .collect()
}

#[tokio::test]
async fn anthropic_stream_restored_across_split_deltas() {
    let s = setup(responder(|seen| {
        let sur = sur_from(seen);
        let text = format!("Hello {sur}, nice to meet you.");
        let (a, rest) = text.split_at(9);
        let (b, c) = rest.split_at(rest.len() / 2);
        anthropic_stream(vec![
            (30, text_delta(0, a)),
            (30, text_delta(0, b)),
            (30, text_delta(0, c)),
        ])
    }))
    .await;
    let resp = s
        .post(
            "/v1/messages",
            &json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": "Say hi to Ravi Kumar"}]}),
        )
        .await;
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    let body = resp.text().await.unwrap();
    let events = parse_events(&body);
    assert_eq!(
        collect_text(&events, "text_delta", "text"),
        "Hello Ravi Kumar, nice to meet you."
    );
    assert!(events.iter().any(|e| e.data.contains("message_stop")));
    // The flush (if any) comes before content_block_stop.
    let stop = events
        .iter()
        .position(|e| e.data.contains("content_block_stop"))
        .unwrap();
    assert!(
        events[stop + 1..]
            .iter()
            .all(|e| !e.data.contains("text_delta"))
    );
}

#[tokio::test]
async fn anthropic_stream_tool_input_json_delta_restored() {
    let s = setup(responder(|seen| {
        let email = find_email(&seen.text());
        let json_text = format!("{{\"to\": \"{email}\", \"subject\": \"hi\"}}");
        let mid = json_text.find('@').unwrap();
        let (a, rest) = json_text.split_at(mid - 2);
        let (b, c) = rest.split_at(5);
        let part = |t: &str| {
            sse(
                Some("content_block_delta"),
                &json!({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": t}}),
            )
        };
        Reply::Sse(vec![
            (0, sse(Some("content_block_start"), &json!({"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "t", "name": "mail", "input": {}}}))),
            (10, part(a)),
            (10, part(b)),
            (10, part(c)),
            (0, sse(Some("content_block_stop"), &json!({"type": "content_block_stop", "index": 1}))),
            (0, sse(Some("message_stop"), &json!({"type": "message_stop"}))),
        ])
    }))
    .await;
    let resp = s
        .post(
            "/v1/messages",
            &json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": "Email ravi.k@gmail.com now"}]}),
        )
        .await;
    let body = resp.text().await.unwrap();
    let json_text = collect_text(&parse_events(&body), "input_json_delta", "partial_json");
    let v: Value = serde_json::from_str(&json_text).unwrap();
    assert_eq!(v["to"], "ravi.k@gmail.com");
    assert_eq!(v["subject"], "hi");
}

#[tokio::test]
async fn stream_is_incremental() {
    let s = setup(responder(|_| {
        anthropic_stream(vec![
            (0, text_delta(0, "first ")),
            (600, text_delta(0, "second")),
        ])
    }))
    .await;
    let started = Instant::now();
    let mut resp = s
        .post(
            "/v1/messages",
            &json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": "hello"}]}),
        )
        .await;
    let first = resp.chunk().await.unwrap().unwrap();
    let first_at = started.elapsed();
    assert!(!first.is_empty());
    assert!(
        first_at < Duration::from_millis(400),
        "first bytes after {first_at:?}"
    );
    let mut rest = String::from_utf8_lossy(&first).into_owned();
    while let Some(c) = resp.chunk().await.unwrap() {
        rest.push_str(&String::from_utf8_lossy(&c));
    }
    assert!(started.elapsed() >= Duration::from_millis(550));
    assert_eq!(
        collect_text(&parse_events(&rest), "text_delta", "text"),
        "first second"
    );
}

#[tokio::test]
async fn stream_thinking_delta_untouched() {
    let s = setup(responder(|seen| {
        let sur = sur_from(seen);
        Reply::Sse(vec![
            (0, sse(Some("content_block_start"), &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": ""}}))),
            (0, sse(Some("content_block_delta"), &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": format!("about {sur}")}}))),
            (0, sse(Some("content_block_delta"), &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "abc=="}}))),
            (0, sse(Some("content_block_stop"), &json!({"type": "content_block_stop", "index": 0}))),
            (0, sse(Some("message_stop"), &json!({"type": "message_stop"}))),
        ])
    }))
    .await;
    let resp = s
        .post(
            "/v1/messages",
            &json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": "Say hi to Ravi Kumar"}]}),
        )
        .await;
    let body = resp.text().await.unwrap();
    let sur = s.engine.redact("Ravi Kumar", "global").unwrap().text;
    assert!(body.contains(&format!("about {sur}")), "{body}");
    assert!(body.contains("abc=="));
    assert!(!body.contains("Ravi"));
}

#[tokio::test]
async fn upstream_error_status_with_json_is_restored() {
    let s = setup(responder(|seen| {
        let sur = sur_from(seen);
        Reply::Json(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"type": "error", "error": {"type": "rate_limit_error", "message": format!("slow down {sur}")}}),
        )
    }))
    .await;
    let resp = s
        .post(
            "/v1/messages",
            &json!({"model": "m", "stream": true, "messages": [{"role": "user", "content": "Say hi to Ravi Kumar"}]}),
        )
        .await;
    assert_eq!(resp.status(), 429);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["message"], "slow down Ravi Kumar");
}
