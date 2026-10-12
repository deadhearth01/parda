//! A mock LLM API that echoes the last user text back — as JSON or as an
//! SSE stream split into small deltas — so an end-to-end run can check that
//! the upstream never sees real values and the client gets them back.

use std::convert::Infallible;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use serde_json::{Value, json};

fn last_user_text(v: &Value) -> String {
    if let Some(s) = v["input"].as_str() {
        return s.to_string();
    }
    let msgs = v["messages"].as_array().or_else(|| v["input"].as_array());
    let Some(msgs) = msgs else {
        return String::new();
    };
    let Some(m) = msgs.iter().rev().find(|m| m["role"] == "user") else {
        return String::new();
    };
    match &m["content"] {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn chunks(s: &str, n: usize) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    chars.chunks(n.max(1)).map(|c| c.iter().collect()).collect()
}

fn sse(event: Option<&str>, data: &Value) -> String {
    match event {
        Some(e) => format!("event: {e}\ndata: {data}\n\n"),
        None => format!("data: {data}\n\n"),
    }
}

fn stream(events: Vec<String>) -> Response {
    let s = futures::stream::unfold(events.into_iter(), |mut it| async move {
        let e = it.next()?;
        tokio::time::sleep(Duration::from_millis(15)).await;
        Some((Ok::<_, Infallible>(Bytes::from(e)), it))
    });
    Response::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(s))
        .unwrap_or_default()
}

fn respond(path: &str, v: &Value) -> Response {
    let echo = format!("You said: {}", last_user_text(v));
    let streaming = v["stream"] == true;
    match (path, streaming) {
        ("/v1/messages", false) => axum::Json(json!({
            "id": "msg_mock", "type": "message", "role": "assistant", "model": "mock",
            "content": [{"type": "text", "text": echo}], "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }))
        .into_response(),
        ("/v1/messages", true) => {
            let mut ev = vec![
                sse(Some("message_start"), &json!({"type": "message_start", "message": {"id": "msg_mock", "content": []}})),
                sse(Some("content_block_start"), &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})),
            ];
            for c in chunks(&echo, 4) {
                ev.push(sse(Some("content_block_delta"), &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": c}})));
            }
            ev.push(sse(Some("content_block_stop"), &json!({"type": "content_block_stop", "index": 0})));
            ev.push(sse(Some("message_delta"), &json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}})));
            ev.push(sse(Some("message_stop"), &json!({"type": "message_stop"})));
            stream(ev)
        }
        ("/v1/chat/completions", false) => axum::Json(json!({
            "id": "chatcmpl-mock", "object": "chat.completion", "model": "mock",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": echo}}]
        }))
        .into_response(),
        ("/v1/chat/completions", true) => {
            let mut ev: Vec<String> = chunks(&echo, 4)
                .into_iter()
                .map(|c| sse(None, &json!({"id": "c", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": c}, "finish_reason": null}]})))
                .collect();
            ev.push(sse(None, &json!({"id": "c", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})));
            ev.push("data: [DONE]\n\n".into());
            stream(ev)
        }
        ("/v1/responses", false) => axum::Json(json!({
            "id": "resp_mock", "object": "response",
            "output": [{"type": "message", "id": "m", "role": "assistant", "content": [{"type": "output_text", "text": echo}]}]
        }))
        .into_response(),
        ("/v1/responses", true) => {
            let mut ev: Vec<String> = chunks(&echo, 4)
                .into_iter()
                .map(|c| sse(Some("response.output_text.delta"), &json!({"type": "response.output_text.delta", "item_id": "m", "output_index": 0, "content_index": 0, "delta": c})))
                .collect();
            ev.push(sse(Some("response.output_text.done"), &json!({"type": "response.output_text.done", "item_id": "m", "output_index": 0, "content_index": 0, "text": echo})));
            ev.push(sse(Some("response.completed"), &json!({"type": "response.completed", "response": {"id": "resp_mock", "output": [{"type": "message", "content": [{"type": "output_text", "text": echo}]}]}})));
            stream(ev)
        }
        _ => (axum::http::StatusCode::NOT_FOUND, "mock: unknown path").into_response(),
    }
}

pub async fn serve(port: u16, log: Option<PathBuf>) -> anyhow::Result<()> {
    let log = Arc::new(Mutex::new(log));
    let app = Router::new().fallback(move |req: Request| {
        let log = log.clone();
        async move {
            let (parts, body) = req.into_parts();
            let bytes = to_bytes(body, 64 * 1024 * 1024).await.unwrap_or_default();
            if let Some(p) = log.lock().ok().and_then(|l| l.clone())
                && let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
            {
                let _ = writeln!(
                    f,
                    "{} {}",
                    parts.uri.path(),
                    String::from_utf8_lossy(&bytes)
                );
            }
            let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            respond(parts.uri.path(), &v)
        }
    });
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("mock upstream on http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_user_text() {
        assert_eq!(
            last_user_text(&json!({"messages": [{"role": "user", "content": "hi"}]})),
            "hi"
        );
        assert_eq!(last_user_text(&json!({"input": "x"})), "x");
        assert_eq!(
            last_user_text(
                &json!({"messages": [{"role": "user", "content": [{"type": "text", "text": "a"}]}]})
            ),
            "a"
        );
        assert_eq!(chunks("abcdef", 4), vec!["abcd", "ef"]);
    }
}
