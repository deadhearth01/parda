mod common;

use common::*;
use http::StatusCode;
use serde_json::{Value, json};

fn first_user_text(v: &Value) -> String {
    v["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["role"] == "user")
        .and_then(|m| m["content"].as_str())
        .unwrap_or("")
        .to_string()
}

#[tokio::test]
async fn openai_chat_nonstream_and_stream() {
    let s = setup(responder(|seen| {
        let v = seen.json();
        let text = first_user_text(&v);
        if v["stream"] == true {
            let sur = text.strip_prefix("Say hi to ").unwrap().to_string();
            let reply = format!("Hi {sur}!");
            let (a, rest) = reply.split_at(5);
            let (b, c) = rest.split_at(3);
            let chunk = |content: &str, finish: Value| {
                sse(None, &json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "gpt",
                    "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": finish}]}))
            };
            Reply::Sse(vec![
                (0, chunk(a, Value::Null)),
                (20, chunk(b, Value::Null)),
                (20, chunk(c, Value::Null)),
                (0, chunk("", json!("stop"))),
                (0, "data: [DONE]\n\n".into()),
            ])
        } else {
            let email = find_email(&v.to_string());
            Reply::Json(
                StatusCode::OK,
                json!({"id": "c1", "object": "chat.completion", "choices": [{"index": 0, "finish_reason": "stop",
                    "message": {"role": "assistant", "content": text,
                        "tool_calls": [{"id": "t1", "type": "function", "function": {"name": "mail", "arguments": json!({"to": email}).to_string()}}]}}]}),
            )
        }
    }))
    .await;

    let resp = s
        .post(
            "/v1/chat/completions",
            &json!({"model": "gpt", "messages": [
                {"role": "system", "content": "Assist Ravi Kumar"},
                {"role": "user", "content": "Hello Ravi Kumar"},
                {"role": "assistant", "content": null, "tool_calls": [{"id": "t0", "type": "function", "function": {"name": "mail", "arguments": "{\"to\":\"ravi.k@gmail.com\"}"}}]},
                {"role": "tool", "tool_call_id": "t0", "content": "sent to ravi.k@gmail.com"}
            ]}),
        )
        .await;
    assert_eq!(resp.status(), 200);
    let up = s.mock.last().text();
    assert!(
        !up.contains("Ravi") && !up.contains("ravi.k@gmail.com"),
        "{up}"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["choices"][0]["message"]["content"], "Hello Ravi Kumar");
    let args: Value = serde_json::from_str(
        body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(args["to"], "ravi.k@gmail.com");

    let resp = s
        .post(
            "/v1/chat/completions",
            &json!({"model": "gpt", "stream": true, "messages": [{"role": "user", "content": "Say hi to Ravi Kumar"}]}),
        )
        .await;
    let body = resp.text().await.unwrap();
    let events = parse_events(&body);
    let text: String = events
        .iter()
        .filter_map(|e| serde_json::from_str::<Value>(&e.data).ok())
        .filter_map(|v| {
            v["choices"][0]["delta"]["content"]
                .as_str()
                .map(str::to_string)
        })
        .collect();
    assert_eq!(text, "Hi Ravi Kumar!");
    assert_eq!(events.last().unwrap().data, "[DONE]");
}

#[tokio::test]
async fn openai_responses_nonstream_and_stream() {
    let s = setup(responder(|seen| {
        let v = seen.json();
        let input = v["input"].as_str().unwrap_or("").to_string();
        if v["stream"] == true {
            let sur = input.strip_prefix("Say hi to ").unwrap().to_string();
            let reply = format!("Hey {sur}.");
            let (a, rest) = reply.split_at(6);
            let (b, c) = rest.split_at(4);
            let delta = |d: &str, n: u64| {
                sse(Some("response.output_text.delta"), &json!({"type": "response.output_text.delta",
                    "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": d, "sequence_number": n}))
            };
            Reply::Sse(vec![
                (0, delta(a, 1)),
                (20, delta(b, 2)),
                (20, delta(c, 3)),
                (0, sse(Some("response.output_text.done"), &json!({"type": "response.output_text.done",
                    "item_id": "msg_1", "output_index": 0, "content_index": 0, "text": reply, "sequence_number": 4}))),
                (0, sse(Some("response.completed"), &json!({"type": "response.completed", "sequence_number": 5,
                    "response": {"id": "r", "output": [{"type": "message", "id": "msg_1", "content": [{"type": "output_text", "text": reply}]}]}}))),
            ])
        } else {
            Reply::Json(
                StatusCode::OK,
                json!({"id": "r", "object": "response", "output": [
                    {"type": "message", "id": "m", "role": "assistant", "content": [{"type": "output_text", "text": input}]},
                    {"type": "function_call", "call_id": "c", "name": "mail", "arguments": json!({"to": find_email(&input)}).to_string()}
                ]}),
            )
        }
    }))
    .await;

    let resp = s
        .post(
            "/v1/responses",
            &json!({"model": "gpt", "instructions": "Help Ravi Kumar", "input": "mail ravi.k@gmail.com"}),
        )
        .await;
    assert_eq!(resp.status(), 200);
    let up = s.mock.last().text();
    assert!(
        !up.contains("Ravi") && !up.contains("ravi.k@gmail.com"),
        "{up}"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["output"][0]["content"][0]["text"],
        "mail ravi.k@gmail.com"
    );
    let args: Value =
        serde_json::from_str(body["output"][1]["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(args["to"], "ravi.k@gmail.com");

    let resp = s
        .post(
            "/v1/responses",
            &json!({"model": "gpt", "stream": true, "input": "Say hi to Ravi Kumar"}),
        )
        .await;
    let body = resp.text().await.unwrap();
    let events: Vec<Value> = parse_events(&body)
        .iter()
        .filter_map(|e| serde_json::from_str(&e.data).ok())
        .collect();
    let streamed: String = events
        .iter()
        .filter(|v| v["type"] == "response.output_text.delta")
        .map(|v| v["delta"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(streamed, "Hey Ravi Kumar.");
    let done = events
        .iter()
        .find(|v| v["type"] == "response.output_text.done")
        .unwrap();
    assert_eq!(done["text"], "Hey Ravi Kumar.");
    let completed = events
        .iter()
        .find(|v| v["type"] == "response.completed")
        .unwrap();
    assert_eq!(
        completed["response"]["output"][0]["content"][0]["text"],
        "Hey Ravi Kumar."
    );
    // Every delta precedes the done event.
    let done_at = events
        .iter()
        .position(|v| v["type"] == "response.output_text.done")
        .unwrap();
    assert!(
        events[done_at..]
            .iter()
            .all(|v| v["type"] != "response.output_text.delta")
    );
}

#[tokio::test]
async fn gzip_upstream_handled() {
    let s = setup(responder(|seen| {
        let v = seen.json();
        Reply::Gzip(json!({"choices": [{"index": 0, "message": {"role": "assistant", "content": first_user_text(&v)}}]}))
    }))
    .await;
    let resp = s
        .post(
            "/v1/chat/completions",
            &json!({"model": "gpt", "messages": [{"role": "user", "content": "for Ravi Kumar"}]}),
        )
        .await;
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("content-encoding").is_none());
    let len: usize = resp.headers()["content-length"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), len);
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["choices"][0]["message"]["content"], "for Ravi Kumar");
}
