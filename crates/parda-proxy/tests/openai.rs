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
        !up.contains("Ravi Kumar") && !up.contains("ravi.k@gmail.com"),
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
        !up.contains("Ravi Kumar") && !up.contains("ravi.k@gmail.com"),
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

fn chat_chunk(delta: Value, finish: Value) -> String {
    sse(
        None,
        &json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "gpt",
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}),
    )
}

fn user_sur(seen: &Seen, prefix: &str) -> String {
    let v = seen.json();
    let text = v["messages"][0]["content"]
        .as_str()
        .or_else(|| v["input"].as_str())
        .unwrap()
        .to_string();
    text.strip_prefix(prefix).unwrap().to_string()
}

fn chat_text(body: &str) -> (String, String) {
    let events: Vec<Value> = parse_events(body)
        .iter()
        .filter_map(|e| serde_json::from_str(&e.data).ok())
        .collect();
    let content = events
        .iter()
        .filter_map(|v| {
            v["choices"][0]["delta"]["content"]
                .as_str()
                .map(str::to_string)
        })
        .collect();
    let args = events
        .iter()
        .filter_map(|v| {
            v["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"]
                .as_str()
                .map(str::to_string)
        })
        .collect();
    (content, args)
}

#[tokio::test]
async fn chat_tail_stays_in_the_chunk_that_finishes_the_choice() {
    // vLLM / Ollama / Groq put the last text and finish_reason in one chunk.
    let s = setup(responder(|seen| {
        let sur = user_sur(seen, "Say hi to ");
        Reply::Sse(vec![
            (
                0,
                chat_chunk(json!({"role": "assistant", "content": "Hi! "}), Value::Null),
            ),
            (
                5,
                chat_chunk(json!({"content": format!("Thanks, {sur}")}), json!("stop")),
            ),
            (0, "data: [DONE]\n\n".into()),
        ])
    }))
    .await;
    let resp = s
        .post(
            "/v1/chat/completions",
            &json!({"model": "gpt", "stream": true, "messages": [{"role": "user", "content": "Say hi to Ravi Kumar"}]}),
        )
        .await;
    let body = resp.text().await.unwrap();
    assert_eq!(chat_text(&body).0, "Hi! Thanks, Ravi Kumar");
    // The finishing chunk is still the last one before [DONE].
    let events = parse_events(&body);
    let n = events.len();
    assert_eq!(events[n - 1].data, "[DONE]");
    let last: Value = serde_json::from_str(&events[n - 2].data).unwrap();
    assert_eq!(last["choices"][0]["finish_reason"], "stop");
}

#[tokio::test]
async fn chat_tool_arguments_escape_restored_values_and_keep_order() {
    let s = setup(responder(|seen| {
        let sur = user_sur(seen, "ship to ");
        let args = serde_json::to_string(&json!({"addr": sur})).unwrap();
        let mut at = args.find(&sur).unwrap() + sur.len() / 2;
        while !args.is_char_boundary(at) {
            at += 1;
        }
        let (a, b) = args.split_at(at);
        let call = |args: &str, first: bool| {
            if first {
                json!({"tool_calls": [{"index": 0, "id": "t", "type": "function", "function": {"name": "ship", "arguments": args}}]})
            } else {
                json!({"tool_calls": [{"index": 0, "function": {"arguments": args}}]})
            }
        };
        Reply::Sse(vec![
            (0, chat_chunk(call(a, true), Value::Null)),
            (5, chat_chunk(call(b, false), json!("tool_calls"))),
            (0, "data: [DONE]\n\n".into()),
        ])
    }))
    .await;
    let resp = s
        .post(
            "/v1/chat/completions",
            &json!({"model": "gpt", "stream": true, "messages": [{"role": "user", "content": format!("ship to {ADDRESS}")}]}),
        )
        .await;
    assert!(!s.mock.last().text().contains("Lotus"));
    let body = resp.text().await.unwrap();
    let args = chat_text(&body).1;
    let v: Value = serde_json::from_str(&args).unwrap_or_else(|e| panic!("{e}: {args}"));
    assert_eq!(v["addr"], ADDRESS);
}

#[tokio::test]
async fn responses_function_arguments_escape_restored_values() {
    let s = setup(responder(|seen| {
        let sur = user_sur(seen, "ship to ");
        let args = serde_json::to_string(&json!({"addr": sur})).unwrap();
        let mut at = args.find(&sur).unwrap() + sur.len() / 2;
        while !args.is_char_boundary(at) {
            at += 1;
        }
        let (a, b) = args.split_at(at);
        let delta = |d: &str, n: u64| {
            sse(
                Some("response.function_call_arguments.delta"),
                &json!({"type": "response.function_call_arguments.delta",
                "item_id": "fc_1", "output_index": 0, "delta": d, "sequence_number": n}),
            )
        };
        Reply::Sse(vec![
            (0, delta(a, 1)),
            (5, delta(b, 2)),
            (
                0,
                sse(
                    Some("response.function_call_arguments.done"),
                    &json!({"type": "response.function_call_arguments.done",
                "item_id": "fc_1", "output_index": 0, "arguments": args, "sequence_number": 3}),
                ),
            ),
        ])
    }))
    .await;
    let resp = s
        .post(
            "/v1/responses",
            &json!({"model": "gpt", "stream": true, "input": format!("ship to {ADDRESS}")}),
        )
        .await;
    let body = resp.text().await.unwrap();
    let events: Vec<Value> = parse_events(&body)
        .iter()
        .filter_map(|e| serde_json::from_str(&e.data).ok())
        .collect();
    let streamed: String = events
        .iter()
        .filter(|v| v["type"] == "response.function_call_arguments.delta")
        .map(|v| v["delta"].as_str().unwrap().to_string())
        .collect();
    let v: Value = serde_json::from_str(&streamed).unwrap_or_else(|e| panic!("{e}: {streamed}"));
    assert_eq!(v["addr"], ADDRESS);
    let done = events
        .iter()
        .find(|v| v["type"] == "response.function_call_arguments.done")
        .unwrap();
    let v: Value = serde_json::from_str(done["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(v["addr"], ADDRESS);
}

fn responses_events(body: &str) -> Vec<Value> {
    parse_events(body)
        .iter()
        .filter_map(|e| serde_json::from_str(&e.data).ok())
        .collect()
}

fn r_ev(v: Value) -> String {
    let ty = v["type"].as_str().unwrap().to_string();
    sse(Some(&ty), &v)
}

/// Split `s` inside `needle` at a char boundary.
fn split_inside(s: &str, needle: &str) -> (String, String) {
    let mut at = s.find(needle).unwrap() + needle.len() / 2;
    while !s.is_char_boundary(at) {
        at += 1;
    }
    (s[..at].to_string(), s[at..].to_string())
}

#[tokio::test]
async fn responses_stream_numbers_and_metadata_stay_consistent() {
    let s = setup(responder(|seen| {
        let sur = user_sur(seen, "Say hi to ");
        let text = format!("Hi {sur}");
        let (a, b) = split_inside(&text, &sur);
        Reply::Sse(vec![
            (0, r_ev(json!({"type": "response.created", "sequence_number": 0, "response": {"id": "r"}}))),
            (0, r_ev(json!({"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": a, "sequence_number": 1}))),
            (5, r_ev(json!({"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": b, "sequence_number": 2}))),
            // No output_text.done: the tail is flushed at response.completed.
            (0, r_ev(json!({"type": "response.completed", "sequence_number": 3, "response": {"id": "r", "output": []}}))),
        ])
    }))
    .await;
    let resp = s
        .post(
            "/v1/responses",
            &json!({"model": "gpt", "stream": true, "input": "Say hi to Ravi Kumar"}),
        )
        .await;
    let events = responses_events(&resp.text().await.unwrap());
    let seq: Vec<u64> = events
        .iter()
        .map(|v| v["sequence_number"].as_u64().unwrap())
        .collect();
    let want: Vec<u64> = (0..seq.len() as u64).collect();
    assert_eq!(seq, want, "{events:?}");
    let deltas: Vec<&Value> = events
        .iter()
        .filter(|v| v["type"] == "response.output_text.delta")
        .collect();
    let text: String = deltas
        .iter()
        .map(|v| v["delta"].as_str().unwrap())
        .collect();
    assert_eq!(text, "Hi Ravi Kumar");
    for d in deltas {
        assert_eq!(d["item_id"], "msg_1", "{d}");
        assert_eq!(d["output_index"], 0, "{d}");
        assert_eq!(d["content_index"], 0, "{d}");
    }
}

#[tokio::test]
async fn responses_custom_tool_input_and_refusal_are_restored() {
    let s = setup(responder(|seen| {
        let sur = user_sur(seen, "Say hi to ");
        let (a, b) = split_inside(&sur, &sur);
        let refusal = format!("I won't contact {sur}");
        Reply::Sse(vec![
            (0, r_ev(json!({"type": "response.custom_tool_call_input.delta", "item_id": "ct_1", "output_index": 0, "delta": format!("grep '{a}"), "sequence_number": 1}))),
            (5, r_ev(json!({"type": "response.custom_tool_call_input.delta", "item_id": "ct_1", "output_index": 0, "delta": format!("{b}' notes"), "sequence_number": 2}))),
            (0, r_ev(json!({"type": "response.custom_tool_call_input.done", "item_id": "ct_1", "output_index": 0, "input": format!("grep '{sur}' notes"), "sequence_number": 3}))),
            (0, r_ev(json!({"type": "response.refusal.delta", "item_id": "msg_2", "output_index": 1, "content_index": 0, "delta": refusal, "sequence_number": 4}))),
            (0, r_ev(json!({"type": "response.refusal.done", "item_id": "msg_2", "output_index": 1, "content_index": 0, "refusal": refusal, "sequence_number": 5}))),
        ])
    }))
    .await;
    let resp = s
        .post(
            "/v1/responses",
            &json!({"model": "gpt", "stream": true, "input": "Say hi to Ravi Kumar"}),
        )
        .await;
    let events = responses_events(&resp.text().await.unwrap());
    let joined = |ty: &str| -> String {
        events
            .iter()
            .filter(|v| v["type"] == ty)
            .map(|v| v["delta"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(
        joined("response.custom_tool_call_input.delta"),
        "grep 'Ravi Kumar' notes"
    );
    assert_eq!(
        joined("response.refusal.delta"),
        "I won't contact Ravi Kumar"
    );
    let done = |ty: &str, field: &str| -> String {
        events.iter().find(|v| v["type"] == ty).unwrap()[field]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(
        done("response.custom_tool_call_input.done", "input"),
        "grep 'Ravi Kumar' notes"
    );
    assert_eq!(
        done("response.refusal.done", "refusal"),
        "I won't contact Ravi Kumar"
    );
}
