//! Every endpoint that carries user text is redacted; path variants route
//! like their canonical form; unknown endpoints with text are refused.

mod common;

use common::*;
use http::StatusCode;
use serde_json::{Value, json};

/// Echo every string the upstream received, for restore checks.
fn echo() -> Responder {
    responder(|seen| {
        let v = seen.json();
        let text = v.to_string();
        if seen.path.ends_with("/v1/complete") {
            let prompt = v["prompt"].as_str().unwrap_or("").to_string();
            if v["stream"] == true {
                let (a, b) = prompt.split_at(prompt.len() / 2);
                return Reply::Sse(vec![
                    (
                        0,
                        sse(
                            Some("completion"),
                            &json!({"type": "completion", "completion": a, "stop_reason": null}),
                        ),
                    ),
                    (
                        5,
                        sse(
                            Some("completion"),
                            &json!({"type": "completion", "completion": b, "stop_reason": "stop_sequence"}),
                        ),
                    ),
                ]);
            }
            return Reply::Json(
                StatusCode::OK,
                json!({"type": "completion", "completion": prompt, "stop_reason": "stop_sequence"}),
            );
        }
        if seen.path.ends_with("/v1/completions") {
            let prompt = v["prompt"]
                .as_str()
                .or_else(|| v["prompt"][0].as_str())
                .unwrap_or("")
                .to_string();
            if v["stream"] == true {
                let (a, b) = prompt.split_at(prompt.len() / 2);
                let chunk = |t: &str, finish: Value| {
                    sse(
                        None,
                        &json!({"id": "c", "object": "text_completion", "choices": [{"index": 0, "text": t, "finish_reason": finish}]}),
                    )
                };
                return Reply::Sse(vec![
                    (0, chunk(a, Value::Null)),
                    (5, chunk(b, json!("stop"))),
                    (0, "data: [DONE]\n\n".into()),
                ]);
            }
            return Reply::Json(
                StatusCode::OK,
                json!({"id": "c", "object": "text_completion", "choices": [{"index": 0, "text": prompt, "finish_reason": "stop"}]}),
            );
        }
        Reply::Json(StatusCode::OK, json!({"ok": true, "seen": text}))
    })
}

async fn post_openai(s: &Setup, path: &str, body: &Value) -> reqwest::Response {
    s.client
        .post(s.url(path))
        .header("authorization", "Bearer sk-test")
        .json(body)
        .send()
        .await
        .unwrap()
}

fn assert_clean(s: &Setup) {
    let up = s.mock.last().text();
    assert!(
        // A surrogate may itself start with "Ravi" (Ravindra, ...).
        !up.contains("Ravi Kumar") && !up.contains("ravi.k@gmail.com"),
        "{up}"
    );
}

#[tokio::test]
async fn anthropic_message_batches_are_redacted() {
    let s = setup(echo()).await;
    let resp = s
        .post(
            "/v1/messages/batches",
            &json!({"requests": [
                {"custom_id": "a", "params": {"model": "m", "max_tokens": 5, "system": "Help Ravi Kumar",
                    "messages": [{"role": "user", "content": "mail ravi.k@gmail.com"}]}},
                {"custom_id": "b", "params": {"model": "m", "max_tokens": 5,
                    "messages": [{"role": "user", "content": [{"type": "text", "text": "Ravi Kumar"}]}]}}
            ]}),
        )
        .await;
    assert_eq!(resp.status(), 200);
    assert_clean(&s);
    assert_eq!(s.mock.last().json()["requests"][1]["custom_id"], "b");
}

#[tokio::test]
async fn legacy_complete_is_redacted_and_restored() {
    let s = setup(echo()).await;
    let prompt = "\n\nHuman: Hello Ravi Kumar\n\nAssistant:";
    let resp = s
        .post(
            "/v1/complete",
            &json!({"model": "claude-2", "prompt": prompt, "max_tokens_to_sample": 5}),
        )
        .await;
    assert_eq!(resp.status(), 200);
    assert_clean(&s);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["completion"], prompt);

    let resp = s
        .post(
            "/v1/complete",
            &json!({"model": "claude-2", "prompt": prompt, "max_tokens_to_sample": 5, "stream": true}),
        )
        .await;
    assert_clean(&s);
    let text: String = parse_events(&resp.text().await.unwrap())
        .iter()
        .filter_map(|e| serde_json::from_str::<Value>(&e.data).ok())
        .filter_map(|v| v["completion"].as_str().map(str::to_string))
        .collect();
    assert_eq!(text, prompt);
}

#[tokio::test]
async fn openai_completions_prompt_and_suffix_are_redacted_and_restored() {
    let s = setup(echo()).await;
    let resp = post_openai(
        &s,
        "/v1/completions",
        &json!({"model": "m", "prompt": "def mail(): # ravi.k@gmail.com", "suffix": "return 'Ravi Kumar'"}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_clean(&s);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["choices"][0]["text"], "def mail(): # ravi.k@gmail.com");

    let resp = post_openai(
        &s,
        "/v1/completions",
        &json!({"model": "m", "prompt": ["Hello Ravi Kumar", "x"], "stream": true}),
    )
    .await;
    assert_clean(&s);
    let text: String = parse_events(&resp.text().await.unwrap())
        .iter()
        .filter_map(|e| serde_json::from_str::<Value>(&e.data).ok())
        .filter_map(|v| v["choices"][0]["text"].as_str().map(str::to_string))
        .collect();
    assert_eq!(text, "Hello Ravi Kumar");
}

#[tokio::test]
async fn embeddings_input_is_redacted() {
    let s = setup(echo()).await;
    for input in [
        json!("Ravi Kumar lives here"),
        json!(["a", "ravi.k@gmail.com"]),
    ] {
        let resp = post_openai(&s, "/v1/embeddings", &json!({"model": "e", "input": input})).await;
        assert_eq!(resp.status(), 200);
        assert_clean(&s);
    }
}

#[tokio::test]
async fn responses_side_endpoints_are_redacted() {
    let s = setup(echo()).await;
    for path in ["/v1/responses/input_tokens", "/v1/responses/compact"] {
        let resp = post_openai(
            &s,
            path,
            &json!({"model": "m", "instructions": "Help Ravi Kumar",
                    "input": [{"role": "user", "content": "mail ravi.k@gmail.com"}]}),
        )
        .await;
        assert_eq!(resp.status(), 200, "{path}");
        assert_clean(&s);
    }
}

#[tokio::test]
async fn conversation_items_are_redacted() {
    let s = setup(echo()).await;
    let items = json!([{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Ravi Kumar"}]},
                       {"type": "function_call_output", "call_id": "c", "output": "ravi.k@gmail.com"}]);
    for path in ["/v1/conversations", "/v1/conversations/conv_123/items"] {
        let resp = post_openai(&s, path, &json!({"items": items})).await;
        assert_eq!(resp.status(), 200, "{path}");
        assert_clean(&s);
    }
}

#[tokio::test]
async fn path_variants_route_like_the_canonical_path() {
    let s = setup(echo()).await;
    for (path, canonical) in [
        ("/v1//chat/completions", "/v1/chat/completions"),
        ("//v1/chat/completions/", "/v1/chat/completions"),
        ("/v1/%63hat/completions", "/v1/chat/completions"),
        ("/v1/./messages", "/v1/messages"),
        ("/v1/x/../messages", "/v1/messages"),
        ("/v1/%6Dessages", "/v1/messages"),
        ("/v1/%6dessages/count_tokens", "/v1/messages/count_tokens"),
    ] {
        let resp = post_openai(
            &s,
            path,
            &json!({"model": "m", "messages": [{"role": "user", "content": "Ravi Kumar"}]}),
        )
        .await;
        assert_eq!(resp.status(), 200, "{path}");
        assert_clean(&s);
        assert_eq!(s.mock.last().path, canonical, "{path}");
    }
}

#[tokio::test]
async fn unknown_endpoint_with_text_is_refused() {
    let s = setup(echo()).await;
    let resp = post_openai(
        &s,
        "/v1/threads/t1/messages",
        &json!({"role": "user", "content": "Ravi Kumar"}),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "parda_unknown_endpoint");
    // Anthropic-looking requests get an Anthropic-shaped error.
    let resp = s.post("/v1/files", &json!({"note": "Ravi Kumar"})).await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["type"], "error");
    assert_eq!(body["error"]["type"], "parda_unknown_endpoint");
    // A non-JSON body on an unknown path is refused too.
    let resp = s
        .client
        .post(s.url("/api/generate"))
        .body("Ravi Kumar")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    // So is a body sent with GET.
    let resp = s
        .client
        .get(s.url("/v1/models"))
        .body("{\"q\": \"Ravi Kumar\"}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert_eq!(s.mock.count(), 0);
}

#[tokio::test]
async fn unknown_endpoints_without_text_pass_through() {
    let s = setup(echo()).await;
    let resp = s
        .client
        .post(s.url("/v1/messages/batches/msgbatch_1/cancel"))
        .header("x-api-key", "k")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(s.mock.last().path, "/v1/messages/batches/msgbatch_1/cancel");
    let resp = post_openai(&s, "/v1/batches/b1/cancel", &json!({})).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(s.mock.last().text(), "{}");
    let resp = s
        .client
        .delete(s.url("/v1/responses/resp_1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(s.mock.count(), 3);
}

#[tokio::test]
async fn passthrough_paths_opt_in_forwards_unknown_endpoints_with_a_warning() {
    let mut s = setup_with(
        echo(),
        |c| {
            c.proxy.passthrough_paths = vec![
                "/api/*".into(),
                "/v1/files".into(),
                // Endpoints parda redacts are never passed through.
                "/v1/chat/completions".into(),
                "/v1/messages/*".into(),
            ];
        },
        None,
    )
    .await;
    let text = json!({"model": "llama3", "prompt": "Ravi Kumar"});

    // Prefix entry, exact entry, and a path that only normalises to a match.
    for (path, canonical) in [
        ("/api/generate", "/api/generate"),
        ("/api/chat/sub", "/api/chat/sub"),
        ("//api/%67enerate", "/api/generate"),
        ("/v1/files", "/v1/files"),
    ] {
        let resp = post_openai(&s, path, &text).await;
        assert_eq!(resp.status(), 200, "{path}");
        let seen = s.mock.last();
        assert_eq!(seen.path, canonical, "{path}");
        assert!(seen.text().contains("Ravi Kumar"), "{path} forwarded as is");
        let ev = s.events.recv().await.unwrap();
        assert!(ev.passthrough, "{path}: {ev:?}");
        assert_eq!(ev.status, 200);
        assert_eq!(ev.error, None);
    }
    let forwarded = s.mock.count();

    // Everything else is still refused.
    for path in ["/api", "/v1/files/f1", "/v1/threads/t1/messages", "/apiary"] {
        let resp = post_openai(&s, path, &text).await;
        assert_eq!(resp.status(), 400, "{path}");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["error"]["type"], "parda_unknown_endpoint", "{path}");
        let ev = s.events.recv().await.unwrap();
        assert!(!ev.passthrough, "{path}");
    }
    assert_eq!(s.mock.count(), forwarded);

    // A listed path that parda knows how to redact is redacted, not passed through.
    let resp = post_openai(
        &s,
        "/v1/chat/completions",
        &json!({"model": "m", "messages": [{"role": "user", "content": "Ravi Kumar"}]}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_clean(&s);
    assert!(!s.events.recv().await.unwrap().passthrough);
    let resp = s
        .post(
            "/v1/messages/batches",
            &json!({"requests": [{"custom_id": "a", "params": {"model": "m", "max_tokens": 5,
                "messages": [{"role": "user", "content": "Ravi Kumar"}]}}]}),
        )
        .await;
    assert_eq!(resp.status(), 200);
    assert_clean(&s);
    assert!(!s.events.recv().await.unwrap().passthrough);
    // Listing a redacted path does not open it to other methods either.
    let resp = s
        .client
        .put(s.url("/v1/chat/completions"))
        .json(&text)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert!(!s.events.recv().await.unwrap().passthrough);
}

#[tokio::test]
async fn nothing_is_passed_through_by_default() {
    let s = setup(echo()).await;
    let resp = post_openai(&s, "/api/generate", &json!({"prompt": "Ravi Kumar"})).await;
    assert_eq!(resp.status(), 400);
    assert_eq!(s.mock.count(), 0);
}
