//! Request bodies that are compressed, slightly malformed or not JSON at all
//! must never reach the upstream unredacted.

mod common;

use std::io::Write;

use common::*;
use http::StatusCode;
use serde_json::{Value, json};

fn ok_reply() -> Responder {
    responder(|_| {
        Reply::Json(
            StatusCode::OK,
            json!({"id": "msg_1", "type": "message", "role": "assistant",
                   "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"}),
        )
    })
}

fn messages_body(text: &str) -> Vec<u8> {
    json!({"model": "m", "max_tokens": 10,
           "messages": [{"role": "user", "content": text}]})
    .to_string()
    .into_bytes()
}

async fn post_raw(
    s: &Setup,
    path: &str,
    body: Vec<u8>,
    encoding: Option<&str>,
) -> reqwest::Response {
    let mut rb = s
        .client
        .post(s.url(path))
        .header("x-api-key", "test-key")
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json");
    if let Some(e) = encoding {
        rb = rb.header("content-encoding", e);
    }
    rb.body(body).send().await.unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn brotli(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
        w.write_all(data).unwrap();
    }
    out
}

fn zstd(data: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
}

async fn assert_redacted_and_decoded(encoding: &str, body: Vec<u8>) {
    let s = setup(ok_reply()).await;
    let resp = post_raw(&s, "/v1/messages", body, Some(encoding)).await;
    assert_eq!(resp.status(), 200, "{encoding}");
    let seen = s.mock.last();
    assert!(
        seen.headers.get("content-encoding").is_none(),
        "{encoding}: the decoded body must not carry the old content-encoding"
    );
    let up = seen.text();
    assert!(!up.contains("Ravi Kumar"), "{encoding}: {up}");
    assert!(
        seen.json()["messages"][0]["content"]
            .as_str()
            .unwrap()
            .starts_with("Hello ")
    );
}

#[tokio::test]
async fn gzip_request_body_is_decoded_and_redacted() {
    assert_redacted_and_decoded("gzip", gzip(&messages_body("Hello Ravi Kumar"))).await;
}

#[tokio::test]
async fn deflate_brotli_and_zstd_request_bodies_are_decoded() {
    assert_redacted_and_decoded("deflate", deflate(&messages_body("Hello Ravi Kumar"))).await;
    assert_redacted_and_decoded("br", brotli(&messages_body("Hello Ravi Kumar"))).await;
    assert_redacted_and_decoded("zstd", zstd(&messages_body("Hello Ravi Kumar"))).await;
    // Stacked encodings are undone in reverse order.
    assert_redacted_and_decoded(
        "gzip, br",
        brotli(&gzip(&messages_body("Hello Ravi Kumar"))),
    )
    .await;
}

#[tokio::test]
async fn unsupported_content_encoding_is_refused() {
    let s = setup(ok_reply()).await;
    let resp = post_raw(
        &s,
        "/v1/messages",
        messages_body("Hello Ravi Kumar"),
        Some("compress"),
    )
    .await;
    assert_eq!(resp.status(), 415);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "parda_unsupported_encoding");
    assert_eq!(s.mock.count(), 0);
}

#[tokio::test]
async fn corrupt_gzip_is_refused() {
    let s = setup(ok_reply()).await;
    let resp = post_raw(
        &s,
        "/v1/messages",
        messages_body("Hello Ravi Kumar"),
        Some("gzip"),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["type"], "parda_unparseable_body");
    assert_eq!(s.mock.count(), 0);
}

#[tokio::test]
async fn decompression_bomb_is_refused() {
    let s = setup_with(ok_reply(), |c| c.proxy.max_body_bytes = 4096, None).await;
    let mut big = messages_body("Hello Ravi Kumar");
    big.extend(std::iter::repeat_n(b' ', 1 << 20));
    let resp = post_raw(&s, "/v1/messages", gzip(&big), Some("gzip")).await;
    assert_eq!(resp.status(), 413);
    assert_eq!(s.mock.count(), 0);
}

#[tokio::test]
async fn lone_surrogate_escape_is_replaced_not_forwarded() {
    let s = setup(ok_reply()).await;
    // A JS client cut an emoji in half: "\ud83d" has no low half.
    let body = br#"{"model":"m","max_tokens":10,"messages":[{"role":"user","content":"Hello Ravi Kumar \ud83d"}]}"#;
    let resp = post_raw(&s, "/v1/messages", body.to_vec(), None).await;
    assert_eq!(resp.status(), 200);
    let seen = s.mock.last();
    let up = seen.text();
    assert!(!up.contains("Ravi Kumar"), "{up}");
    let content = seen.json()["messages"][0]["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(content.ends_with('\u{fffd}'), "{content}");

    // A lone low half, and "\ud800" before a non-surrogate escape.
    let body =
        br#"{"model":"m","messages":[{"role":"user","content":"\udc00 Ravi Kumar \ud800\u0041"}]}"#;
    let resp = post_raw(&s, "/v1/messages", body.to_vec(), None).await;
    assert_eq!(resp.status(), 200);
    let content = s.mock.last().json()["messages"][0]["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        content.starts_with("\u{fffd} ") && content.ends_with("\u{fffd}A"),
        "{content}"
    );
    assert!(!content.contains("Ravi Kumar"));

    // A well-formed pair is kept, and an escaped backslash is not an escape.
    let body = br#"{"model":"m","messages":[{"role":"user","content":"\ud83d\ude00 \\ud800 Ravi Kumar"}]}"#;
    let resp = post_raw(&s, "/v1/messages", body.to_vec(), None).await;
    assert_eq!(resp.status(), 200);
    let content = s.mock.last().json()["messages"][0]["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(content.starts_with("\u{1f600} \\ud800 "), "{content}");
}

#[tokio::test]
async fn utf8_bom_is_accepted_and_redacted() {
    let s = setup(ok_reply()).await;
    let mut body = b"\xEF\xBB\xBF".to_vec();
    body.extend(messages_body("Hello Ravi Kumar"));
    let resp = post_raw(&s, "/v1/messages", body, None).await;
    assert_eq!(resp.status(), 200);
    assert!(!s.mock.last().text().contains("Ravi Kumar"));
}

#[tokio::test]
async fn unparseable_body_is_refused_not_forwarded() {
    let s = setup(ok_reply()).await;
    for path in ["/v1/messages", "/v1/chat/completions", "/v1/responses"] {
        let resp = post_raw(&s, path, b"{\"messages\": [Ravi Kumar".to_vec(), None).await;
        assert_eq!(resp.status(), 400, "{path}");
        let body: Value = resp.json().await.unwrap();
        let kind = body["error"]["type"].as_str().unwrap().to_string();
        assert_eq!(kind, "parda_unparseable_body", "{path}");
    }
    assert_eq!(s.mock.count(), 0);
}

#[tokio::test]
async fn non_object_json_bodies_are_refused_on_rewrite_routes() {
    let s = setup(ok_reply()).await;
    let paths = [
        "/v1/messages",
        "/v1/messages/count_tokens",
        "/v1/messages/batches",
        "/v1/complete",
        "/v1/chat/completions",
        "/v1/responses",
        "/v1/responses/input_tokens",
        "/v1/responses/compact",
        "/v1/completions",
        "/v1/embeddings",
        "/v1/conversations",
        "/v1/conversations/c1/items",
    ];
    for path in paths {
        for body in [r#"["Ravi Kumar"]"#, r#""Ravi Kumar""#, "42", "null", "true"] {
            let resp = post_raw(&s, path, body.as_bytes().to_vec(), None).await;
            assert_eq!(resp.status(), 400, "{path} {body}");
            let v: Value = resp.json().await.unwrap();
            assert_eq!(
                v["error"]["type"], "parda_unparseable_body",
                "{path} {body}"
            );
        }
    }
    // Compressed ones too.
    let resp = post_raw(&s, "/v1/messages", gzip(br#"["Ravi Kumar"]"#), Some("gzip")).await;
    assert_eq!(resp.status(), 400);
    assert_eq!(s.mock.count(), 0);
}

#[tokio::test]
async fn decompression_runs_off_the_async_workers() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    // The default test runtime has one thread: server, client and the
    // heartbeat below share it, so any long synchronous step shows up as a
    // gap between heartbeats.
    let s = setup(ok_reply()).await;
    let zeros = vec![b' '; 60 * 1024 * 1024];
    let body = gzip(&zeros);
    drop(zeros);
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let beat = tokio::spawn(async move {
        let mut worst = Duration::ZERO;
        let mut last = Instant::now();
        while !stop2.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(2)).await;
            worst = worst.max(last.elapsed());
            last = Instant::now();
        }
        worst
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    // 60 MiB of blanks is not JSON: refused, but only after decoding.
    let resp = post_raw(&s, "/v1/messages", body, Some("gzip")).await;
    assert_eq!(resp.status(), 400);
    stop.store(true, Ordering::Relaxed);
    let worst = beat.await.unwrap();
    assert!(
        worst < Duration::from_millis(100),
        "the async runtime stalled for {worst:?} while decoding the body"
    );
    assert_eq!(s.mock.count(), 0);
}

#[tokio::test]
async fn too_deeply_nested_body_is_refused() {
    let s = setup(ok_reply()).await;
    let mut input = json!("Ravi Kumar");
    for _ in 0..200 {
        input = json!({"x": input});
    }
    let body = json!({"model": "m", "messages": [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "n", "input": input}]}
    ]});
    // serde_json's own serialiser has no depth limit; build the text by hand.
    let resp = post_raw(&s, "/v1/messages", body.to_string().into_bytes(), None).await;
    assert_eq!(resp.status(), 400);
    assert_eq!(s.mock.count(), 0);
}

#[tokio::test]
async fn number_literals_survive_the_rewrite() {
    let s = setup(ok_reply()).await;
    // Too big for u64 / i64, and float spellings serde_json would change.
    let body = br#"{"model":"m","metadata":{"id":123456789012345678901234567890,"neg":-98765432109876543210},"temperature":1.0,"top_p":1e-1,"messages":[{"role":"user","content":"Ravi Kumar"},{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"n","input":{"order":340282366920938463463374607431768211457,"to":"Ravi Kumar"}}]}]}"#;
    let resp = post_raw(&s, "/v1/messages", body.to_vec(), None).await;
    assert_eq!(resp.status(), 200);
    let up = s.mock.last().text();
    assert!(!up.contains("Ravi Kumar"), "{up}");
    for lit in [
        "123456789012345678901234567890",
        "-98765432109876543210",
        "\"temperature\":1.0",
        "\"top_p\":1e-1",
        "340282366920938463463374607431768211457",
    ] {
        assert!(up.contains(lit), "{lit} missing in {up}");
    }

    // Inside a JSON-encoded tool-call argument string too.
    let s = setup(responder(|_| {
        Reply::Json(StatusCode::OK, json!({"choices": []}))
    }))
    .await;
    let args = r#"{"to":"Ravi Kumar","id":123456789012345678901234567890}"#;
    let resp = post_raw(
        &s,
        "/v1/chat/completions",
        json!({"model": "m", "messages": [{"role": "assistant", "content": null,
            "tool_calls": [{"id": "1", "type": "function", "function": {"name": "f", "arguments": args}}]}]})
        .to_string()
        .into_bytes(),
        None,
    )
    .await;
    assert_eq!(resp.status(), 200);
    let seen = s.mock.last().json();
    let sent = seen["messages"][0]["tool_calls"][0]["function"]["arguments"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(sent.contains("123456789012345678901234567890"), "{sent}");
    assert!(!sent.contains("Ravi Kumar"), "{sent}");
}
