//! End-to-end tests of the engine-backed intercept with site-shaped traffic
//! (chatgpt.com, claude.ai, Gemini): what the site receives, and what the
//! browser gets back. No external network.

mod common;

use std::io::Write;
use std::sync::Arc;

use common::{FailingMl, Reply, Responder, SITES, Seen, start_parda, start_upstream};
use parda_core::{MlDetector, UnscannedMedia};
use parda_wire::sse::{SseEvent, SseParser};
use serde_json::{Value, json};

const CONV: &str = "6f1c2a9e-0b7d-4c55-9a3e-2d8f6b1c4e70";
const MSG: &str = "aaa2b8c1-55f4-4bd2-9a1c-0123456789ab";
const ORG: &str = "1e2d3c4b-5a69-4788-9a0b-c1d2e3f40516";

fn sse_body(events: &[(Option<&str>, Value)]) -> Vec<String> {
    events
        .iter()
        .map(|(name, data)| match name {
            Some(n) => format!("event: {n}\ndata: {data}\n\n"),
            None => format!("data: {data}\n\n"),
        })
        .collect()
}

fn events(body: &[u8]) -> Vec<SseEvent> {
    let mut p = SseParser::default();
    let mut evs = p.feed(body);
    evs.extend(p.finish());
    evs
}

/// Gemini's answer frame (JSON inside a JSON string).
const GEMINI_ANSWER: &str = "[[\"wrb.fr\",null,\"[[\\\"Hi [NAME_1]\\\"]]\"]]";

/// A Google length-prefixed frame: the number counts the payload in UTF-16
/// code units, starting right after the digits.
fn gemini_frame(json: &str) -> String {
    let payload = format!("\n{json}\n");
    format!("{}{payload}", payload.encode_utf16().count())
}

/// The fake site: chatgpt.com, claude.ai, Gemini, DeepSeek and Meta AI
/// endpoints; anything else echoes the request body as text.
fn site() -> Responder {
    Arc::new(|seen: &Seen| match seen.path.as_str() {
        // An echo as a stream (chatgpt's other send endpoint, or any site).
        "/backend-api/f/conversation" | "/echo/stream" => Reply::new(
            "text/event-stream",
            vec![format!("data: echo: {}\n\n", seen.text())],
        ),
        // DeepSeek-shaped: a delta stream, the tag split across events.
        "/api/v0/chat/completion" => Reply::new(
            "text/event-stream; charset=utf-8",
            sse_body(&[
                (None, json!({"v": "Hi [NA"})),
                (None, json!({"v": "ME_1]"})),
                (Some("close"), json!({"click_behavior": "none"})),
            ]),
        ),
        // Meta AI GraphQL: one JSON document, or several values (one per
        // line) when the query asks for a stream, typed as NDJSON when it
        // asks for that too, else as JSON.
        "/api/graphql/" if seen.text().contains("\"stream\":true") => Reply::new(
            if seen.text().contains("\"ndjson\":true") {
                "application/x-ndjson"
            } else {
                "application/json"
            },
            vec![
                format!("{}\n", json!({"seq": 1, "delta": "Hi [NAME_1]"})),
                format!("{}\n", json!({"seq": 2, "delta": " bye"})),
            ],
        ),
        "/api/graphql/" => Reply::new(
            "application/json",
            vec![json!({"data": {"node": {"text": "Hi [NAME_1]"}}}).to_string()],
        ),
        "/backend-api/conversation" => Reply::new("text/event-stream; charset=utf-8", {
            let mut v = sse_body(&[
                (Some("delta_encoding"), json!("v1")),
                (
                    Some("delta"),
                    json!({"p": "", "o": "add", "v": {"message": {
                            "id": MSG, "author": {"role": "assistant"},
                            "content": {"content_type": "text", "parts": [""]},
                            "status": "in_progress"}, "conversation_id": CONV}, "c": 0}),
                ),
                (
                    Some("delta"),
                    json!({"p": "/message/content/parts/0", "o": "append",
                               "v": "Sure, I'll write to [NA"}),
                ),
                (Some("delta"), json!({"v": "ME_"})),
                (Some("delta"), json!({"v": "1] at [EMAIL_1]."})),
                (
                    Some("delta"),
                    json!({"p": "", "o": "patch", "v": [
                            {"p": "/message/content/parts/0", "o": "append", "v": " Bye [name_1]"},
                            {"p": "/message/status", "o": "replace", "v": "finished_successfully"}]}),
                ),
                (
                    None,
                    json!({"type": "message_stream_complete", "conversation_id": CONV}),
                ),
            ]);
            v.push("data: [DONE]\n\n".into());
            v
        }),
        p if p.starts_with("/backend-api/share/") => Reply::new(
            "application/json",
            vec![
                json!({"title": "Shared by someone", "text": "Hi [NAME_1] [EMAIL_1]"}).to_string(),
            ],
        ),
        p if p.starts_with("/backend-api/conversation/") => Reply::new(
            "application/json",
            vec![
                json!({"title": "Note to [NAME_1]", "mapping": {MSG: {"message": {
                    "id": MSG, "content": {"parts": ["Mail [EMAIL_1] please"]}}}},
                    "current_node": MSG})
                .to_string(),
            ],
        ),
        p if p.ends_with("/completion") => Reply::new("text/event-stream", {
            sse_body(&[
                (
                    Some("completion"),
                    json!({"type": "completion", "completion": "Hello [NAM",
                           "stop_reason": null, "log_id": "abc"}),
                ),
                (Some("ping"), json!({"type": "ping"})),
                (
                    Some("completion"),
                    json!({"type": "completion", "completion": "E_1], ",
                           "stop_reason": null, "log_id": "abc"}),
                ),
                (
                    Some("content_block_delta"),
                    json!({"type": "content_block_delta", "index": 0,
                           "delta": {"type": "text_delta", "text": "mail [EMA"}}),
                ),
                (
                    Some("content_block_delta"),
                    json!({"type": "content_block_delta", "index": 0,
                           "delta": {"type": "text_delta", "text": "IL_1] now"}}),
                ),
                (
                    Some("content_block_stop"),
                    json!({"type": "content_block_stop", "index": 0}),
                ),
                (Some("message_stop"), json!({"type": "message_stop"})),
            ])
        }),
        p if p.contains("StreamGenerate") => {
            // A Google length-prefixed frame, split inside the tag.
            let framed = gemini_frame(GEMINI_ANSWER);
            let cut = framed.find("[NA").unwrap() + 3;
            Reply::new(
                "application/json; charset=utf-8",
                vec![
                    ")]}'\n\n".to_string(),
                    framed[..cut].to_string(),
                    framed[cut..].to_string(),
                ],
            )
        }
        _ => Reply::new("text/plain", vec![format!("echo: {}", seen.text())]),
    })
}

/// The text a chatgpt.com client builds from the delta-encoded answer.
fn chatgpt_text(body: &[u8]) -> String {
    let mut text = String::new();
    let mut last_o = String::new();
    for ev in events(body) {
        if ev.event.as_deref() != Some("delta") {
            continue;
        }
        let v: Value = serde_json::from_str(&ev.data).unwrap();
        if let Some(o) = v["o"].as_str() {
            last_o = o.to_string();
        }
        match (last_o.as_str(), &v["v"]) {
            ("append", Value::String(s)) => text.push_str(s),
            ("patch", Value::Array(ops)) => {
                for op in ops {
                    if op["o"] == "append" && op["p"] == "/message/content/parts/0" {
                        text.push_str(op["v"].as_str().unwrap());
                    }
                }
            }
            _ => {}
        }
    }
    text
}

#[tokio::test]
async fn chatgpt_request_answer_and_history() {
    let up = start_upstream(site()).await;
    let mut parda = start_parda(&up, |_| {}, None).await;
    let c = parda.client();
    let base = format!("https://chatgpt.com:{}", up.port);

    let request = json!({
        "action": "next",
        "messages": [{
            "id": MSG,
            "author": {"role": "user"},
            "create_time": 1760000000.123,
            "content": {"content_type": "text",
                        "parts": ["Write to Ravi Kumar at ravi.kumar@example.com"]},
            "metadata": {"serialization_metadata": {"custom_symbol_offsets": []}},
        }],
        "conversation_id": CONV,
        "parent_message_id": "client-created-root",
        "model": "auto",
        "timezone_offset_min": -330,
        "timezone": "Asia/Kolkata",
        "conversation_mode": {"kind": "primary_assistant"},
        "websocket_request_id": "5f1c2a9e-0b7d-4c55-9a3e-2d8f6b1c4e71",
        "supported_encodings": ["v1"],
        "client_contextual_info": {"is_dark_mode": true, "page_height": 900},
    });
    let res = c
        .post(format!("{base}/backend-api/conversation"))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let answer = res.bytes().await.unwrap();

    // The site saw tags in the message text only.
    let seen = up.seen();
    assert_eq!(seen.len(), 1);
    let mut want = request.clone();
    want["messages"][0]["content"]["parts"][0] = json!("Write to [NAME_1] at [EMAIL_1]");
    let got: Value = serde_json::from_slice(&seen[0].body).unwrap();
    assert_eq!(got, want);
    assert!(!seen[0].text().contains("Ravi") && !seen[0].text().contains("ravi."));
    let ev = parda.next_event().await;
    assert_eq!(
        (ev.host.as_str(), ev.path.as_str()),
        ("chatgpt.com", "/backend-api/conversation")
    );
    assert_eq!(ev.counts.get("Person"), Some(&1));
    assert_eq!(ev.counts.get("Email"), Some(&1));

    // The answer: a tag split across three events comes back whole.
    assert_eq!(
        chatgpt_text(&answer),
        "Sure, I'll write to Ravi Kumar at ravi.kumar@example.com. Bye Ravi Kumar"
    );
    let text = String::from_utf8_lossy(&answer);
    assert!(text.contains(MSG) && text.contains(CONV) && text.ends_with("data: [DONE]\n\n"));

    // The conversation history, as JSON.
    let res = c
        .get(format!("{base}/backend-api/conversation/{CONV}"))
        .send()
        .await
        .unwrap();
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["title"], "Note to Ravi Kumar");
    assert_eq!(
        v["mapping"][MSG]["message"]["content"]["parts"][0],
        "Mail ravi.kumar@example.com please"
    );
}

#[tokio::test]
async fn claude_completion_request_and_stream() {
    let up = start_upstream(site()).await;
    let parda = start_parda(&up, |_| {}, None).await;
    let c = parda.client();
    let url = format!(
        "https://claude.ai:{}/api/organizations/{ORG}/chat_conversations/{CONV}/completion",
        up.port
    );
    let request = json!({
        "prompt": "Ask Ravi Kumar (ravi.kumar@example.com) about it",
        "parent_message_uuid": MSG,
        "timezone": "Asia/Kolkata",
        "locale": "en-US",
        "personalized_styles": [{"type": "default", "key": "Default", "name": "Normal"}],
        "attachments": [],
        "files": [],
        "sync_sources": [],
        "rendering_mode": "messages",
    });
    let res = c.post(&url).json(&request).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body = res.bytes().await.unwrap();

    let seen = up.seen();
    let got: Value = serde_json::from_slice(&seen[0].body).unwrap();
    let mut want = request.clone();
    want["prompt"] = json!("Ask [NAME_1] ([EMAIL_1]) about it");
    assert_eq!(got, want);

    let mut text = String::new();
    for ev in events(&body) {
        let v: Value = serde_json::from_str(&ev.data).unwrap();
        match v["type"].as_str() {
            Some("completion") => text.push_str(v["completion"].as_str().unwrap()),
            Some("content_block_delta") => text.push_str(v["delta"]["text"].as_str().unwrap()),
            _ => {}
        }
    }
    assert_eq!(text, "Hello Ravi Kumar, mail ravi.kumar@example.com now");
}

#[tokio::test]
async fn gemini_form_with_json_in_strings() {
    let up = start_upstream(site()).await;
    let parda = start_parda(&up, |_| {}, None).await;
    let c = parda.client();
    let inner = json!([
        [
            "Ravi Kumar here, mail ravi.kumar@example.com",
            0,
            null,
            null,
            null,
            null,
            0
        ],
        ["en"],
        [
            "c_9b1f0e2a7d4c3b5a",
            "r_1a2b3c4d5e6f7a8b",
            "rc_0f1e2d3c4b5a6978",
            null,
            null
        ],
        "!xyzTOKEN0123456789abcdef",
    ])
    .to_string();
    let freq = json!([null, inner]).to_string();
    let query = "bl=boq_assistant-bard-web-server_20251001.08_p0&f.sid=-1234567890123456789\
                 &hl=en&_reqid=123456&rt=c";
    let url = format!(
        "https://gemini.google.com:{}/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate?{query}",
        up.port
    );
    let res = c
        .post(&url)
        .form(&[
            ("f.req", freq.as_str()),
            ("at", "AJvLN6M3xYz:1697000000000"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let answer = res.text().await.unwrap();
    // The XSSI-prefixed frame is restored, its length recomputed.
    assert_eq!(
        answer,
        format!(
            ")]}}'\n\n{}",
            gemini_frame(&GEMINI_ANSWER.replace("[NAME_1]", "Ravi Kumar"))
        )
    );

    let seen = up.seen();
    assert_eq!(seen[0].query.as_deref(), Some(query));
    let pairs: Vec<(String, String)> = form_urlencoded::parse(&seen[0].body).into_owned().collect();
    assert_eq!(
        pairs[1],
        ("at".to_string(), "AJvLN6M3xYz:1697000000000".to_string())
    );
    assert_eq!(pairs[0].0, "f.req");
    let outer: Value = serde_json::from_str(&pairs[0].1).unwrap();
    let got: Value = serde_json::from_str(outer[1].as_str().unwrap()).unwrap();
    let mut want: Value = serde_json::from_str(&inner).unwrap();
    want[0][0] = json!("[NAME_1] here, mail [EMAIL_1]");
    assert_eq!(got, want);
}

#[tokio::test]
async fn query_strings_compressed_bodies_and_refusals() {
    let up = start_upstream(site()).await;
    let mut parda = start_parda(&up, |_| {}, None).await;
    let c = parda.client();
    let base = format!("https://example.com:{}", up.port);

    // A query: values redacted, identifiers untouched.
    let res = c
        .get(format!(
            "{base}/search?q=Ravi%20Kumar&conversation_id={CONV}&n=5"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.text().await.unwrap(), "echo: ");
    let ev = parda.next_event().await;
    assert_eq!(ev.path, "/search");
    assert_eq!(ev.counts.get("Person"), Some(&1));

    // A gzip-compressed JSON body is decoded, redacted and sent identity.
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(json!({"message": "I am Ravi Kumar"}).to_string().as_bytes())
        .unwrap();
    let res = c
        .post(format!("{base}/api/chat"))
        .header("content-type", "application/json")
        .header("content-encoding", "gzip")
        .body(gz.finish().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.text().await.unwrap(),
        "echo: {\"message\":\"I am [NAME_1]\"}",
        "another site's answer is restored only when it streams"
    );

    // Unparseable JSON never leaves.
    let res = c
        .post(format!("{base}/api/chat"))
        .header("content-type", "application/json")
        .body("{\"message\": \"Ravi Kumar")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let msg = res.text().await.unwrap();
    assert!(
        msg.starts_with("parda_unparseable_body") && !msg.contains("Ravi"),
        "{msg}"
    );

    let seen = up.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(
        seen[0].query.as_deref(),
        Some(format!("q=%5BNAME_1%5D&conversation_id={CONV}&n=5").as_str())
    );
    assert_eq!(seen[1].text(), "{\"message\":\"I am [NAME_1]\"}");
    assert_eq!(seen[1].content_encoding, None);
}

#[tokio::test]
async fn strict_mode_ml_failure_sends_nothing() {
    let up = start_upstream(site()).await;
    let mut parda = start_parda(
        &up,
        |c| c.detect.model = "failing".into(),
        Some(Arc::new(FailingMl) as Arc<dyn MlDetector>),
    )
    .await;
    let res = parda
        .client()
        .post(format!(
            "https://chatgpt.com:{}/backend-api/conversation",
            up.port
        ))
        .json(&json!({"messages": [{"content": {"parts": ["Ravi Kumar"]}}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 503);
    assert!(
        res.text()
            .await
            .unwrap()
            .starts_with("parda_ml_unavailable")
    );
    assert!(up.seen().is_empty());
    let ev = parda.next_event().await;
    assert_eq!(ev.status, 503);
    assert!(ev.refused.unwrap().starts_with("parda_ml_unavailable"));
}

fn multipart(boundary: &str) -> String {
    format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\n\
         Summarise this for Ravi Kumar\r\n--{boundary}\r\nContent-Disposition: form-data; \
         name=\"file\"; filename=\"notes.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n\
         RAW-BYTES Ravi Kumar\r\n--{boundary}--\r\n"
    )
}

#[tokio::test]
async fn multipart_files_are_unscanned_and_blockable() {
    let up = start_upstream(site()).await;
    let mut parda = start_parda(&up, |_| {}, None).await;
    let res = parda
        .client()
        .post(format!("https://chatgpt.com:{}/backend-api/files", up.port))
        .header("content-type", "multipart/form-data; boundary=XyZ")
        .body(multipart("XyZ"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let seen = up.seen();
    assert_eq!(
        seen[0].text(),
        multipart("XyZ").replace("for Ravi Kumar", "for [NAME_1]")
    );
    let ev = parda.next_event().await;
    assert_eq!(ev.unscanned, 1);

    // intercept.unscanned = "block": refused, nothing sent.
    let up2 = start_upstream(site()).await;
    let parda2 = start_parda(
        &up2,
        |c| c.intercept.unscanned = UnscannedMedia::Block,
        None,
    )
    .await;
    let res = parda2
        .client()
        .post(format!(
            "https://chatgpt.com:{}/backend-api/files",
            up2.port
        ))
        .header("content-type", "multipart/form-data; boundary=XyZ")
        .body(multipart("XyZ"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 415);
    assert!(
        res.text()
            .await
            .unwrap()
            .starts_with("parda_unscanned_blocked")
    );
    assert!(up2.seen().is_empty());
}

/// A WebSocket's frames are never read, so `unscanned = "block"` refuses the
/// upgrade before anything reaches the site.
#[tokio::test]
async fn websocket_upgrades_are_refused_when_unscanned_is_block() {
    let up = start_upstream(site()).await;
    let mut parda = start_parda(&up, |c| c.intercept.unscanned = UnscannedMedia::Block, None).await;
    let res = parda
        .client()
        .get(format!(
            "https://chatgpt.com:{}/backend-api/ws?x=1",
            up.port
        ))
        .version(http::Version::HTTP_11)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 415);
    assert!(
        res.text()
            .await
            .unwrap()
            .starts_with("parda_unscanned_blocked")
    );
    assert!(up.seen().is_empty(), "the upgrade reached the site");
    let ev = parda.next_event().await;
    assert_eq!(ev.status, 415);
    assert!(ev.refused.is_some());
}

#[test]
fn the_fake_site_answers_for_listed_hosts_only() {
    let hosts = parda_intercept::HostList::new(&SITES.map(String::from));
    for s in SITES {
        assert!(hosts.matches(s));
    }
}

#[tokio::test]
async fn a_tag_issued_for_one_site_is_not_restored_for_another() {
    let up = start_upstream(site()).await;
    let parda = start_parda(&up, |_| {}, None).await;
    let c = parda.client();
    let post = |url: String, body: &str| {
        c.post(url)
            .header("content-type", "text/plain")
            .body(body.to_string())
            .send()
    };
    let data = |body: &[u8]| -> String { events(body).iter().map(|e| e.data.clone()).collect() };
    // chatgpt.com gets [NAME_1] for Ravi Kumar, and its echo comes back real.
    let chatgpt = format!("https://chatgpt.com:{}/backend-api/f/conversation", up.port);
    let res = post(chatgpt, "I am Ravi Kumar").await.unwrap();
    assert_eq!(data(&res.bytes().await.unwrap()), "echo: I am Ravi Kumar");
    // Another site streaming that tag back gets nothing.
    let other = format!("https://example.com:{}/echo/stream", up.port);
    let res = post(other, "[NAME_1]").await.unwrap();
    assert_eq!(data(&res.bytes().await.unwrap()), "echo: [NAME_1]");
    let seen = up.seen();
    assert_eq!(seen[0].text(), "I am [NAME_1]");
    assert_eq!(seen[1].text(), "[NAME_1]");
    assert_eq!(
        parda.engine.restore("[NAME_1]", "intercept:chatgpt.com"),
        "Ravi Kumar"
    );
}

#[tokio::test]
async fn shared_pages_are_never_restored() {
    let up = start_upstream(site()).await;
    let parda = start_parda(&up, |_| {}, None).await;
    let c = parda.client();
    let base = format!("https://chatgpt.com:{}", up.port);
    // The user's own send issues the tags, and its answer is restored.
    let res = c
        .post(format!("{base}/backend-api/f/conversation"))
        .header("content-type", "text/plain")
        .body("Ravi Kumar, ravi@example.com")
        .send()
        .await
        .unwrap();
    let evs = events(&res.bytes().await.unwrap());
    assert_eq!(evs[0].data, "echo: Ravi Kumar, ravi@example.com");
    // A page someone else wrote, full of those tags, stays tags.
    let res = c
        .get(format!("{base}/backend-api/share/6f1c2a9e"))
        .send()
        .await
        .unwrap();
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["text"], "Hi [NAME_1] [EMAIL_1]");
    // So does the answer to a POST that is not a send (a GPT, a file):
    // the site echoes the tag it got, and the tag stays.
    for path in ["/backend-api/gizmos/g-1", "/echo"] {
        let res = c
            .post(format!("{base}{path}"))
            .header("content-type", "text/plain")
            .body("Ravi Kumar")
            .send()
            .await
            .unwrap();
        assert_eq!(res.text().await.unwrap(), "echo: [NAME_1]", "{path}");
    }
    // The user's own history is restored.
    let res = c
        .get(format!("{base}/backend-api/conversation/{CONV}"))
        .send()
        .await
        .unwrap();
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["title"], "Note to Ravi Kumar");
}

#[tokio::test]
async fn other_sites_get_back_streamed_answers_to_sends_only() {
    let up = start_upstream(site()).await;
    let parda = start_parda(&up, |_| {}, None).await;
    let c = parda.client();

    // DeepSeek: the streamed answer to the user's send is restored, the
    // tag split across events.
    let ds = format!(
        "https://chat.deepseek.com:{}/api/v0/chat/completion",
        up.port
    );
    let text = |body: &[u8]| -> String {
        events(body)
            .iter()
            .filter_map(|e| serde_json::from_str::<Value>(&e.data).ok())
            .filter_map(|v| v["v"].as_str().map(String::from))
            .collect()
    };
    let res = c
        .post(&ds)
        .json(&json!({"prompt": "I am Ravi Kumar"}))
        .send()
        .await
        .unwrap();
    assert_eq!(text(&res.bytes().await.unwrap()), "Hi Ravi Kumar");
    // The same stream answering a GET keeps its tags.
    let res = c.get(&ds).send().await.unwrap();
    assert_eq!(text(&res.bytes().await.unwrap()), "Hi [NAME_1]");

    // Meta AI GraphQL: a JSON document keeps its tags, even for a POST
    // (it may be anybody's content)...
    let meta = format!("https://meta.ai:{}/api/graphql/", up.port);
    let res = c
        .post(&meta)
        .json(&json!({"variables": {"message": "I am Ravi Kumar"}}))
        .send()
        .await
        .unwrap();
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["data"]["node"]["text"], "Hi [NAME_1]");
    // ...and so do values one per line under a JSON type (a GraphQL
    // document followed by `{"extensions":…}` looks just like that)...
    let res = c
        .post(&meta)
        .json(&json!({"variables": {"message": "Ravi Kumar again"}, "stream": true}))
        .send()
        .await
        .unwrap();
    let body = res.text().await.unwrap();
    let deltas: Vec<Value> = body
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(deltas[0]["delta"], "Hi [NAME_1]", "{body}");
    // ...while the same values typed as NDJSON are an answer being
    // written: restored.
    let res = c
        .post(&meta)
        .json(
            &json!({"variables": {"message": "Ravi Kumar again"}, "stream": true, "ndjson": true}),
        )
        .send()
        .await
        .unwrap();
    let body = res.text().await.unwrap();
    let deltas: Vec<Value> = body
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(deltas[0]["delta"], "Hi Ravi Kumar", "{body}");
    assert_eq!(deltas[1]["delta"], " bye", "{body}");

    let seen = up.seen();
    assert_eq!(seen.len(), 5);
    assert!(
        seen[0].text().contains("I am [NAME_1]"),
        "{}",
        seen[0].text()
    );
    assert!(
        seen[2].text().contains("I am [NAME_1]"),
        "{}",
        seen[2].text()
    );
    for r in &seen[3..] {
        assert!(r.text().contains("[NAME_1] again"), "{}", r.text());
    }
}

/// Reviewer probe (I4): a page opened as `chatgpt.com/?q=<prompt>` would
/// send the real prompt in the `Referer` of every later request, undoing the
/// query redaction. Listed hosts get the referrer without query or fragment.
#[tokio::test]
async fn referer_loses_its_query_and_fragment() {
    let up = start_upstream(site()).await;
    let parda = start_parda(&up, |_| {}, None).await;
    let c = parda.client();
    let base = format!("https://chatgpt.com:{}", up.port);
    for (referer, want) in [
        (
            "https://chatgpt.com/?q=Ravi%20Kumar%20ravi%40example.com#frag",
            "https://chatgpt.com/",
        ),
        ("https://chatgpt.com/c/x#Ravi", "https://chatgpt.com/c/x"),
        (
            "https://other.example/a?b=Ravi+Kumar",
            "https://other.example/a",
        ),
        ("https://chatgpt.com/c/x", "https://chatgpt.com/c/x"),
    ] {
        c.get(format!("{base}/echo"))
            .header("referer", referer)
            .send()
            .await
            .unwrap();
        c.post(format!("{base}/echo"))
            .header("referer", referer)
            .header("content-type", "text/plain")
            .body("hi")
            .send()
            .await
            .unwrap();
        let seen = up.seen();
        for s in &seen[seen.len() - 2..] {
            assert_eq!(s.referer.as_deref(), Some(want), "{} {referer}", s.method);
        }
    }
}
