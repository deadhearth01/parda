#![allow(dead_code)]

use std::convert::Infallible;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_TYPE};
use http::{HeaderMap, StatusCode};
use parda_core::{Config, Detection, MlDetector};
use parda_detect::{PersonBlock, RulesFile};
use parda_engine::{Engine, EngineOptions};
use parda_proxy::{ProxyEvent, ProxyState, SseEvent, parse_sse};
use serde_json::Value;
use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub struct Seen {
    pub path: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

pub enum Reply {
    Json(StatusCode, Value),
    /// (delay before sending in ms, raw SSE text)
    Sse(Vec<(u64, String)>),
    Gzip(Value),
    /// 307 redirect to the given absolute URL.
    Redirect(String),
}

pub type Responder = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

pub fn responder(f: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Responder {
    Arc::new(f)
}

pub struct Mock {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl Mock {
    pub fn last(&self) -> Seen {
        self.seen
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("mock saw a request")
    }
    pub fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

pub async fn mock(responder: Responder) -> Mock {
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let seen2 = seen.clone();
    let app = Router::new().fallback(move |req: Request| {
        let seen = seen2.clone();
        let responder = responder.clone();
        async move {
            let (parts, body) = req.into_parts();
            let bytes = to_bytes(body, usize::MAX).await.unwrap();
            let s = Seen {
                path: parts.uri.path().to_string(),
                headers: parts.headers,
                body: bytes.to_vec(),
            };
            let reply = responder(&s);
            seen.lock().unwrap().push(s);
            match reply {
                Reply::Json(status, v) => {
                    (status, [(CONTENT_TYPE, "application/json")], v.to_string()).into_response()
                }
                Reply::Sse(events) => {
                    let stream = futures::stream::unfold(events.into_iter(), |mut it| async move {
                        let (delay, text) = it.next()?;
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        Some((Ok::<_, Infallible>(Bytes::from(text)), it))
                    });
                    Response::builder()
                        .header(CONTENT_TYPE, "text/event-stream")
                        .body(Body::from_stream(stream))
                        .unwrap()
                }
                Reply::Redirect(to) => (
                    StatusCode::TEMPORARY_REDIRECT,
                    [(http::header::LOCATION, to)],
                    String::new(),
                )
                    .into_response(),
                Reply::Gzip(v) => {
                    let mut enc =
                        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                    enc.write_all(v.to_string().as_bytes()).unwrap();
                    let gz = enc.finish().unwrap();
                    Response::builder()
                        .header(CONTENT_TYPE, "application/json")
                        .header(CONTENT_ENCODING, "gzip")
                        .body(Body::from(gz))
                        .unwrap()
                }
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Mock { addr, seen }
}

pub struct Setup {
    pub _dir: tempfile::TempDir,
    pub engine: Engine,
    pub proxy: SocketAddr,
    pub events: broadcast::Receiver<ProxyEvent>,
    pub mock: Mock,
    pub client: reqwest::Client,
    pub state: Arc<ProxyState>,
}

impl Setup {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.proxy)
    }

    pub async fn post(&self, path: &str, body: &Value) -> reqwest::Response {
        self.client
            .post(self.url(path))
            .header("x-api-key", "test-key")
            .header("anthropic-version", "2023-06-01")
            .json(body)
            .send()
            .await
            .unwrap()
    }
}

/// A custom term whose real value needs JSON escaping.
pub const ADDRESS: &str = "Flat 4\\B, \"Lotus\"\nPune";

pub fn rules() -> RulesFile {
    RulesFile {
        person: vec![PersonBlock {
            name: "Ravi Kumar".into(),
            ..Default::default()
        }],
        term: vec![parda_detect::Term {
            text: ADDRESS.into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

pub async fn setup(responder: Responder) -> Setup {
    setup_with(responder, |_| {}, None).await
}

pub async fn setup_with(
    responder: Responder,
    tweak: impl FnOnce(&mut Config),
    ml: Option<Arc<dyn MlDetector>>,
) -> Setup {
    let mock = mock(responder).await;
    let mut config = Config::default();
    config.detect.model = "none".into();
    config.proxy.anthropic_upstream = format!("http://{}", mock.addr);
    config.proxy.openai_upstream = format!("http://{}", mock.addr);
    tweak(&mut config);
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        EngineOptions {
            config: config.clone(),
            rules: rules(),
            data_dir: dir.path().join("data"),
            use_keyring: false,
        },
        ml,
    )
    .unwrap();
    let (tx, rx) = broadcast::channel(64);
    let state = ProxyState::new(engine.clone(), config.proxy.clone(), tx).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let served = state.clone();
    tokio::spawn(async move { parda_proxy::serve(listener, served).await.unwrap() });
    Setup {
        _dir: dir,
        engine,
        proxy,
        events: rx,
        mock,
        client: reqwest::Client::new(),
        state,
    }
}

/// Raw SSE text for one event.
pub fn sse(event: Option<&str>, data: &Value) -> String {
    match event {
        Some(e) => format!("event: {e}\ndata: {data}\n\n"),
        None => format!("data: {data}\n\n"),
    }
}

pub fn parse_events(body: &str) -> Vec<SseEvent> {
    let mut buf = bytes::BytesMut::from(body.as_bytes());
    parse_sse(&mut buf)
}

pub struct FailingMl;

impl MlDetector for FailingMl {
    fn name(&self) -> &str {
        "failing"
    }
    fn detect_batch(&self, _texts: &[&str]) -> anyhow::Result<Vec<Vec<Detection>>> {
        anyhow::bail!("model crashed")
    }
}

/// First e-mail-looking token in `s`.
pub fn find_email(s: &str) -> String {
    s.split(|c: char| c.is_whitespace() || c == '"' || c == ',' || c == '\\')
        .find(|w| w.contains('@'))
        .unwrap_or_default()
        .trim_end_matches(['.', ')'])
        .to_string()
}
