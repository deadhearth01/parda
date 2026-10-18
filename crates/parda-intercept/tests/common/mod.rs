//! Harness for end-to-end tests of the engine-backed intercept, with no
//! external network: a fake HTTPS "AI site" (own test CA) on 127.0.0.1 that
//! answers for chatgpt.com, claude.ai, gemini.google.com and example.com,
//! parda intercept with a real engine in front of it, and a reqwest client
//! that uses parda as its proxy.

#![allow(dead_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use parda_core::{Config, Detection, MlDetector};
use parda_detect::{PersonBlock, RulesFile};
use parda_engine::{Engine, EngineOptions};
use parda_intercept::{
    Ca, EngineTransform, HostList, InterceptEvent, InterceptState, Timeouts, serve,
    upstream_client_builder,
};
use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

pub const T: Duration = Duration::from_secs(10);

/// The names the fake site answers for.
pub const SITES: [&str; 6] = [
    "chatgpt.com",
    "claude.ai",
    "gemini.google.com",
    "chat.deepseek.com",
    "meta.ai",
    "example.com",
];

/// What the fake site received.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    pub referer: Option<String>,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A fake answer: sent as separate frames, a moment apart.
pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    /// Further `Content-Type` headers, sent after the first.
    pub more_content_types: Vec<&'static str>,
    pub chunks: Vec<Bytes>,
}

impl Reply {
    pub fn new(content_type: &'static str, chunks: Vec<impl Into<Bytes>>) -> Self {
        Reply {
            status: 200,
            content_type,
            more_content_types: Vec::new(),
            chunks: chunks.into_iter().map(Into::into).collect(),
        }
    }
}

pub type Responder = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

pub struct Upstream {
    pub port: u16,
    pub ca_pem: String,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl Upstream {
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

type Body = BoxBody<Bytes, Infallible>;

async fn handle(
    req: Request<Incoming>,
    seen: Arc<Mutex<Vec<Seen>>>,
    responder: Responder,
) -> Result<Response<Body>, Infallible> {
    let header = |n: &str| {
        req.headers()
            .get(n)
            .map(|v| v.to_str().unwrap_or("").to_string())
    };
    let mut s = Seen {
        method: req.method().to_string(),
        path: req.uri().path().to_string(),
        query: req.uri().query().map(str::to_string),
        content_type: header("content-type"),
        content_encoding: header("content-encoding"),
        referer: header("referer"),
        body: Vec::new(),
    };
    s.body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
    seen.lock().unwrap().push(s.clone());
    let reply = responder(&s);
    let frames = futures::stream::unfold(reply.chunks.into_iter(), |mut it| async move {
        let next = it.next()?;
        tokio::time::sleep(Duration::from_millis(2)).await;
        Some((Ok::<_, Infallible>(Frame::data(next)), it))
    });
    let mut res = Response::builder()
        .status(reply.status)
        .header("content-type", reply.content_type);
    for ct in reply.more_content_types {
        res = res.header("content-type", ct);
    }
    Ok(res.body(BodyExt::boxed(StreamBody::new(frames))).unwrap())
}

pub async fn start_upstream(responder: Responder) -> Upstream {
    let ca_key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::default();
    p.distinguished_name
        .push(DnType::CommonName, "fake AI site test CA");
    p.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = p.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(p, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(SITES.map(String::from).to_vec())
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
    .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, s, r) = (acceptor.clone(), s.clone(), responder.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                let svc = hyper::service::service_fn(move |req| handle(req, s.clone(), r.clone()));
                if h2 {
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                }
            });
        }
    });
    Upstream {
        port,
        ca_pem: ca_cert.pem(),
        seen,
    }
}

/// Fails every batch (strict mode refuses the send).
pub struct FailingMl;

impl MlDetector for FailingMl {
    fn name(&self) -> &str {
        "failing"
    }
    fn detect_batch(&self, _: &[&str]) -> anyhow::Result<Vec<Vec<Detection>>> {
        anyhow::bail!("model crashed")
    }
}

pub struct Parda {
    pub proxy: SocketAddr,
    pub state: Arc<InterceptState>,
    pub engine: Engine,
    pub events: broadcast::Receiver<InterceptEvent>,
    _dir: tempfile::TempDir,
}

impl Parda {
    /// A client that uses parda as its proxy and trusts only parda's CA.
    pub fn client(&self) -> reqwest::Client {
        let mut b = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{}", self.proxy)).unwrap())
            .redirect(reqwest::redirect::Policy::none())
            .tls_built_in_root_certs(false)
            .add_root_certificate(
                reqwest::Certificate::from_pem(self.state.ca.cert_pem().as_bytes()).unwrap(),
            )
            .timeout(T);
        for name in SITES {
            b = b.resolve(name, "127.0.0.1:0".parse().unwrap());
        }
        b.build().unwrap()
    }

    pub async fn next_event(&mut self) -> InterceptEvent {
        tokio::time::timeout(T, self.events.recv())
            .await
            .unwrap()
            .unwrap()
    }
}

/// parda intercept listing the fake site's names, with an engine that knows
/// "Ravi Kumar" (rules only, unless `ml`).
pub async fn start_parda(
    up: &Upstream,
    tweak: impl FnOnce(&mut Config),
    ml: Option<Arc<dyn MlDetector>>,
) -> Parda {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.detect.model = "none".into();
    config.intercept.hosts = SITES.map(String::from).to_vec();
    tweak(&mut config);
    let engine = Engine::open(
        EngineOptions {
            config: config.clone(),
            rules: RulesFile {
                person: vec![PersonBlock {
                    name: "Ravi Kumar".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            data_dir: dir.path().join("data"),
            use_keyring: false,
        },
        ml,
    )
    .unwrap();
    let transform = EngineTransform::new(engine.clone(), &config.intercept);
    let trusting = |b: reqwest::ClientBuilder| {
        let mut b =
            b.add_root_certificate(reqwest::Certificate::from_pem(up.ca_pem.as_bytes()).unwrap());
        for name in SITES {
            b = b.resolve(name, "127.0.0.1:0".parse().unwrap());
        }
        b.build().unwrap()
    };
    let (tx, rx) = broadcast::channel(64);
    let state = Arc::new(InterceptState {
        ca: Arc::new(Ca::generate().unwrap()),
        hosts: HostList::new(&config.intercept.hosts),
        transform: Arc::new(transform),
        events: tx,
        upstream: trusting(upstream_client_builder()),
        upstream_http1: trusting(upstream_client_builder().http1_only()),
        timeouts: Timeouts::default(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, state.clone()));
    Parda {
        proxy,
        state,
        engine,
        events: rx,
        _dir: dir,
    }
}
