//! What a running listener does when its owner changes it: the host list
//! follows the engine transform's configuration without a restart, and
//! `serve_with_shutdown` stops cleanly (requests in progress finish, idle
//! connections and tunnels close, the port is released).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{Reply, SITES, T, Upstream, start_upstream};
use parda_core::Config;
use parda_engine::{Engine, EngineOptions};
use parda_intercept::{
    BodyTransform, Ca, EngineTransform, HostList, InterceptState, Timeouts, serve,
    serve_with_shutdown, upstream_client_builder,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, oneshot};

struct Live {
    proxy: SocketAddr,
    ca_pem: String,
    transform: Arc<EngineTransform>,
    state: Arc<InterceptState>,
    _dir: tempfile::TempDir,
}

/// parda intercept with an engine transform listing `hosts`, in front of
/// the fake site `up`; not yet serving.
async fn live(up: &Upstream, hosts: &[&str]) -> (Live, TcpListener) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.detect.model = "none".into();
    config.intercept.hosts = hosts.iter().map(|h| h.to_string()).collect();
    let engine = Engine::open(
        EngineOptions {
            config: config.clone(),
            rules: Default::default(),
            data_dir: dir.path().join("data"),
            use_keyring: false,
        },
        None,
    )
    .unwrap();
    let transform = Arc::new(EngineTransform::new(engine, &config.intercept));
    let trusting = |b: reqwest::ClientBuilder| {
        let mut b =
            b.add_root_certificate(reqwest::Certificate::from_pem(up.ca_pem.as_bytes()).unwrap());
        for name in SITES {
            b = b.resolve(name, "127.0.0.1:0".parse().unwrap());
        }
        b.build().unwrap()
    };
    let ca = Arc::new(Ca::generate().unwrap());
    let (tx, _) = broadcast::channel(64);
    let state = Arc::new(InterceptState {
        ca: ca.clone(),
        hosts: HostList::new(&config.intercept.hosts),
        transform: transform.clone() as Arc<dyn BodyTransform>,
        events: tx,
        upstream: trusting(upstream_client_builder()),
        upstream_http1: trusting(upstream_client_builder().http1_only()),
        timeouts: Timeouts::default(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    (
        Live {
            proxy,
            ca_pem: ca.cert_pem(),
            transform,
            state,
            _dir: dir,
        },
        listener,
    )
}

impl Live {
    /// A fresh client (no pooled connections) that uses parda as its proxy
    /// and trusts only parda's CA: a tunnelled host fails its handshake.
    fn client(&self) -> reqwest::Client {
        let mut b = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{}", self.proxy)).unwrap())
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(self.ca_pem.as_bytes()).unwrap())
            .timeout(T);
        for name in SITES {
            b = b.resolve(name, "127.0.0.1:0".parse().unwrap());
        }
        b.build().unwrap()
    }

    async fn decrypted(&self, up: &Upstream, host: &str) -> bool {
        let url = format!("https://{host}:{}/api/x", up.port);
        self.client().get(url).send().await.is_ok()
    }

    async fn pac(&self) -> String {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{}/parda.pac", self.proxy))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    }

    fn set_hosts(&self, hosts: &[&str]) {
        let mut cfg = Config::default().intercept;
        cfg.hosts = hosts.iter().map(|h| h.to_string()).collect();
        self.transform.set_config(&cfg);
    }
}

fn ok_json() -> common::Responder {
    Arc::new(|_| Reply::new("application/json", vec![r#"{"ok":true}"#]))
}

#[tokio::test]
async fn host_list_follows_the_transform_without_a_restart() {
    // Unlisted hosts are tunnelled with the system resolver, so this test
    // never sends one through parda (no network): it checks the list the
    // CONNECT handler consults, the PAC, and that an added host is decrypted.
    let up = start_upstream(ok_json()).await;
    let (p, listener) = live(&up, &["chatgpt.com"]).await;
    tokio::spawn(serve(listener, p.state.clone()));

    assert!(p.decrypted(&up, "chatgpt.com").await);
    assert_eq!(p.state.listed_hosts().entries(), ["chatgpt.com"]);
    let pac = p.pac().await;
    assert!(pac.contains("\"chatgpt.com\"") && !pac.contains("example.com"));

    p.set_hosts(&["chatgpt.com", "example.com"]);
    assert!(
        p.decrypted(&up, "example.com").await,
        "added host decrypted"
    );

    p.set_hosts(&["example.com"]);
    assert_eq!(p.state.listed_hosts().entries(), ["example.com"]);
    let pac = p.pac().await;
    assert!(pac.contains("\"example.com\"") && !pac.contains("chatgpt.com"));
    // The static list still says what the listener started with.
    assert_eq!(p.state.hosts.entries(), ["chatgpt.com"]);
}

/// A plain TCP echo server; returns its port.
async fn echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

/// Read until EOF (true) or the time runs out (false).
async fn closes(s: &mut TcpStream) -> bool {
    let mut buf = [0u8; 256];
    tokio::time::timeout(T, async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn shutdown_finishes_requests_in_progress_and_closes_the_rest() {
    // A slow streamed answer: 150 chunks, a couple of ms apart.
    let up = start_upstream(Arc::new(|_| {
        Reply::new("text/plain", (0..150).map(|_| "x").collect::<Vec<_>>())
    }))
    .await;
    let (p, listener) = live(&up, &["chatgpt.com"]).await;
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(serve_with_shutdown(listener, p.state.clone(), async {
        let _ = stopped.await;
    }));

    // An idle proxy connection, and a blind tunnel to a non-listed host.
    let mut idle = TcpStream::connect(p.proxy).await.unwrap();
    let echo_port = echo().await;
    let mut tunnel = TcpStream::connect(p.proxy).await.unwrap();
    tunnel
        .write_all(
            format!(
                "CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut head = [0u8; 64];
    let n = tunnel.read(&mut head).await.unwrap();
    assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"));
    tunnel.write_all(b"ping").await.unwrap();
    let mut pong = [0u8; 4];
    tunnel.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"ping");

    // A decrypted request whose answer is still streaming.
    let res = p
        .client()
        .get(format!("https://chatgpt.com:{}/api/x", up.port))
        .send()
        .await
        .unwrap();
    stop.send(()).unwrap();
    let body = res.bytes().await.expect("the answer in progress finishes");
    assert_eq!(body.len(), 150);

    tokio::time::timeout(T, server)
        .await
        .expect("serve returns once connections are done")
        .unwrap()
        .unwrap();
    assert!(closes(&mut idle).await, "idle connection closed");
    assert!(closes(&mut tunnel).await, "tunnel closed");
    // The port is released.
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(TcpStream::connect(p.proxy).await.is_err());
    assert!(TcpListener::bind(p.proxy).await.is_ok());
}
