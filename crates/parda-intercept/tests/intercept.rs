//! End-to-end tests of the intercept transport, with no external network: a
//! fake upstream HTTPS server (own test CA) on 127.0.0.1, parda intercept in
//! front of it, and reqwest clients that use parda as their proxy.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use parda_intercept::{
    BodyTransform, Ca, HostList, InterceptEvent, InterceptState, Refusal, StreamTransform,
    Timeouts, pac, serve, upstream_client_builder,
};
use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

const T: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------- test PKI

/// A throwaway CA plus one server certificate for `names`, signed by it.
struct TestPki {
    ca_pem: String,
    leaf_der: CertificateDer<'static>,
    server: Arc<rustls::ServerConfig>,
}

fn test_pki(names: &[&str]) -> TestPki {
    let ca_key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::default();
    p.distinguished_name
        .push(DnType::CommonName, "fake upstream test CA");
    p.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = p.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(p, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    let leaf = CertificateParams::new(names)
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
    // Like real AI sites: HTTP/2 preferred, HTTP/1.1 offered.
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    TestPki {
        ca_pem: ca_cert.pem(),
        leaf_der: leaf.der().clone(),
        server: Arc::new(server),
    }
}

// ------------------------------------------------------- fake upstream site

#[derive(Debug, Clone)]
struct Seen {
    path: String,
    body: String,
    host: String,
    version: http::Version,
}

struct Upstream {
    port: u16,
    ca_pem: String,
    leaf_der: CertificateDer<'static>,
    seen: Arc<Mutex<Vec<Seen>>>,
    sse_done: Arc<AtomicBool>,
}

type Body = BoxBody<Bytes, Infallible>;

fn full(s: impl Into<Bytes>) -> Body {
    Full::new(s.into()).boxed()
}

async fn upstream_handle(
    mut req: Request<Incoming>,
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    sse_done: Arc<AtomicBool>,
) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path().to_string();
    // HTTP/2 carries the authority in the URI, HTTP/1.1 in Host.
    let host = match req.uri().authority() {
        Some(a) => a.to_string(),
        None => req
            .headers()
            .get("host")
            .map(|h| h.to_str().unwrap().to_string())
            .unwrap_or_default(),
    };
    let version = req.version();
    if path == "/ws" {
        seen.lock().unwrap().push(Seen {
            path,
            body: String::new(),
            host,
            version,
        });
        if req.version() == http::Version::HTTP_2 {
            // No 101 in HTTP/2: the upgrade headers never even arrive.
            return Ok(Response::builder()
                .status(400)
                .body(full("no upgrade over h2"))
                .unwrap());
        }
        let on_upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let mut io = TokioIo::new(on_upgrade.await.unwrap());
            let mut buf = [0u8; 1024];
            loop {
                let n = io.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                io.write_all(&buf[..n]).await.unwrap();
            }
        });
        return Ok(Response::builder()
            .status(101)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-accept", "test-accept")
            .body(full(""))
            .unwrap());
    }
    let body = req.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    seen.lock().unwrap().push(Seen {
        path: path.clone(),
        body: body.clone(),
        host,
        version,
    });
    match path.as_str() {
        "/redirect" => Ok(Response::builder()
            .status(302)
            .header("location", format!("https://other.test:{port}/x"))
            .body(full(""))
            .unwrap()),
        "/sse" => {
            let events = futures::stream::unfold(0u8, move |step| {
                let sse_done = sse_done.clone();
                async move {
                    match step {
                        0 => Some((Bytes::from("data: hello SECRET one\n\n"), 1)),
                        1 => {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            sse_done.store(true, Ordering::SeqCst);
                            Some((Bytes::from("data: two SECRET\n\n"), 2))
                        }
                        _ => None,
                    }
                }
            })
            .map(|b| Ok::<_, Infallible>(Frame::data(b)));
            Ok(Response::builder()
                .header("content-type", "text/event-stream")
                .body(BodyExt::boxed(StreamBody::new(events)))
                .unwrap())
        }
        _ => Ok(Response::builder()
            .header("content-type", "text/plain")
            .body(full(format!("echo: {body}")))
            .unwrap()),
    }
}

async fn start_upstream(pki: TestPki) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sse_done = Arc::new(AtomicBool::new(false));
    let acceptor = tokio_rustls::TlsAcceptor::from(pki.server.clone());
    let (s, d) = (seen.clone(), sse_done.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let (acceptor, s, d) = (acceptor.clone(), s.clone(), d.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                let svc = hyper::service::service_fn(move |req| {
                    upstream_handle(req, port, s.clone(), d.clone())
                });
                if h2 {
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .with_upgrades()
                        .await;
                }
            });
        }
    });
    Upstream {
        port,
        ca_pem: pki.ca_pem,
        leaf_der: pki.leaf_der,
        seen,
        sse_done,
    }
}

// ------------------------------------------------------------ test transform

/// Request: "secret" → "SECRET" (refuses bodies containing "refuse-me").
/// Response: "SECRET" → "secret", holding back a possible split match.
struct Upper;

impl BodyTransform for Upper {
    fn request(
        &self,
        _host: &str,
        _path: &str,
        _headers: &http::HeaderMap,
        body: Bytes,
    ) -> Result<Bytes, Refusal> {
        let s = String::from_utf8_lossy(&body);
        if s.contains("refuse-me") {
            return Err(Refusal {
                status: 451,
                message: "blocked by test transform".into(),
            });
        }
        Ok(Bytes::from(s.replace("secret", "SECRET")))
    }

    fn response_stream(
        &self,
        _host: &str,
        _path: &str,
        _content_type: &str,
    ) -> Box<dyn StreamTransform> {
        Box::new(Lower::default())
    }
}

#[derive(Default)]
struct Lower {
    carry: Vec<u8>,
}

impl StreamTransform for Lower {
    fn push(&mut self, chunk: &[u8]) -> Bytes {
        const PAT: &[u8] = b"SECRET";
        self.carry.extend_from_slice(chunk);
        let text = String::from_utf8_lossy(&self.carry).replace("SECRET", "secret");
        let mut out = text.into_bytes();
        // Keep the longest tail that could start a split "SECRET".
        let keep = (1..PAT.len())
            .rev()
            .find(|&k| out.len() >= k && out.ends_with(&PAT[..k]))
            .unwrap_or(0);
        self.carry = out.split_off(out.len() - keep);
        Bytes::from(out)
    }

    fn finish(&mut self) -> Bytes {
        Bytes::from(std::mem::take(&mut self.carry))
    }
}

// ------------------------------------------------------------------ harness

struct Harness {
    proxy: SocketAddr,
    state: Arc<InterceptState>,
    events: broadcast::Receiver<InterceptEvent>,
}

/// parda's own upstream client builder, plus trust in the fake site's CA
/// and the test names resolved to 127.0.0.1.
fn test_upstream(builder: reqwest::ClientBuilder, upstream_ca_pem: &str) -> reqwest::Client {
    builder
        .add_root_certificate(reqwest::Certificate::from_pem(upstream_ca_pem.as_bytes()).unwrap())
        .resolve("chat.test", "127.0.0.1:0".parse().unwrap())
        .resolve("other.test", "127.0.0.1:0".parse().unwrap())
        .build()
        .unwrap()
}

/// State for parda intercept listing `chat.test`.
fn state_for(
    upstream_ca_pem: &str,
    timeouts: Timeouts,
) -> (InterceptState, broadcast::Receiver<InterceptEvent>) {
    let (tx, rx) = broadcast::channel(64);
    let state = InterceptState {
        ca: Arc::new(Ca::generate().unwrap()),
        hosts: HostList::new(&["chat.test".to_string()]),
        transform: Arc::new(Upper),
        events: tx,
        upstream: test_upstream(upstream_client_builder(), upstream_ca_pem),
        upstream_http1: test_upstream(upstream_client_builder().http1_only(), upstream_ca_pem),
        timeouts,
    };
    (state, rx)
}

async fn start_parda(upstream_ca_pem: &str) -> Harness {
    start_parda_with(upstream_ca_pem, Timeouts::default()).await
}

async fn start_parda_with(upstream_ca_pem: &str, timeouts: Timeouts) -> Harness {
    let (state, rx) = state_for(upstream_ca_pem, timeouts);
    let state = Arc::new(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, state.clone()));
    Harness {
        proxy,
        state,
        events: rx,
    }
}

/// A client that uses parda as its proxy, trusts exactly `ca_pem` and does
/// not follow redirects.
fn client(proxy: SocketAddr, ca_pem: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{proxy}")).unwrap())
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .resolve("chat.test", "127.0.0.1:0".parse().unwrap())
        .resolve("other.test", "127.0.0.1:0".parse().unwrap())
        .timeout(T)
        .build()
        .unwrap()
}

/// The certificate a client sees for `name:port` through parda (reqwest does
/// not report TLS info for proxied connections, so do the handshake here).
async fn peer_cert(proxy: SocketAddr, name: &str, port: u16, ca_pem: &str) -> Vec<u8> {
    let tls = tokio::time::timeout(
        T,
        tls_via_connect(
            proxy,
            &format!("{name}:{port}"),
            ca_pem,
            ServerName::try_from(name.to_string()).unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    tls.get_ref().1.peer_certificates().unwrap()[0].to_vec()
}

async fn next_event(rx: &mut broadcast::Receiver<InterceptEvent>) -> InterceptEvent {
    tokio::time::timeout(T, rx.recv()).await.unwrap().unwrap()
}

// -------------------------------------------------------------------- tests

#[tokio::test]
async fn listed_host_is_decrypted_transformed_and_restored() {
    let up = start_upstream(test_pki(&["chat.test", "localhost"])).await;
    let mut h = start_parda(&up.ca_pem).await;
    let c = client(h.proxy, &h.state.ca.cert_pem());

    let res = c
        .post(format!("https://chat.test:{}/echo?q=1", up.port))
        .body("my secret plan")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "echo: my secret plan");
    // The client talks TLS with parda's leaf for chat.test, not the site's.
    let seen_cert = peer_cert(h.proxy, "chat.test", up.port, &h.state.ca.cert_pem()).await;
    assert_eq!(
        seen_cert,
        h.state.ca.leaf_for("chat.test").unwrap().cert[0].to_vec()
    );
    assert_ne!(seen_cert, up.leaf_der.to_vec());

    let seen = up.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/echo");
    assert_eq!(seen[0].body, "my SECRET plan");
    assert_eq!(seen[0].host, format!("chat.test:{}", up.port));
    // parda talks HTTP/2 to sites that offer it.
    assert_eq!(seen[0].version, http::Version::HTTP_2);

    let ev = next_event(&mut h.events).await;
    assert_eq!(ev.host, "chat.test");
    assert_eq!(ev.path, "/echo");
    assert_eq!(ev.status, 200);
    assert_eq!(ev.refused, None);
    assert_eq!(ev.unscanned, 0);
}

#[tokio::test]
async fn unlisted_host_is_tunnelled_byte_for_byte() {
    // `localhost` is not listed. The tunnel resolves names with the system
    // resolver, so the test uses a name that resolves without a network.
    let up = start_upstream(test_pki(&["chat.test", "localhost"])).await;
    let h = start_parda(&up.ca_pem).await;

    // Trusting only parda's CA fails: parda never terminates this TLS.
    let only_parda = client(h.proxy, &h.state.ca.cert_pem());
    let err = only_parda
        .post(format!("https://localhost:{}/echo", up.port))
        .body("my secret plan")
        .send()
        .await;
    assert!(
        err.is_err(),
        "parda must not hold a cert for unlisted hosts"
    );

    // Trusting only the site's own CA succeeds: a blind tunnel.
    let only_site = client(h.proxy, &up.ca_pem);
    let res = only_site
        .post(format!("https://localhost:{}/echo", up.port))
        .body("my secret plan")
        .send()
        .await
        .unwrap();
    assert_eq!(res.text().await.unwrap(), "echo: my secret plan");
    let seen = up.seen.lock().unwrap().clone();
    assert_eq!(seen.last().unwrap().body, "my secret plan");
    // The client sees the site's own certificate.
    assert_eq!(
        peer_cert(h.proxy, "localhost", up.port, &up.ca_pem).await,
        up.leaf_der.to_vec()
    );
}

#[tokio::test]
async fn unreachable_unlisted_host_gets_502_on_connect() {
    let up = start_upstream(test_pki(&["localhost"])).await;
    let h = start_parda(&up.ca_pem).await;
    // A port nothing listens on.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let mut tcp = TcpStream::connect(h.proxy).await.unwrap();
    tcp.write_all(
        format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(T, tcp.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
}

#[tokio::test]
async fn refusal_reaches_the_client_and_nothing_goes_upstream() {
    let up = start_upstream(test_pki(&["chat.test"])).await;
    let mut h = start_parda(&up.ca_pem).await;
    let c = client(h.proxy, &h.state.ca.cert_pem());
    let res = c
        .post(format!("https://chat.test:{}/echo", up.port))
        .body("please refuse-me")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 451);
    assert!(
        res.text()
            .await
            .unwrap()
            .contains("blocked by test transform")
    );
    assert!(up.seen.lock().unwrap().is_empty());
    let ev = next_event(&mut h.events).await;
    assert_eq!(ev.status, 451);
    assert_eq!(ev.refused.as_deref(), Some("blocked by test transform"));
}

#[tokio::test]
async fn sse_streams_without_waiting_for_the_upstream_to_finish() {
    let up = start_upstream(test_pki(&["chat.test"])).await;
    let h = start_parda(&up.ca_pem).await;
    let c = client(h.proxy, &h.state.ca.cert_pem());
    let mut res = c
        .get(format!("https://chat.test:{}/sse", up.port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers()["content-type"].to_str().unwrap(),
        "text/event-stream"
    );
    let first = res.chunk().await.unwrap().unwrap();
    assert!(
        !up.sse_done.load(Ordering::SeqCst),
        "first event arrived only after the upstream finished"
    );
    assert_eq!(&first[..], b"data: hello secret one\n\n");
    let mut rest = Vec::new();
    while let Some(chunk) = res.chunk().await.unwrap() {
        rest.extend_from_slice(&chunk);
    }
    assert_eq!(String::from_utf8(rest).unwrap(), "data: two secret\n\n");
}

#[tokio::test]
async fn pac_is_served_and_other_plain_requests_are_refused() {
    let up = start_upstream(test_pki(&["chat.test"])).await;
    let h = start_parda(&up.ca_pem).await;
    let plain = reqwest::Client::builder()
        .no_proxy()
        .timeout(T)
        .build()
        .unwrap();
    let res = plain
        .get(format!("http://{}/parda.pac", h.proxy))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers()["content-type"].to_str().unwrap(),
        "application/x-ns-proxy-autoconfig"
    );
    let text = res.text().await.unwrap();
    assert_eq!(text, pac(&h.state.hosts, h.proxy));
    assert!(text.contains("\"chat.test\""));
    assert!(text.contains(&format!("PROXY 127.0.0.1:{}", h.proxy.port())));

    // Anything else in plain HTTP is not proxied.
    let res = plain
        .get(format!("http://{}/other", h.proxy))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 405);
    let via_proxy = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", h.proxy)).unwrap())
        .timeout(T)
        .build()
        .unwrap();
    // Plain http for an unlisted host is not proxied (listed hosts are
    // redirected to https: see plain_http_to_a_listed_host_is_redirected).
    let res = via_proxy
        .get("http://example.test/echo")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 405);
    assert!(up.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn untrusted_upstream_certificate_gives_502() {
    // parda's upstream client trusts `trusted`, but the site presents a
    // certificate from another CA.
    let trusted = test_pki(&["chat.test"]);
    let up = start_upstream(test_pki(&["chat.test"])).await;
    let mut h = start_parda(&trusted.ca_pem).await;
    let c = client(h.proxy, &h.state.ca.cert_pem());
    let res = c
        .post(format!("https://chat.test:{}/echo", up.port))
        .body("my secret plan")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);
    assert!(up.seen.lock().unwrap().is_empty());
    assert_eq!(next_event(&mut h.events).await.status, 502);
}

#[tokio::test]
async fn host_header_must_match_the_connect_target() {
    let up = start_upstream(test_pki(&["chat.test", "other.test"])).await;
    let h = start_parda(&up.ca_pem).await;
    let c = client(h.proxy, &h.state.ca.cert_pem());
    let res = c
        .post(format!("https://chat.test:{}/echo", up.port))
        .header("host", format!("other.test:{}", up.port))
        .body("my secret plan")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 421);
    assert!(up.seen.lock().unwrap().is_empty());
}

/// Read one response head (up to the blank line).
async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut b = [0u8; 1];
        tokio::time::timeout(T, s.read_exact(&mut b))
            .await
            .unwrap()
            .unwrap();
        head.push(b[0]);
    }
    String::from_utf8(head).unwrap()
}

/// A CONNECT tunnel to `target` through parda.
async fn connect_tunnel(proxy: SocketAddr, target: &str) -> TcpStream {
    let mut tcp = TcpStream::connect(proxy).await.unwrap();
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = read_head(&mut tcp).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    tcp
}

/// The peer closes `s` within the test timeout.
async fn closes<S: AsyncRead + Unpin>(s: &mut S, what: &str) {
    let mut sink = Vec::new();
    let r = tokio::time::timeout(T, s.read_to_end(&mut sink)).await;
    assert!(r.is_ok(), "{what}: connection was not closed");
}

/// Open a CONNECT tunnel to `target` through parda and start TLS with `sni`.
async fn tls_via_connect(
    proxy: SocketAddr,
    target: &str,
    ca_pem: &str,
    sni: ServerName<'static>,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = connect_tunnel(proxy, target).await;
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(sni, tcp)
        .await
}

#[tokio::test]
async fn sni_must_match_the_connect_target() {
    let up = start_upstream(test_pki(&["chat.test"])).await;
    let h = start_parda(&up.ca_pem).await;
    let ca = h.state.ca.cert_pem();
    let target = format!("chat.test:{}", up.port);
    // Matching SNI works (and offers http/1.1 only).
    let ok = tokio::time::timeout(
        T,
        tls_via_connect(
            h.proxy,
            &target,
            &ca,
            ServerName::try_from("chat.test").unwrap(),
        ),
    )
    .await
    .unwrap();
    assert!(ok.is_ok());
    // A different listed-looking name is refused.
    let other = tokio::time::timeout(
        T,
        tls_via_connect(
            h.proxy,
            &target,
            &ca,
            ServerName::try_from("x.chat.test").unwrap(),
        ),
    )
    .await
    .unwrap();
    assert!(other.is_err());
    // No SNI at all (an IP server name sends none) is refused.
    let none = tokio::time::timeout(
        T,
        tls_via_connect(
            h.proxy,
            &target,
            &ca,
            ServerName::IpAddress("127.0.0.1".parse::<std::net::IpAddr>().unwrap().into()),
        ),
    )
    .await
    .unwrap();
    assert!(none.is_err());
}

#[tokio::test]
async fn websocket_upgrade_is_relayed_and_tunnelled_unscanned() {
    let up = start_upstream(test_pki(&["chat.test"])).await;
    let mut h = start_parda(&up.ca_pem).await;
    let c = client(h.proxy, &h.state.ca.cert_pem());
    let res = c
        .get(format!("https://chat.test:{}/ws", up.port))
        .version(http::Version::HTTP_11)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 101);
    assert_eq!(res.headers()["sec-websocket-accept"], "test-accept");
    let mut io = res.upgrade().await.unwrap();
    // Raw bytes both ways, untouched (no transform on upgraded streams).
    io.write_all(b"ping secret").await.unwrap();
    let mut buf = [0u8; 11];
    tokio::time::timeout(T, io.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"ping secret");
    let ev = next_event(&mut h.events).await;
    assert_eq!(ev.path, "/ws");
    assert_eq!(ev.status, 101);
    assert_eq!(ev.unscanned, 1);
    // The h2-capable site was asked over HTTP/1.1, where 101 exists.
    let seen = up.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].version, http::Version::HTTP_11);
}

#[tokio::test]
async fn upstream_redirects_are_relayed_not_followed() {
    let up = start_upstream(test_pki(&["chat.test", "other.test"])).await;
    let h = start_parda(&up.ca_pem).await;
    let c = client(h.proxy, &h.state.ca.cert_pem());
    let res = c
        .get(format!("https://chat.test:{}/redirect", up.port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 302);
    assert_eq!(
        res.headers()["location"].to_str().unwrap(),
        format!("https://other.test:{}/x", up.port)
    );
    let paths: Vec<String> = up
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.path.clone())
        .collect();
    assert_eq!(paths, ["/redirect"], "parda must not follow the redirect");
}

#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "binding 0.0.0.0 can raise the macOS firewall prompt; the address check is unit-tested"
)]
async fn serve_refuses_a_non_loopback_listener() {
    let pki = test_pki(&["chat.test"]);
    let (state, _rx) = state_for(&pki.ca_pem, Timeouts::default());
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let r = tokio::time::timeout(T, serve(listener, Arc::new(state)))
        .await
        .expect("serve must return at once");
    assert!(r.is_err());
}

#[tokio::test]
async fn pac_endpoint_refuses_foreign_hosts_and_origins() {
    let up = start_upstream(test_pki(&["chat.test"])).await;
    let h = start_parda(&up.ca_pem).await;
    let plain = reqwest::Client::builder()
        .no_proxy()
        .timeout(T)
        .build()
        .unwrap();
    let url = format!("http://{}/parda.pac", h.proxy);
    let ok = plain.get(&url).send().await.unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(ok.headers()["x-content-type-options"], "nosniff");
    assert_eq!(ok.headers()["cross-origin-resource-policy"], "same-origin");
    let ok = plain
        .get(&url)
        .header("host", format!("localhost:{}", h.proxy.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    // DNS rebinding: a page on evil.example resolving to 127.0.0.1.
    let rebound = plain
        .get(&url)
        .header("host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(rebound.status(), 403);
    // Any cross-origin fetch from a web page.
    let cross = plain
        .get(&url)
        .header("origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(cross.status(), 403);
}

#[tokio::test]
async fn request_targets_must_be_origin_or_absolute_form() {
    let up = start_upstream(test_pki(&["chat.test"])).await;
    let h = start_parda(&up.ca_pem).await;
    let target = format!("chat.test:{}", up.port);
    let mut tls = tokio::time::timeout(
        T,
        tls_via_connect(
            h.proxy,
            &target,
            &h.state.ca.cert_pem(),
            ServerName::try_from("chat.test").unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    tls.write_all(format!("OPTIONS * HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = read_head(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
    assert!(up.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn slow_and_idle_clients_are_disconnected() {
    let up = start_upstream(test_pki(&["chat.test"])).await;
    let short = Duration::from_millis(300);
    let h = start_parda_with(
        &up.ca_pem,
        Timeouts {
            tls_handshake: short,
            header_read: short,
            idle: short,
            body_read: short,
        },
    )
    .await;
    let target = format!("chat.test:{}", up.port);
    // Proxy side: connected, never sends a request.
    let mut tcp = TcpStream::connect(h.proxy).await.unwrap();
    closes(&mut tcp, "no request").await;
    // CONNECT accepted, never starts TLS.
    let mut tcp = connect_tunnel(h.proxy, &target).await;
    closes(&mut tcp, "no TLS handshake").await;
    // Decrypted connection that stays idle.
    let mut tls = tls_via_connect(
        h.proxy,
        &target,
        &h.state.ca.cert_pem(),
        ServerName::try_from("chat.test").unwrap(),
    )
    .await
    .unwrap();
    closes(&mut tls, "idle decrypted connection").await;
    // A request body that trickles (10 of 100 bytes, then nothing): 408,
    // and nothing goes upstream.
    let mut tls = tls_via_connect(
        h.proxy,
        &target,
        &h.state.ca.cert_pem(),
        ServerName::try_from("chat.test").unwrap(),
    )
    .await
    .unwrap();
    tls.write_all(
        format!("POST /echo HTTP/1.1\r\nHost: {target}\r\nContent-Length: 100\r\n\r\n0123456789")
            .as_bytes(),
    )
    .await
    .unwrap();
    let head = read_head(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 408"), "{head}");
    assert!(up.seen.lock().unwrap().is_empty());
    // A streamed answer that pauses longer than the idle timeout (500 ms
    // between events) is not cut: the timer only runs between requests.
    let c = client(h.proxy, &h.state.ca.cert_pem());
    let body = c
        .get(format!("https://chat.test:{}/sse", up.port))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, "data: hello secret one\n\ndata: two secret\n\n");
}

#[tokio::test]
async fn plain_http_to_a_listed_host_is_redirected_to_https() {
    let up = start_upstream(test_pki(&["chat.test"])).await;
    let h = start_parda(&up.ca_pem).await;
    let via_proxy = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", h.proxy)).unwrap())
        .redirect(reqwest::redirect::Policy::none())
        .timeout(T)
        .build()
        .unwrap();
    let res = via_proxy
        .post("http://chat.test/x?q=1")
        .body("my secret plan")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 308);
    assert_eq!(res.headers()["location"], "https://chat.test/x?q=1");
    let res = via_proxy
        .get(format!("http://CHAT.test:{}/y", up.port))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 308);
    assert_eq!(
        res.headers()["location"].to_str().unwrap(),
        format!("https://chat.test:{}/y", up.port)
    );
    assert!(up.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ws_connect_to_a_listed_host_on_port_80_is_refused() {
    let up = start_upstream(test_pki(&["chat.test"])).await;
    let h = start_parda(&up.ca_pem).await;
    let mut tcp = TcpStream::connect(h.proxy).await.unwrap();
    tcp.write_all(b"CONNECT chat.test:80 HTTP/1.1\r\nHost: chat.test:80\r\n\r\n")
        .await
        .unwrap();
    let head = read_head(&mut tcp).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
}
