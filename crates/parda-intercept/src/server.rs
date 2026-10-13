//! The CONNECT proxy: tunnels unlisted hosts byte-for-byte, terminates TLS
//! for listed ones and forwards their requests through the body transform.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use http::header::{
    ACCEPT_ENCODING, ALLOW, CACHE_CONTROL, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH,
    CONTENT_TYPE, HOST, ORIGIN, UPGRADE, X_CONTENT_TYPE_OPTIONS,
};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full, LengthLimitError, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::Serialize;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;

use crate::transform::RequestOutcome;
use crate::{BodyTransform, Ca, HostList, StreamTransform, pac};

/// Request bodies to listed hosts are read whole, up to this size (else 413).
pub const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;
/// How long a tunnel to an unlisted host may take to connect.
const TUNNEL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = UnsyncBoxBody<Bytes, BoxError>;

static PROVIDER: LazyLock<Arc<CryptoProvider>> =
    LazyLock::new(|| Arc::new(rustls::crypto::ring::default_provider()));

/// One request to a listed host, for the event feed. Never holds values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InterceptEvent {
    pub host: String,
    /// Path only; the query string is never recorded.
    pub path: String,
    pub status: u16,
    /// Replacements by kind in the request.
    pub counts: BTreeMap<String, u32>,
    /// Time parda itself spent on the request body.
    pub added_ms: u64,
    /// Why the transform refused the request, if it did.
    pub refused: Option<String>,
    /// Parts forwarded without scanning (media, WebSocket streams).
    pub unscanned: u32,
}

/// Everything a running intercept listener needs.
pub struct InterceptState {
    pub ca: Arc<Ca>,
    pub hosts: HostList,
    pub transform: Arc<dyn BodyTransform>,
    pub events: broadcast::Sender<InterceptEvent>,
    /// Client for the real servers. Must keep certificate verification on.
    pub upstream: reqwest::Client,
    /// HTTP/1.1-only client for upgrade (WebSocket) requests.
    pub upstream_http1: reqwest::Client,
    pub timeouts: Timeouts,
}

impl InterceptState {
    /// State with parda's own upstream clients ([`upstream_client_builder`])
    /// and default timeouts.
    pub fn new(
        ca: Arc<Ca>,
        hosts: HostList,
        transform: Arc<dyn BodyTransform>,
        events: broadcast::Sender<InterceptEvent>,
    ) -> anyhow::Result<InterceptState> {
        Ok(InterceptState {
            ca,
            hosts,
            transform,
            events,
            upstream: upstream_client_builder().build()?,
            upstream_http1: upstream_client_builder().http1_only().build()?,
            timeouts: Timeouts::default(),
        })
    }
}

/// Connection timeouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Client TLS handshake on a decrypted tunnel.
    pub tls_handshake: Duration,
    /// Waiting for a request head on the proxy-facing side (CONNECT, PAC).
    pub header_read: Duration,
    /// A decrypted connection waiting for its next request is closed after this.
    pub idle: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            tls_handshake: Duration::from_secs(10),
            header_read: Duration::from_secs(30),
            idle: Duration::from_secs(90),
        }
    }
}

/// How long connecting to a real server may take.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest silence between two reads from a real server. Per read, not per
/// response: a streamed answer may run for minutes.
const UPSTREAM_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// The builder for parda's upstream clients. Callers may add roots or DNS
/// overrides (tests do) but should not loosen it:
///
/// - redirects are never followed: a 3xx from an AI host is relayed to the
///   browser, which judges it under the right origin (following it here
///   would fetch another site under the AI site's origin, with its headers);
/// - no proxy (an `HTTPS_PROXY` pointing at parda would loop) and https only;
/// - certificates verified against the webpki (Mozilla) roots built into
///   reqwest, never the OS store, so parda's own CA, once trusted by the
///   OS, is never trusted for upstream connections. (The workspace must keep
///   reqwest's native-roots features off.)
/// - connect and per-read timeouts, but no total timeout (it would cut
///   long event streams).
pub fn upstream_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .https_only(true)
        .tls_built_in_root_certs(true)
        .connect_timeout(UPSTREAM_CONNECT_TIMEOUT)
        .read_timeout(UPSTREAM_READ_TIMEOUT)
}

/// Serve the proxy on `listener`, which must be bound to a loopback address
/// (anything else is refused); connections from non-loopback peers are
/// dropped.
///
/// - `CONNECT host:port` to a listed host: TLS is terminated with a leaf from
///   the parda CA (SNI must equal the CONNECT host; ALPN `http/1.1` only) and
///   each request is forwarded through the transform.
/// - `CONNECT` to any other host: a blind byte tunnel.
/// - Plain `GET /parda.pac`: the PAC file. Any other plain request: 405.
pub async fn serve(listener: TcpListener, state: Arc<InterceptState>) -> anyhow::Result<()> {
    let local = listener.local_addr()?;
    anyhow::ensure!(
        is_loopback(local.ip()),
        "parda intercept must listen on a loopback address, not {local}"
    );
    loop {
        let tcp = match listener.accept().await {
            Ok((tcp, peer)) if is_loopback(peer.ip()) => tcp,
            Ok((_, peer)) => {
                tracing::warn!(%peer, "intercept: dropped a non-loopback client");
                continue;
            }
            Err(e) => {
                // E.g. out of file descriptors: back off instead of spinning.
                tracing::warn!(error = %e, "intercept: accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _ = tcp.set_nodelay(true);
            let svc = service_fn(move |req| front(req, state.clone(), local));
            if let Err(e) = http1::Builder::new()
                .serve_connection(TokioIo::new(tcp), svc)
                .with_upgrades()
                .await
            {
                tracing::debug!(error = %e, "intercept: client connection ended");
            }
        });
    }
}

/// A request on the plain (proxy-facing) side of the listener.
async fn front(
    req: Request<Incoming>,
    state: Arc<InterceptState>,
    local: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    if req.method() == Method::CONNECT {
        return Ok(connect(req, state).await);
    }
    if req.method() == Method::GET && req.uri().path() == "/parda.pac" && is_local(req.uri()) {
        // The OS fetches the PAC with Host 127.0.0.1/localhost and no Origin.
        // Refuse web pages: cross-origin fetches carry an Origin, and a
        // DNS-rebound page carries its own host name.
        let host_ok = req
            .headers()
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.parse::<http::uri::Authority>().ok())
            .is_some_and(|a| is_local_host(a.host()));
        if !host_ok || req.headers().contains_key(ORIGIN) {
            return Ok(text(
                StatusCode::FORBIDDEN,
                "parda intercept: the PAC file is for this machine's proxy settings only\n",
            ));
        }
        let mut res = Response::new(full(pac(&state.hosts, local)));
        let h = res.headers_mut();
        h.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-ns-proxy-autoconfig"),
        );
        h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        h.insert(
            "cross-origin-resource-policy",
            HeaderValue::from_static("same-origin"),
        );
        return Ok(res);
    }
    let mut res = text(
        StatusCode::METHOD_NOT_ALLOWED,
        "parda intercept only serves CONNECT and GET /parda.pac\n",
    );
    res.headers_mut()
        .insert(ALLOW, HeaderValue::from_static("CONNECT, GET"));
    Ok(res)
}

/// Origin-form, or absolute-form naming this machine.
fn is_local(uri: &http::Uri) -> bool {
    uri.host().is_none_or(is_local_host)
}

/// `localhost` or a loopback IP literal.
fn is_local_host(h: &str) -> bool {
    let h = h.trim_start_matches('[').trim_end_matches(']');
    h.eq_ignore_ascii_case("localhost") || h.parse::<std::net::IpAddr>().is_ok_and(is_loopback)
}

async fn connect(req: Request<Incoming>, state: Arc<InterceptState>) -> Response<Body> {
    let Some(authority) = req.uri().authority().cloned() else {
        return text(StatusCode::BAD_REQUEST, "CONNECT needs host:port\n");
    };
    let host = normalize_host(authority.host());
    let port = authority.port_u16().unwrap_or(443);

    if state.hosts.matches(&host) {
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(io) => intercept_tls(TokioIo::new(io), host, port, state).await,
                Err(e) => tracing::debug!(error = %e, "intercept: CONNECT upgrade failed"),
            }
        });
        return empty(StatusCode::OK);
    }

    // Not an AI host: a blind tunnel. parda never sees its plaintext.
    // Connect first so that an unreachable host is a 502, not a dead tunnel.
    let upstream = match tokio::time::timeout(
        TUNNEL_CONNECT_TIMEOUT,
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            return text(
                StatusCode::BAD_GATEWAY,
                &format!("parda intercept: cannot reach {host}:{port}\n"),
            );
        }
    };
    tokio::spawn(async move {
        let _ = upstream.set_nodelay(true);
        match hyper::upgrade::on(req).await {
            Ok(io) => {
                let mut client = TokioIo::new(io);
                let mut server = upstream;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            }
            Err(e) => tracing::debug!(error = %e, "intercept: CONNECT upgrade failed"),
        }
    });
    empty(StatusCode::OK)
}

/// Lowercase, without IPv6 brackets or a trailing dot.
fn normalize_host(h: &str) -> String {
    h.trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Hands out the parda leaf for the CONNECT host, and nothing else: a
/// missing SNI or one naming another host fails the handshake.
#[derive(Debug)]
struct ConnectHostCert {
    ca: Arc<Ca>,
    host: String,
}

impl ResolvesServerCert for ConnectHostCert {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let Some(sni) = hello.server_name() else {
            tracing::debug!(host = %self.host, "intercept: TLS without SNI refused");
            return None;
        };
        if normalize_host(sni) != self.host {
            tracing::debug!(host = %self.host, "intercept: SNI differs from CONNECT host");
            return None;
        }
        match self.ca.leaf_for(&self.host) {
            Ok(leaf) => Some(leaf),
            Err(e) => {
                tracing::warn!(host = %self.host, error = %e, "intercept: no leaf certificate");
                None
            }
        }
    }
}

fn server_config(ca: Arc<Ca>, host: String) -> anyhow::Result<rustls::ServerConfig> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(PROVIDER.clone())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ConnectHostCert { ca, host }));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

async fn intercept_tls(
    io: TokioIo<hyper::upgrade::Upgraded>,
    host: String,
    port: u16,
    state: Arc<InterceptState>,
) {
    let cfg = match server_config(state.ca.clone(), host.clone()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "intercept: TLS config");
            return;
        }
    };
    let tls = match TlsAcceptor::from(Arc::new(cfg)).accept(io).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!(%host, error = %e, "intercept: client TLS handshake failed");
            return;
        }
    };
    let target = Arc::new(Target { host, port });
    let svc = service_fn(move |req| forward(req, state.clone(), target.clone()));
    if let Err(e) = http1::Builder::new()
        .serve_connection(TokioIo::new(tls), svc)
        .with_upgrades()
        .await
    {
        tracing::debug!(error = %e, "intercept: decrypted connection ended");
    }
}

/// The CONNECT target of a decrypted connection.
struct Target {
    host: String,
    port: u16,
}

impl Target {
    fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Does a `Host` header / request authority name this target?
    fn is(&self, authority: &str) -> bool {
        let Ok(a) = authority.parse::<http::uri::Authority>() else {
            return false;
        };
        normalize_host(a.host()) == self.host && a.port_u16().is_none_or(|p| p == self.port)
    }
}

/// One decrypted request to a listed host.
async fn forward(
    req: Request<Incoming>,
    state: Arc<InterceptState>,
    target: Arc<Target>,
) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path().to_string();
    // Requests on this connection may only go to the CONNECT host.
    let host_ok = req
        .headers()
        .get(HOST)
        .is_none_or(|h| h.to_str().is_ok_and(|h| target.is(h)))
        && req.uri().authority().is_none_or(|a| target.is(a.as_str()));
    if !host_ok {
        return Ok(text(
            StatusCode::MISDIRECTED_REQUEST,
            "parda intercept: Host does not match the CONNECT target\n",
        ));
    }
    let url = format!(
        "https://{}{}",
        target.authority(),
        req.uri().path_and_query().map_or("/", |p| p.as_str())
    );
    if is_upgrade(req.headers()) {
        return Ok(upgrade(req, &state, &target, path, url).await);
    }

    let (parts, body) = req.into_parts();
    let body = match read_body(&parts.headers, body, MAX_REQUEST_BODY).await {
        Ok(b) => b,
        Err(status) => {
            let msg = if status == StatusCode::PAYLOAD_TOO_LARGE {
                "parda intercept: request body too large to filter\n"
            } else {
                "parda intercept: could not read the request body\n"
            };
            emit(
                &state,
                &target,
                &path,
                status.as_u16(),
                Default::default(),
                0,
                None,
                0,
            );
            return Ok(text(status, msg));
        }
    };

    let started = Instant::now();
    let outcome = if body.is_empty() {
        Ok(RequestOutcome::default())
    } else {
        state
            .transform
            .request_outcome(&target.host, &path, &parts.headers, body)
    };
    let added_ms = started.elapsed().as_millis() as u64;
    let outcome = match outcome {
        Ok(o) => o,
        Err(refusal) => {
            let status = StatusCode::from_u16(refusal.status).unwrap_or(StatusCode::FORBIDDEN);
            emit(
                &state,
                &target,
                &path,
                status.as_u16(),
                Default::default(),
                added_ms,
                Some(refusal.message.clone()),
                0,
            );
            return Ok(text(status, &format!("{}\n", refusal.message)));
        }
    };

    let mut headers = end_to_end(&parts.headers);
    headers.remove(HOST);
    headers.remove(CONTENT_LENGTH);
    headers.remove(CONTENT_ENCODING);
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    let mut rb = state
        .upstream
        .request(parts.method.clone(), &url)
        .headers(headers);
    if !outcome.body.is_empty() || !matches!(parts.method, Method::GET | Method::HEAD) {
        rb = rb.body(outcome.body);
    }
    let res = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            let e = e.without_url();
            tracing::info!(host = %target.host, %path, error = %e, "intercept: upstream failed");
            emit(
                &state,
                &target,
                &path,
                502,
                outcome.counts,
                added_ms,
                None,
                outcome.unscanned,
            );
            return Ok(text(
                StatusCode::BAD_GATEWAY,
                &format!("parda intercept: upstream request failed: {e}\n"),
            ));
        }
    };

    let status = res.status();
    let content_type = res
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // reqwest decodes what it can; anything still encoded is passed through
    // untouched (the transform could not read it).
    let still_encoded = res
        .headers()
        .get(CONTENT_ENCODING)
        .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
    let mut out_headers = end_to_end(res.headers());
    out_headers.remove(CONTENT_LENGTH);
    if !still_encoded {
        out_headers.remove(CONTENT_ENCODING);
    }
    emit(
        &state,
        &target,
        &path,
        status.as_u16(),
        outcome.counts,
        added_ms,
        None,
        outcome.unscanned,
    );
    let stream = res.bytes_stream();
    let body = if still_encoded {
        passthrough(stream)
    } else {
        transformed(
            stream,
            state
                .transform
                .response_stream(&target.host, &path, &content_type),
        )
    };
    let mut out = Response::new(body);
    *out.status_mut() = status;
    *out.headers_mut() = out_headers;
    Ok(out)
}

/// Stream `upstream` through `rewriter`, chunk by chunk, then flush it.
fn transformed(
    upstream: impl Stream<Item = reqwest::Result<Bytes>> + Send + 'static,
    rewriter: Box<dyn StreamTransform>,
) -> Body {
    let frames =
        futures::stream::unfold(Some((Box::pin(upstream), rewriter)), |state| async move {
            let (mut upstream, mut rewriter) = state?;
            loop {
                match upstream.next().await {
                    Some(Ok(chunk)) => {
                        let out = rewriter.push(&chunk);
                        if !out.is_empty() {
                            return Some((Ok(Frame::data(out)), Some((upstream, rewriter))));
                        }
                    }
                    Some(Err(e)) => {
                        return Some((Err(BoxError::from(e.without_url())), None));
                    }
                    None => {
                        let out = rewriter.finish();
                        return (!out.is_empty()).then(|| (Ok(Frame::data(out)), None));
                    }
                }
            }
        });
    BodyExt::boxed_unsync(StreamBody::new(frames))
}

/// Stream `upstream` unchanged.
fn passthrough(upstream: impl Stream<Item = reqwest::Result<Bytes>> + Send + 'static) -> Body {
    BodyExt::boxed_unsync(StreamBody::new(upstream.map(|r| {
        r.map(Frame::data)
            .map_err(|e| BoxError::from(e.without_url()))
    })))
}

/// A WebSocket (or other) upgrade on a listed host: relay the handshake,
/// then tunnel the raw bytes both ways. The stream is not inspected.
async fn upgrade(
    mut req: Request<Incoming>,
    state: &InterceptState,
    target: &Target,
    path: String,
    url: String,
) -> Response<Body> {
    let client_side = hyper::upgrade::on(&mut req);
    let mut headers = end_to_end(req.headers());
    headers.remove(HOST);
    headers.remove(CONTENT_LENGTH);
    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    if let Some(u) = req.headers().get(UPGRADE) {
        headers.insert(UPGRADE, u.clone());
    }
    // A separate HTTP/1.1-only client: on an HTTP/2 connection (which the
    // main client negotiates with most sites) there is no 101 to relay.
    let res = state
        .upstream_http1
        .request(req.method().clone(), &url)
        .version(http::Version::HTTP_11)
        .headers(headers)
        .send()
        .await;
    let res = match res {
        Ok(r) => r,
        Err(e) => {
            let e = e.without_url();
            emit(state, target, &path, 502, Default::default(), 0, None, 0);
            return text(
                StatusCode::BAD_GATEWAY,
                &format!("parda intercept: upstream upgrade failed: {e}\n"),
            );
        }
    };
    let status = res.status();
    if status != StatusCode::SWITCHING_PROTOCOLS {
        // The server declined the upgrade: relay its answer as is.
        emit(
            state,
            target,
            &path,
            status.as_u16(),
            Default::default(),
            0,
            None,
            0,
        );
        let mut out_headers = end_to_end(res.headers());
        out_headers.remove(CONTENT_LENGTH);
        let mut out = Response::new(passthrough(res.bytes_stream()));
        *out.status_mut() = status;
        *out.headers_mut() = out_headers;
        return out;
    }
    emit(state, target, &path, 101, Default::default(), 0, None, 1);
    let mut out_headers = res.headers().clone();
    out_headers.remove(CONTENT_LENGTH);
    out_headers.remove(http::header::TRANSFER_ENCODING);
    tokio::spawn(async move {
        let (server_io, client_io) = match (res.upgrade().await, client_side.await) {
            (Ok(s), Ok(c)) => (s, c),
            _ => {
                tracing::debug!("intercept: upgrade did not complete");
                return;
            }
        };
        let mut client_io = TokioIo::new(client_io);
        let mut server_io = server_io;
        let _ = tokio::io::copy_bidirectional(&mut client_io, &mut server_io).await;
    });
    let mut out = empty(StatusCode::SWITCHING_PROTOCOLS);
    *out.headers_mut() = out_headers;
    out
}

fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(UPGRADE) && connection_tokens(headers).iter().any(|t| t == "upgrade")
}

/// Lowercased tokens of every `Connection` header.
fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// `headers` without hop-by-hop headers (fixed list plus any named in
/// `Connection`).
fn end_to_end(headers: &HeaderMap) -> HeaderMap {
    const HOP_BY_HOP: [&str; 9] = [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    let named = connection_tokens(headers);
    let mut out = HeaderMap::with_capacity(headers.len());
    for (k, v) in headers {
        let k_str = k.as_str();
        if HOP_BY_HOP.contains(&k_str) || named.iter().any(|n| n == k_str) {
            continue;
        }
        out.append(k.clone(), v.clone());
    }
    out
}

/// Read a whole request body of at most `limit` bytes. Errors are the status
/// to answer with: 413 when too large, 400 when the body broke off.
async fn read_body<B>(headers: &HeaderMap, body: B, limit: usize) -> Result<Bytes, StatusCode>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    let declared = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > limit as u64) || body.size_hint().lower() > limit as u64 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    match Limited::new(body, limit).collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        }
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

#[allow(clippy::too_many_arguments)]
fn emit(
    state: &InterceptState,
    target: &Target,
    path: &str,
    status: u16,
    counts: BTreeMap<String, u32>,
    added_ms: u64,
    refused: Option<String>,
    unscanned: u32,
) {
    // No subscribers is fine.
    let _ = state.events.send(InterceptEvent {
        host: target.host.clone(),
        path: path.to_string(),
        status,
        counts,
        added_ms,
        refused,
        unscanned,
    });
}

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|n| match n {}).boxed_unsync()
}

fn empty(status: StatusCode) -> Response<Body> {
    let mut res = Response::new(Empty::new().map_err(|n| match n {}).boxed_unsync());
    *res.status_mut() = status;
    res
}

fn text(status: StatusCode, msg: &str) -> Response<Body> {
    let mut res = Response::new(full(msg.to_string()));
    *res.status_mut() = status;
    res.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    res
}

/// Loopback, including IPv4-mapped IPv6 loopback.
fn is_loopback(ip: std::net::IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_state_uses_the_safe_upstream_clients() {
        let (tx, _rx) = broadcast::channel(1);
        let state = InterceptState::new(
            Arc::new(Ca::generate().unwrap()),
            HostList::new(&["chat.test".to_string()]),
            Arc::new(crate::transform::tests_support::Identity),
            tx,
        )
        .unwrap();
        assert_eq!(state.timeouts, Timeouts::default());
    }

    #[test]
    fn loopback_addresses_only() {
        for ok in ["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1"] {
            assert!(is_loopback(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "0.0.0.0",
            "::",
            "192.168.1.2",
            "10.0.0.1",
            "::ffff:10.0.0.1",
            "fe80::1",
        ] {
            assert!(!is_loopback(bad.parse().unwrap()), "{bad}");
        }
    }

    #[tokio::test]
    async fn body_limit_gives_413() {
        let none = HeaderMap::new();
        let ok = read_body(&none, Full::new(Bytes::from(vec![b'a'; 10])), 10).await;
        assert_eq!(ok.unwrap().len(), 10);
        let big = read_body(&none, Full::new(Bytes::from(vec![b'a'; 11])), 10).await;
        assert_eq!(big.unwrap_err(), StatusCode::PAYLOAD_TOO_LARGE);
        let mut declared = HeaderMap::new();
        declared.insert(CONTENT_LENGTH, HeaderValue::from_static("1000"));
        let big = read_body(&declared, Empty::<Bytes>::new(), 10).await;
        assert_eq!(big.unwrap_err(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn hop_by_hop_headers_are_dropped() {
        let mut h = HeaderMap::new();
        h.insert(
            CONNECTION,
            HeaderValue::from_static("keep-alive, x-private"),
        );
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert("x-private", HeaderValue::from_static("1"));
        h.insert("proxy-authorization", HeaderValue::from_static("x"));
        h.insert("authorization", HeaderValue::from_static("Bearer t"));
        h.append("cookie", HeaderValue::from_static("a=1"));
        h.append("cookie", HeaderValue::from_static("b=2"));
        let out = end_to_end(&h);
        assert_eq!(out.len(), 3);
        assert_eq!(out.get_all("cookie").iter().count(), 2);
        assert!(out.contains_key("authorization"));
    }

    #[test]
    fn target_matches_host_headers() {
        let t = Target {
            host: "chat.test".into(),
            port: 443,
        };
        assert!(t.is("chat.test"));
        assert!(t.is("CHAT.test:443"));
        assert!(t.is("chat.test."));
        assert!(!t.is("chat.test:8443"));
        assert!(!t.is("other.test"));
        assert!(!t.is("x.chat.test"));
        assert_eq!(t.authority(), "chat.test");
        let t = Target {
            host: "chat.test".into(),
            port: 8443,
        };
        assert_eq!(t.authority(), "chat.test:8443");
    }

    #[test]
    fn pac_only_for_local_targets() {
        assert!(is_local(&"/parda.pac".parse().unwrap()));
        assert!(is_local(
            &"http://127.0.0.1:8788/parda.pac".parse().unwrap()
        ));
        assert!(is_local(
            &"http://localhost:8788/parda.pac".parse().unwrap()
        ));
        assert!(is_local(&"http://[::1]:8788/parda.pac".parse().unwrap()));
        assert!(!is_local(&"http://example.com/parda.pac".parse().unwrap()));
    }
}
