//! End-to-end tests: a real `serve` task, the blocking `Client`, and raw peers.
//!
//! Unix tests each get their own tempdir runtime dir. The Windows variant runs
//! the same scenarios against one named pipe, with a unique `PARDA_PIPE_NAME`.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use interprocess::local_socket::tokio::{Stream, prelude::*};
use parda_ipc::{
    Client, Event, Handler, IpcError, MAX_LINE_BYTES, PROTOCOL_VERSION, Request, Response, serve,
    socket_name,
};
use serde_json::json;
#[cfg(unix)]
use tokio::{io::AsyncReadExt, task::JoinSet};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::broadcast,
    task::JoinHandle,
};

const LIMIT: usize = MAX_LINE_BYTES;
const STEP: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Test handler and server harness
// ---------------------------------------------------------------------------

struct Echo {
    events: broadcast::Sender<Event>,
    /// Events sent right after a subscription is created, before it is returned.
    burst: usize,
}

impl Echo {
    fn new() -> Arc<Self> {
        Self::with_events(16, 2)
    }

    fn with_events(capacity: usize, burst: usize) -> Arc<Self> {
        Arc::new(Self {
            events: broadcast::channel(capacity).0,
            burst,
        })
    }
}

impl Handler for Echo {
    fn handle(&self, req: Request) -> Response {
        match req {
            Request::Status => Response::ok(json!({"ready": true})),
            Request::RulesSet { .. } => Response::err("invalid_rules", "test rejection"),
            Request::ConfigGet => Response::ok(json!({"text": "x".repeat(LIMIT)})),
            Request::Reload => {
                // block_on would panic on an async worker: dispatch must use
                // spawn_blocking, even when the handler invokes async work.
                tokio::runtime::Handle::current().block_on(async {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                });
                Response::ok(json!({"reloaded": true}))
            }
            Request::VaultStats => Response::ok(()),
            Request::PasteSafe => Response::ok(vec![1, 2, 3]),
            Request::RulesGet => Response::Ok(json!("directly built")),
            Request::ConfigSet { .. } => Response::ok(json!({"kind": "collides"})),
            Request::Shutdown => panic!("handler panic is contained"),
            other => Response::ok(other),
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<Event> {
        let receiver = self.events.subscribe();
        for i in 0..self.burst {
            let event = match (self.burst, i) {
                (2, 0) => Event::now("proxy", "first"),
                (2, 1) => Event::now("clipboard", "second"),
                _ => Event::now("proxy", format!("event-{i}")),
            };
            self.events.send(event).unwrap();
        }
        receiver
    }
}

struct Server {
    dir: PathBuf,
    handler: Arc<Echo>,
    task: JoinHandle<Result<(), IpcError>>,
}

impl Server {
    async fn start(dir: &Path) -> Self {
        Self::start_with(dir, Echo::new()).await
    }

    async fn start_with(dir: &Path, handler: Arc<Echo>) -> Self {
        let server_dir = dir.to_owned();
        let server_handler = handler.clone();
        let task = tokio::spawn(async move { serve(&server_dir, server_handler).await });
        tokio::time::timeout(STEP, async {
            loop {
                if Stream::connect(socket_name(dir)).await.is_ok() {
                    break;
                }
                assert!(
                    !task.is_finished(),
                    "server exited before accepting clients"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("server startup timeout");
        Self {
            dir: dir.to_owned(),
            handler,
            task,
        }
    }

    /// Run blocking client code on the blocking pool, as a CLI thread would.
    async fn client<T: Send + 'static>(&self, f: impl FnOnce(Client) -> T + Send + 'static) -> T {
        let dir = self.dir.clone();
        tokio::task::spawn_blocking(move || f(Client::connect(&dir).unwrap()))
            .await
            .unwrap()
    }

    async fn raw(&self) -> Raw {
        Raw(BufReader::new(
            Stream::connect(socket_name(&self.dir)).await.unwrap(),
        ))
    }

    async fn stop(self) {
        self.task.abort();
        assert!(self.task.await.unwrap_err().is_cancelled());
    }
}

/// A raw NDJSON peer, for protocol-level behaviour the typed client hides.
struct Raw(BufReader<Stream>);

impl Raw {
    async fn send(&mut self, bytes: &[u8]) {
        self.0.get_mut().write_all(bytes).await.unwrap();
    }

    async fn response(&mut self) -> Response {
        let mut line = String::new();
        tokio::time::timeout(STEP, self.0.read_line(&mut line))
            .await
            .expect("response timeout")
            .unwrap();
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad response {line:?}: {e}"))
    }

    async fn expect_err(&mut self, expected_code: &str) {
        match self.response().await {
            Response::Err { code, .. } => assert_eq!(code, expected_code),
            other => panic!("expected Err {expected_code}, got {other:?}"),
        }
    }

    async fn expect_closed(&mut self) {
        let mut buf = Vec::new();
        let read = tokio::time::timeout(STEP, self.0.read_until(b'\n', &mut buf))
            .await
            .expect("close timeout");
        // A server that closes with unread input may reset instead of EOF.
        assert!(matches!(read, Ok(0) | Err(_)), "expected EOF, read {buf:?}");
    }
}

// ---------------------------------------------------------------------------
// Scenarios shared by the Unix and Windows variants
// ---------------------------------------------------------------------------

async fn scenario_status(server: &Server) {
    server
        .client(|mut client| {
            assert_eq!(
                client.call(Request::Status).unwrap(),
                json!({"ready": true})
            );
            // Non-ASCII text survives framing, including an embedded newline.
            let text = "नमस्ते\n世界 🦀";
            assert_eq!(
                client.call(Request::Scan { text: text.into() }).unwrap(),
                json!({"op": "Scan", "text": text})
            );
            // A handler error is a value, not a broken connection.
            let err = client
                .call(Request::RulesSet {
                    rules_toml: String::new(),
                })
                .unwrap_err();
            assert!(matches!(err, IpcError::Remote { ref code, .. } if code == "invalid_rules"));
            assert_eq!(
                client.call(Request::Status).unwrap(),
                json!({"ready": true})
            );
        })
        .await;
}

async fn scenario_version_mismatch(server: &Server) {
    server
        .client(|mut client| {
            let err = client.call(Request::Hello { version: 999 }).unwrap_err();
            assert!(matches!(err, IpcError::Remote { ref code, .. } if code == "version_mismatch"));
            // The server closed the connection; the client stays failed.
            assert!(client.call(Request::Status).is_err());
            assert!(client.call(Request::Status).is_err());
        })
        .await;

    // Raw: mismatch is fatal whether Hello comes first or after other requests.
    for after_status in [false, true] {
        let mut raw = server.raw().await;
        if after_status {
            raw.send(b"{\"op\":\"Status\"}\n").await;
            let _ = raw.response().await;
        }
        raw.send(b"{\"op\":\"Hello\",\"version\":999}\n").await;
        raw.expect_err("version_mismatch").await;
        raw.expect_closed().await;
    }

    // A matching Hello is acknowledged with the version.
    let mut raw = server.raw().await;
    let hello = format!("{{\"op\":\"Hello\",\"version\":{PROTOCOL_VERSION}}}\n");
    // Fragmented frames must not be dispatched before their newline arrives.
    for chunk in hello.as_bytes().chunks(3) {
        raw.send(chunk).await;
    }
    assert!(
        matches!(raw.response().await, Response::Ok(v) if v == json!({"version": PROTOCOL_VERSION}))
    );
}

async fn scenario_subscribe(server: &Server) {
    server
        .client(|client| {
            let mut events = client.subscribe();
            let first = events.next().unwrap();
            let second = events.next().unwrap();
            assert_eq!(
                (first.surface.as_str(), first.summary.as_str()),
                ("proxy", "first")
            );
            assert_eq!(
                (second.surface.as_str(), second.summary.as_str()),
                ("clipboard", "second")
            );
            assert!(first.ts_ms > 0);
            assert!(first.counts.is_empty());
            assert_eq!(first.latency_ms, None);
            assert_eq!(first.level, "info");
            assert!(events.error().is_none());
        })
        .await;

    // The idle subscription must release its receiver once the peer is gone.
    tokio::time::timeout(STEP, async {
        while server.handler.events.receiver_count() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("subscriber leaked after disconnect");

    // Events produced after subscribing are delivered live.
    let mut raw = server.raw().await;
    raw.send(b"{\"op\":\"Subscribe\"}\n").await;
    for _ in 0..2 {
        assert!(matches!(raw.response().await, Response::Event(_)));
    }
    server
        .handler
        .events
        .send(Event::now("proxy", "live"))
        .unwrap();
    assert!(matches!(raw.response().await, Response::Event(e) if e.summary == "live"));
}

async fn scenario_overlong(server: &Server) {
    // More than 16 MiB without any newline: rejected from the size alone.
    let mut raw = server.raw().await;
    raw.send(&vec![b' '; LIMIT + 1]).await;
    raw.expect_err("line_too_long").await;
    raw.expect_closed().await;

    // The typed client refuses to send an oversized request at all, and the
    // connection stays usable because nothing was written.
    server
        .client(|mut client| {
            let request = Request::Scan {
                text: "é".repeat(LIMIT / 2),
            };
            assert!(matches!(client.call(request), Err(IpcError::LineTooLong)));
            assert_eq!(
                client.call(Request::Status).unwrap(),
                json!({"ready": true})
            );
        })
        .await;

    // A handler response over the limit becomes Err and the connection closes.
    let mut raw = server.raw().await;
    raw.send(b"{\"op\":\"ConfigGet\"}\n").await;
    raw.expect_err("line_too_long").await;
    raw.expect_closed().await;

    // So does an oversized event.
    let mut raw = server.raw().await;
    raw.send(b"{\"op\":\"Subscribe\"}\n").await;
    for _ in 0..2 {
        assert!(matches!(raw.response().await, Response::Event(_)));
    }
    server
        .handler
        .events
        .send(Event::now("proxy", "x".repeat(LIMIT)))
        .unwrap();
    raw.expect_err("line_too_long").await;
    raw.expect_closed().await;

    // The limit is inclusive and counts UTF-8 bytes, excluding the newline.
    let mut raw = server.raw().await;
    let mut frame = serde_json::to_vec(&Request::Status).unwrap();
    frame.resize(LIMIT, b' ');
    frame.push(b'\n');
    raw.send(&frame).await;
    assert!(matches!(raw.response().await, Response::Ok(_)));
}

// ---------------------------------------------------------------------------
// Unix tests
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};

    use super::*;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn status_roundtrip() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::start(&root.path().join("run")).await;
        scenario_status(&server).await;
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn version_mismatch() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::start(root.path()).await;
        scenario_version_mismatch(&server).await;
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subscribe_receives_events() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::start(root.path()).await;
        scenario_subscribe(&server).await;
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overlong_line_yields_err() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::start(root.path()).await;
        scenario_overlong(&server).await;
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overlong_line_with_overshoot_still_yields_err() {
        // A peer that keeps writing past the limit must still see the Err.
        let root = tempfile::tempdir().unwrap();
        let server = Server::start(root.path()).await;
        let raw = server.raw().await;
        let mut line = vec![b' '; LIMIT + 4096];
        line.push(b'\n');
        let (mut reader, mut writer) = tokio::io::split(raw.0);
        let write = tokio::spawn(async move {
            // The server may close before the tail is accepted; that is fine.
            let _ = writer.write_all(&line).await;
            writer
        });
        let mut text = String::new();
        let mut lines = BufReader::new(&mut reader);
        tokio::time::timeout(STEP, lines.read_line(&mut text))
            .await
            .expect("response timeout")
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<Response>(&text).unwrap(),
            Response::Err { code, .. } if code == "line_too_long"
        ));
        let _ = write.await;
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_dir_is_created_0700() {
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("a").join("run");
        let server = Server::start(&runtime).await;
        assert_eq!(mode(&runtime), 0o700);
        assert!(runtime.parent().is_some_and(|p| mode(p) != 0o000));
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn existing_loose_runtime_dir_is_tightened_to_0700() {
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("run");
        std::fs::DirBuilder::new()
            .mode(0o755)
            .create(&runtime)
            .unwrap();
        assert_eq!(mode(&runtime), 0o755);
        let server = Server::start(&runtime).await;
        assert_eq!(mode(&runtime), 0o700);
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_socket_file_is_replaced() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("parda.sock");
        // Dropping a std listener leaves the socket file behind: a crashed daemon.
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
        assert!(socket.exists());
        let server = Server::start(root.path()).await;
        scenario_status(&server).await;
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_socket_is_not_stolen() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::start(root.path()).await;
        let second = serve(root.path(), Echo::new()).await;
        assert!(matches!(
            second,
            Err(IpcError::Io(ref e)) if e.kind() == std::io::ErrorKind::AddrInUse
        ));
        // The first daemon is unaffected.
        scenario_status(&server).await;
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stopping_serve_closes_peers_and_removes_the_socket() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::start(root.path()).await;
        let mut raw = server.raw().await;
        raw.send(b"{\"op\":\"Status\"}\n").await;
        assert!(matches!(raw.response().await, Response::Ok(_)));
        let socket = root.path().join("parda.sock");
        server.stop().await;
        raw.expect_closed().await;
        assert!(!socket.exists(), "socket file should be reclaimed");
    }

    #[tokio::test]
    async fn non_socket_files_and_symlinked_runtime_dirs_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("parda.sock");
        std::fs::write(&socket, "keep me").unwrap();
        assert!(serve(root.path(), Echo::new()).await.is_err());
        assert_eq!(std::fs::read_to_string(socket).unwrap(), "keep me");

        let actual = root.path().join("actual");
        std::fs::create_dir(&actual).unwrap();
        std::fs::set_permissions(&actual, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = root.path().join("link");
        symlink(&actual, &link).unwrap();
        assert!(serve(&link, Echo::new()).await.is_err());
        assert_eq!(mode(&actual), 0o755);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn protocol_edge_cases() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::start(root.path()).await;

        // One-shot clients may skip Hello; several lines may share one write.
        let mut raw = server.raw().await;
        raw.send(b"{\"op\":\"Status\"}\n{\"op\":\"Status\"}\n")
            .await;
        for _ in 0..2 {
            assert!(matches!(raw.response().await, Response::Ok(v) if v == json!({"ready": true})));
        }

        // Garbage never reaches the handler and never stops the listener.
        for frame in [
            b"not json\n".as_slice(),
            b"\xff\n",
            b"{\"op\":\"Unknown\"}\n",
        ] {
            let mut raw = server.raw().await;
            raw.send(frame).await;
            raw.expect_err("invalid_request").await;
            raw.expect_closed().await;
        }

        // A frame cut off by EOF is invalid too. Half-closing needs a std socket.
        let socket = root.path().join("parda.sock");
        let reply = tokio::task::spawn_blocking(move || {
            use std::{
                io::{Read, Write},
                net::Shutdown,
                os::unix::net::UnixStream,
            };
            let mut stream = UnixStream::connect(socket).unwrap();
            stream.write_all(b"{\"op\":\"Status\"").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).unwrap();
            reply
        })
        .await
        .unwrap();
        assert!(matches!(
            serde_json::from_str::<Response>(reply.trim_end()).unwrap(),
            Response::Err { code, .. } if code == "invalid_request"
        ));

        // A handler may use the runtime handle; it runs on the blocking pool.
        server
            .client(|mut client| {
                assert_eq!(
                    client.call(Request::Reload).unwrap(),
                    json!({"reloaded": true})
                );
            })
            .await;

        let mut raw = server.raw().await;
        raw.send(b"{\"op\":\"Status\"}\n").await;
        assert!(matches!(raw.response().await, Response::Ok(_)));
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ok_payloads_are_always_objects_and_handler_panics_are_contained() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::start(root.path()).await;
        server
            .client(|mut client| {
                // Unit becomes an empty object; scalars and arrays are wrapped.
                assert_eq!(client.call(Request::VaultStats).unwrap(), json!({}));
                assert_eq!(
                    client.call(Request::PasteSafe).unwrap(),
                    json!({"value": [1, 2, 3]})
                );
                assert_eq!(
                    client.call(Request::RulesGet).unwrap(),
                    json!({"value": "directly built"})
                );
                // A payload that would shadow the tag is a handler bug.
                assert!(matches!(
                    client.call(Request::ConfigSet { toml: String::new() }),
                    Err(IpcError::Remote { ref code, .. }) if code == "invalid_response"
                ));
                assert!(matches!(
                    client.call(Request::Shutdown),
                    Err(IpcError::Remote { ref code, .. }) if code == "handler_failed"
                ));
                // The connection and the server survive both.
                assert_eq!(
                    client.call(Request::Status).unwrap(),
                    json!({"ready": true})
                );
            })
            .await;
        server.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_subscribers_get_a_warning_event_and_stay_connected() {
        let root = tempfile::tempdir().unwrap();
        // Capacity 4 and a burst of 10 events: the receiver starts 6 behind.
        let handler = Echo::with_events(4, 10);
        let server = Server::start_with(root.path(), handler.clone()).await;
        let mut raw = server.raw().await;
        raw.send(b"{\"op\":\"Subscribe\"}\n").await;
        match raw.response().await {
            Response::Event(event) => {
                assert_eq!(
                    (event.surface.as_str(), event.level.as_str()),
                    ("ipc", "warn")
                );
                assert_eq!(event.counts.get("dropped"), Some(&6));
            }
            other => panic!("expected a lag warning, got {other:?}"),
        }
        for i in 6..10 {
            assert!(
                matches!(raw.response().await, Response::Event(e) if e.summary == format!("event-{i}"))
            );
        }
        handler
            .events
            .send(Event::now("proxy", "still-live"))
            .unwrap();
        assert!(matches!(raw.response().await, Response::Event(e) if e.summary == "still-live"));
        server.stop().await;
    }

    // -- client-side behaviour without a (real) server ----------------------

    #[test]
    fn client_reports_not_running_without_a_daemon() {
        let root = tempfile::tempdir().unwrap();
        // No socket file at all.
        let err = Client::connect(root.path()).err().unwrap();
        assert!(matches!(err, IpcError::NotRunning), "{err:?}");
        assert!(err.is_not_running());
        assert!(err.to_string().contains("not running"), "{err}");
        // Runtime dir does not exist.
        let err = Client::connect(&root.path().join("missing")).err().unwrap();
        assert!(matches!(err, IpcError::NotRunning), "{err:?}");
        // A stale socket file refuses connections.
        drop(std::os::unix::net::UnixListener::bind(root.path().join("parda.sock")).unwrap());
        let err = Client::connect(root.path()).err().unwrap();
        assert!(matches!(err, IpcError::NotRunning), "{err:?}");

        // The CLI sees anyhow errors, with or without added context.
        let any = anyhow::Error::from(err);
        assert!(parda_ipc::is_not_running(&any));
        assert!(parda_ipc::is_not_running(
            &any.context("while running parda scan")
        ));
    }

    #[test]
    fn other_errors_are_not_classified_as_not_running() {
        for err in [
            IpcError::Timeout,
            IpcError::LineTooLong,
            IpcError::Remote {
                code: "x".into(),
                message: "y".into(),
            },
            IpcError::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        ] {
            assert!(!err.is_not_running(), "{err:?}");
            assert!(!parda_ipc::is_not_running(&anyhow::Error::from(err)));
        }
        assert!(!parda_ipc::is_not_running(&anyhow::anyhow!("unrelated")));
    }

    #[test]
    fn connect_gives_up_on_a_daemon_that_never_answers_hello() {
        let root = tempfile::tempdir().unwrap();
        let listener =
            std::os::unix::net::UnixListener::bind(root.path().join("parda.sock")).unwrap();
        let holder = std::thread::spawn(move || {
            // Accept and then stay silent until the client gives up.
            let (mut stream, _) = listener.accept().unwrap();
            let _ = std::io::Read::read_to_end(&mut stream, &mut Vec::new());
        });
        let started = std::time::Instant::now();
        let err = Client::connect_with_timeout(root.path(), Duration::from_millis(200))
            .err()
            .unwrap();
        assert!(matches!(err, IpcError::Timeout), "{err:?}");
        assert!(!err.is_not_running());
        assert!(started.elapsed() < Duration::from_secs(4));
        holder.join().unwrap();
    }

    #[test]
    fn default_connect_timeout_is_two_seconds() {
        assert_eq!(parda_ipc::CONNECT_TIMEOUT, Duration::from_secs(2));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_bounds_responses_and_exposes_subscription_errors() {
        use interprocess::local_socket::ListenerOptions;
        let root = tempfile::tempdir().unwrap();
        let listener = ListenerOptions::new()
            .name(socket_name(root.path()))
            .create_tokio()
            .unwrap();
        let peer = tokio::spawn(async move {
            let mut conns = JoinSet::new();
            for payload in [
                vec![b' '; LIMIT + 1],
                b"{\"kind\":\"Err\",\"code\":\"x\",\"message\":\"y\"}\n".to_vec(),
                b"not JSON\n".to_vec(),
                Vec::new(),
            ] {
                let mut stream = BufReader::new(listener.accept().await.unwrap());
                // Each connection lives until its client hangs up.
                conns.spawn(async move {
                    let mut line = String::new();
                    stream.read_line(&mut line).await.unwrap();
                    assert_eq!(
                        serde_json::from_str::<Request>(&line).unwrap(),
                        Request::Hello { version: 1 }
                    );
                    let ok = b"{\"kind\":\"Ok\",\"version\":1}\n";
                    stream.get_mut().write_all(ok).await.unwrap();
                    line.clear();
                    stream.read_line(&mut line).await.unwrap();
                    if payload.is_empty() {
                        // EOF: local-socket `shutdown` does not half-close on
                        // every platform, so close the connection instead.
                        return;
                    }
                    let _ = stream.get_mut().write_all(&payload).await;
                    let _ = stream.read_to_end(&mut Vec::new()).await;
                });
            }
            while let Some(done) = conns.join_next().await {
                done.unwrap();
            }
        });
        let dir = root.path().to_owned();
        tokio::task::spawn_blocking(move || {
            // An oversized response poisons the connection: framing is lost.
            let mut client = Client::connect(&dir).unwrap();
            assert!(matches!(
                client.call(Request::Status),
                Err(IpcError::LineTooLong)
            ));
            assert!(matches!(
                client.call(Request::Status),
                Err(IpcError::Protocol(_))
            ));

            let mut events = Client::connect(&dir).unwrap().subscribe();
            assert!(events.next().is_none());
            assert!(matches!(
                events.error(),
                Some(IpcError::Remote { code, .. }) if code == "x"
            ));
            assert!(events.next().is_none());

            let mut events = Client::connect(&dir).unwrap().subscribe();
            assert!(events.next().is_none());
            assert!(matches!(events.error(), Some(IpcError::Json(_))));

            let mut events = Client::connect(&dir).unwrap().subscribe();
            assert!(events.next().is_none());
            assert!(events.error().is_none());
            assert!(events.next().is_none());
        })
        .await
        .unwrap();
        peer.await.unwrap();
    }
}

// ---------------------------------------------------------------------------
// Windows variant
// ---------------------------------------------------------------------------

// A child process sets the pipe-name override, avoiding process-wide env mutation.
#[cfg(windows)]
#[test]
fn windows_roundtrip() {
    if std::env::var_os("PARDA_IPC_TEST_CHILD").is_some() {
        let root = tempfile::tempdir().unwrap();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let server = Server::start(root.path()).await;
                scenario_status(&server).await;
                scenario_version_mismatch(&server).await;
                scenario_subscribe(&server).await;
                scenario_overlong(&server).await;
                server.stop().await;
            });
    } else {
        let unique = format!(
            "parda-test-{}-{}",
            std::process::id(),
            Event::now("", "").ts_ms
        );
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows_roundtrip", "--nocapture"])
            .env("PARDA_PIPE_NAME", unique)
            .env("PARDA_IPC_TEST_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}

#[cfg(windows)]
#[test]
fn windows_client_reports_not_running_without_a_pipe() {
    if std::env::var_os("PARDA_IPC_TEST_CHILD").is_some() {
        let root = tempfile::tempdir().unwrap();
        let err = Client::connect(root.path()).err().unwrap();
        assert!(matches!(err, IpcError::NotRunning), "{err:?}");
    } else {
        let unique = format!("parda-test-absent-{}", std::process::id());
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows_client_reports_not_running_without_a_pipe",
            ])
            .env("PARDA_PIPE_NAME", unique)
            .env("PARDA_IPC_TEST_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}

// ---------------------------------------------------------------------------
// Platform-independent protocol checks
// ---------------------------------------------------------------------------

#[test]
fn every_request_roundtrips_through_json() {
    assert_eq!(PROTOCOL_VERSION, 1);
    let requests = [
        Request::Hello { version: 1 },
        Request::Status,
        Request::Redact {
            text: "é".into(),
            scope: Some("chat".into()),
        },
        Request::Restore {
            text: "⟦PERSON_1⟧".into(),
            scope: None,
        },
        Request::Scan {
            text: "世界".into(),
        },
        Request::PasteSafe,
        Request::Subscribe,
        Request::RulesGet,
        Request::RulesSet {
            rules_toml: String::new(),
        },
        Request::VaultStats,
        Request::VaultWipe { scope: None },
        Request::ConfigGet,
        Request::ConfigSet {
            toml: String::new(),
        },
        Request::Reload,
        Request::Shutdown,
    ];
    for req in requests {
        let line = serde_json::to_string(&req).unwrap();
        assert!(!line.contains('\n'), "NDJSON frames must be single-line");
        assert_eq!(serde_json::from_str::<Request>(&line).unwrap(), req);
    }
}
