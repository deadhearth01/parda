//! An accept error (here EMFILE: out of file descriptors) must not end the
//! server: the daemon would otherwise shut every service down.
//!
//! Its own test binary: it lowers the process-wide descriptor limit.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use parda_ipc::{Event, Handler, Request, Response, serve};
use serde_json::json;
use tokio::sync::broadcast;

struct Ok200;

impl Handler for Ok200 {
    fn handle(&self, _req: Request) -> Response {
        Response::ok(json!({}))
    }
    fn subscribe(&self) -> broadcast::Receiver<Event> {
        broadcast::channel(1).1
    }
}

// rlim_t is u64 on the platforms tested here but not everywhere.
#[allow(unsafe_code, clippy::unnecessary_cast)]
fn set_fd_limit(soft: u64) -> u64 {
    // SAFETY: getrlimit/setrlimit read and write one plain struct.
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim), 0);
        let old = lim.rlim_cur as u64;
        lim.rlim_cur = soft as libc::rlim_t;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lim), 0);
        old
    }
}

#[test]
fn accept_errors_do_not_stop_the_server() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runtime_dir = dir.path().join("run");
    let rd = runtime_dir.clone();
    let server = rt.spawn(async move { serve(&rd, Arc::new(Ok200)).await });
    let sock = runtime_dir.join("parda.sock");
    for _ in 0..200 {
        if UnixStream::connect(&sock).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(100));

    // Leave exactly one free descriptor: the client takes it, the server's
    // accept then fails with EMFILE.
    let probe = std::fs::File::open("/dev/null").unwrap();
    let lowest_free = std::os::fd::AsRawFd::as_raw_fd(&probe) as u64;
    drop(probe);
    let old = set_fd_limit(lowest_free + 1);
    let client = UnixStream::connect(&sock);
    std::thread::sleep(Duration::from_millis(300));
    let alive = !server.is_finished();
    set_fd_limit(old);
    // The kernel may drop the connection whose accept failed (macOS does);
    // what matters is that later clients are still served.
    drop(client.expect("client connected with the last descriptor"));
    assert!(alive, "the server stopped on an accept error");
    std::thread::sleep(Duration::from_millis(1100));
    assert!(
        !server.is_finished(),
        "the server stopped on an accept error"
    );

    let mut client = UnixStream::connect(&sock).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(b"{\"op\":\"Hello\",\"version\":1}\n")
        .unwrap();
    let mut line = String::new();
    BufReader::new(&client).read_line(&mut line).unwrap();
    assert!(line.contains("\"version\":1"), "{line}");
    server.abort();
}
