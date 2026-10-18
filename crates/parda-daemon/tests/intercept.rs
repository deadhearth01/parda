//! The daemon hosts the intercept listener: only with an existing CA, with
//! its address in `intercept.addr`, its events on the daemon's feed (never
//! values), configuration changes applied live, and a clean shutdown.
//!
//! No network: listed hosts are only sent requests parda refuses before
//! contacting the real server, and tunnels go to a local echo server.

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use parda_daemon::{Paths, RunOptions, ca_store, run, write_private};
use parda_ipc::{Client, Request};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const BASE: &str = "[detect]\nmodel = \"none\"\n[clipboard]\nenabled = false\n\
                    [vault]\nuse_keyring = false\n[proxy]\nlisten = \"127.0.0.1:0\"\n";

const ALL: RunOptions = RunOptions {
    proxy: true,
    clipboard: false,
    ipc: true,
    hotkey: false,
};

fn config(intercept: &str) -> String {
    format!("{BASE}[intercept]\n{intercept}")
}

fn home_with(config: &str) -> (tempfile::TempDir, Paths) {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::under(home.path().to_path_buf());
    paths.ensure().unwrap();
    write_private(&paths.config_file(), config).unwrap();
    (home, paths)
}

/// One IPC call (on a blocking thread), waiting for the daemon to come up.
async fn ipc(paths: &Paths, req: Request) -> anyhow::Result<Value> {
    let dir = paths.runtime_dir.clone();
    tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut c = loop {
            match Client::connect(&dir) {
                Ok(c) => break c,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(e) => panic!("daemon never came up: {e}"),
            }
        };
        Ok(c.call(req)?)
    })
    .await
    .unwrap()
}

async fn status(paths: &Paths) -> Value {
    ipc(paths, Request::Status).await.unwrap()
}

async fn set_config(paths: &Paths, toml: String) -> Value {
    ipc(paths, Request::ConfigSet { toml }).await.unwrap()
}

async fn stop(paths: &Paths, daemon: tokio::task::JoinHandle<anyhow::Result<()>>) {
    ipc(paths, Request::Shutdown).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), daemon)
        .await
        .expect("daemon stopped")
        .unwrap()
        .unwrap();
}

fn listening(st: &Value) -> Option<SocketAddr> {
    st["intercept"]["listening"]
        .as_str()
        .map(|a| a.parse().unwrap())
}

/// A client that uses the intercept listener as its proxy and trusts only
/// the parda CA in `paths`.
fn client(paths: &Paths, proxy: SocketAddr) -> reqwest::Client {
    let pem = std::fs::read(ca_store::ca_cert_path(paths)).unwrap();
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{proxy}")).unwrap())
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(&pem).unwrap())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

/// A request to listed host `chat.test` that parda refuses before
/// contacting the real server (so no network is needed); returns the status.
async fn refused_request(
    paths: &Paths,
    proxy: SocketAddr,
    content_type: &str,
    body: impl Into<reqwest::Body>,
) -> u16 {
    client(paths, proxy)
        .post("https://chat.test/api/send?q=secret-query")
        .header("content-type", content_type)
        .body(body)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn pac(proxy: SocketAddr) -> String {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{proxy}/parda.pac"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
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

/// Wait until nothing accepts connections on `addr`.
async fn released(addr: SocketAddr) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).await.is_err() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

fn recent(st: &Value) -> Vec<Value> {
    st["activity"]["recent"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn addr_file(paths: &Paths) -> Option<String> {
    std::fs::read_to_string(paths.intercept_addr_file()).ok()
}

#[cfg(unix)]
fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_runs_the_intercept_listener_with_an_existing_ca() {
    let (_home, paths) = home_with(&config(
        "enabled = true\nlisten = \"127.0.0.1:0\"\nhosts = [\"chat.test\"]\n",
    ));
    ca_store::create_ca(&paths, false, false).unwrap();
    let daemon = tokio::spawn(run(paths.clone(), ALL));

    let st = status(&paths).await;
    let addr = listening(&st).expect("listening");
    assert!(addr.ip().is_loopback() && addr.port() != 0);
    assert_eq!(st["intercept"]["ca"], true);
    assert_eq!(st["intercept"]["enabled"], true);
    assert_eq!(st["intercept"]["error"], Value::Null);
    // The proxy keeps its own field (backwards compatible).
    assert!(st["proxy"].is_string());
    assert_eq!(
        addr_file(&paths).as_deref(),
        Some(addr.to_string().as_str())
    );
    #[cfg(unix)]
    assert_eq!(mode(&paths.intercept_addr_file()), 0o600);

    // The PAC names the listed hosts and this listener.
    let pac = pac(addr).await;
    assert!(pac.contains("\"chat.test\"") && pac.contains(&format!("PROXY {addr}")));

    // A non-listed host is tunnelled byte for byte.
    let port = echo().await;
    let mut t = TcpStream::connect(addr).await.unwrap();
    t.write_all(
        format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut head = [0u8; 64];
    let n = t.read(&mut head).await.unwrap();
    assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"));
    t.write_all(b"ping").await.unwrap();
    let mut pong = [0u8; 4];
    t.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"ping");

    // A listed host is decrypted (parda's CA) and its events reach the
    // daemon's feed, without values or the query string.
    let status_code = refused_request(
        &paths,
        addr,
        "application/json",
        "{\"prompt\": \"Ravi Kumar",
    )
    .await;
    assert_eq!(status_code, 400);
    let deadline = Instant::now() + Duration::from_secs(5);
    let ev = loop {
        let st = status(&paths).await;
        if let Some(ev) = recent(&st)
            .into_iter()
            .find(|e| e["surface"] == "intercept" && e["summary"].as_str().unwrap().contains("400"))
        {
            break ev;
        }
        assert!(Instant::now() < deadline, "no intercept event: {st}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let summary = ev["summary"].as_str().unwrap();
    assert!(summary.contains("chat.test"), "{summary}");
    assert!(summary.contains("refused"), "{summary}");
    assert_eq!(ev["level"], "warn");
    let st = status(&paths).await;
    let all = st["activity"].to_string();
    assert!(
        !all.contains("Ravi") && !all.contains("secret-query"),
        "{all}"
    );
    // Only the request counts: the "listening" notice is not activity.
    assert_eq!(st["activity"]["surfaces"]["intercept"]["warnings"], 1);
    assert_eq!(st["activity"]["surfaces"]["intercept"]["events"], 1);

    stop(&paths, daemon).await;
    assert!(addr_file(&paths).is_none(), "intercept.addr removed");
    assert!(released(addr).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_ca_intercept_does_not_listen_and_says_why() {
    let intercept = "enabled = true\nlisten = \"127.0.0.1:0\"\nhosts = [\"chat.test\"]\n";
    let (_home, paths) = home_with(&config(intercept));
    let daemon = tokio::spawn(run(paths.clone(), ALL));

    let st = status(&paths).await;
    assert_eq!(listening(&st), None);
    assert_eq!(st["intercept"]["ca"], false);
    let error = st["intercept"]["error"].as_str().unwrap();
    assert!(error.contains("parda ca create"), "{error}");
    let warn = recent(&st)
        .into_iter()
        .find(|e| e["surface"] == "intercept")
        .expect("a warning event");
    assert_eq!(warn["level"], "warn");
    assert!(
        warn["summary"]
            .as_str()
            .unwrap()
            .contains("no CA — run `parda ca create`"),
        "{warn}"
    );
    assert!(addr_file(&paths).is_none());
    // A notice, not intercepted traffic: no intercept totals.
    assert_eq!(st["activity"]["surfaces"]["intercept"], Value::Null, "{st}");
    // Never created implicitly.
    assert!(!ca_store::ca_exists(&paths));

    // Once the CA exists, a reload starts the listener.
    ca_store::create_ca(&paths, false, false).unwrap();
    let res = ipc(&paths, Request::Reload).await.unwrap();
    assert_eq!(res["restart_required"], false);
    let st = status(&paths).await;
    let addr = listening(&st).expect("listening after reload");
    assert_eq!(st["intercept"]["error"], Value::Null);
    assert_eq!(
        addr_file(&paths).as_deref(),
        Some(addr.to_string().as_str())
    );

    stop(&paths, daemon).await;
}

/// Binary data: never read as text, so unscanned (UTF-8 text is read
/// whatever its declared type).
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\xff";

/// An `[intercept]` section.
fn section(enabled: bool, listen: &str, hosts: &str, unscanned: &str) -> String {
    config(&format!(
        "enabled = {enabled}\nlisten = \"{listen}\"\nhosts = {hosts}\nunscanned = \"{unscanned}\"\n"
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn intercept_settings_apply_live() {
    let one = "[\"chat.test\"]";
    let two = "[\"chat.test\", \"other.test\"]";
    let (_home, paths) = home_with(&section(false, "127.0.0.1:0", one, "allow"));
    ca_store::create_ca(&paths, false, false).unwrap();
    let daemon = tokio::spawn(run(paths.clone(), ALL));

    let st = status(&paths).await;
    assert_eq!(listening(&st), None);
    assert_eq!(st["intercept"]["enabled"], false);
    assert_eq!(st["intercept"]["error"], Value::Null);

    // Switched on: starts listening, no daemon restart.
    let res = set_config(&paths, section(true, "127.0.0.1:0", one, "allow")).await;
    assert_eq!(res["restart_required"], false);
    let addr = listening(&status(&paths).await).expect("listening");
    assert_eq!(res["intercept"]["listening"], addr.to_string());
    assert_eq!(
        addr_file(&paths).as_deref(),
        Some(addr.to_string().as_str())
    );

    // Hosts and unscanned apply to the running listener (same address).
    let res = set_config(&paths, section(true, "127.0.0.1:0", two, "block")).await;
    assert_eq!(res["restart_required"], false);
    assert_eq!(listening(&status(&paths).await), Some(addr));
    assert!(pac(addr).await.contains("\"other.test\""));
    assert_eq!(refused_request(&paths, addr, "image/png", PNG).await, 415);

    // A new listen address restarts the listener there.
    let free = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let res = set_config(&paths, section(true, &free.to_string(), two, "block")).await;
    assert_eq!(res["restart_required"], false);
    assert_eq!(listening(&status(&paths).await), Some(free));
    assert!(released(addr).await, "old listener closed");
    assert_eq!(
        addr_file(&paths).as_deref(),
        Some(free.to_string().as_str())
    );
    assert!(pac(free).await.contains(&format!("PROXY {free}")));

    // Switched off: stops listening and removes the address file.
    let res = set_config(&paths, section(false, &free.to_string(), two, "block")).await;
    assert_eq!(res["restart_required"], false);
    assert_eq!(listening(&status(&paths).await), None);
    assert!(addr_file(&paths).is_none());
    assert!(released(free).await);

    stop(&paths, daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_loopback_intercept_listen_is_reported_not_fatal() {
    let (_home, paths) = home_with(&config("enabled = true\nlisten = \"0.0.0.0:0\"\n"));
    ca_store::create_ca(&paths, false, false).unwrap();
    let daemon = tokio::spawn(run(paths.clone(), ALL));
    let st = status(&paths).await;
    assert_eq!(listening(&st), None);
    let error = st["intercept"]["error"].as_str().unwrap();
    assert!(error.contains("loopback"), "{error}");
    // The rest of the daemon runs.
    assert!(st["proxy"].is_string());
    stop(&paths, daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pac_left_on_without_a_listener_is_warned_about() {
    // `parda intercept on` ran earlier (its state file is here), but the
    // listener is off now: AI sites would fail to load.
    let (_home, paths) = home_with(&config("enabled = false\n"));
    let pac_url = "http://127.0.0.1:8788/parda.pac";
    write_private(
        &paths.data_dir.join("intercept-state.json"),
        &format!(r#"{{"platform":"MacOs","pac_url":"{pac_url}","saved":[]}}"#),
    )
    .unwrap();
    let daemon = tokio::spawn(run(paths.clone(), ALL));
    let st = status(&paths).await;
    assert_eq!(st["intercept"]["pac"], pac_url);
    assert_eq!(listening(&st), None);
    let warn = recent(&st)
        .into_iter()
        .find(|e| e["surface"] == "intercept" && e["level"] == "warn")
        .expect("a warning event");
    let summary = warn["summary"].as_str().unwrap();
    assert!(
        summary.contains("fail to load") && summary.contains("parda intercept off"),
        "{summary}"
    );
    stop(&paths, daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replaced_ca_restarts_the_listener_on_reload() {
    let (_home, paths) = home_with(&config(
        "enabled = true\nlisten = \"127.0.0.1:0\"\nhosts = [\"chat.test\"]\n",
    ));
    ca_store::create_ca(&paths, false, false).unwrap();
    let daemon = tokio::spawn(run(paths.clone(), ALL));
    let first = listening(&status(&paths).await).expect("listening");
    // The old CA still signs.
    assert_eq!(
        refused_request(&paths, first, "application/json", "{").await,
        400
    );

    ca_store::create_ca(&paths, false, true).unwrap();
    ipc(&paths, Request::Reload).await.unwrap();
    let second = listening(&status(&paths).await).expect("listening again");
    // The new CA signs (the client trusts only the file's certificate now).
    assert_eq!(
        refused_request(&paths, second, "application/json", "{").await,
        400
    );
    stop(&paths, daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replaced_ca_is_picked_up_without_a_reload() {
    // `parda ca uninstall` + `parda ca create --force` + `parda ca install`
    // send no config change: the daemon notices the new file by itself.
    let (_home, paths) = home_with(&config(
        "enabled = true\nlisten = \"127.0.0.1:0\"\nhosts = [\"chat.test\"]\n",
    ));
    ca_store::create_ca(&paths, false, false).unwrap();
    let daemon = tokio::spawn(run(paths.clone(), ALL));
    let first = listening(&status(&paths).await).expect("listening");
    ca_store::create_ca(&paths, false, true).unwrap();

    // On its own, within a few seconds (no IPC call at all).
    let deadline = Instant::now() + Duration::from_secs(10);
    while addr_file(&paths).as_deref() == Some(first.to_string().as_str()) {
        assert!(Instant::now() < deadline, "listener never restarted");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let second = listening(&status(&paths).await).expect("listening again");
    assert_ne!(second, first);
    assert_eq!(
        refused_request(&paths, second, "application/json", "{").await,
        400,
        "the new CA signs"
    );

    // A status call checks too, at once.
    ca_store::create_ca(&paths, false, true).unwrap();
    let third = listening(&status(&paths).await).expect("listening");
    assert_ne!(third, second);
    assert_eq!(
        refused_request(&paths, third, "application/json", "{").await,
        400
    );
    stop(&paths, daemon).await;
}

/// Final review: with intercept wanted but no CA at start, `parda ca
/// create` (which pings the daemon with a status request) must start the
/// listener; so must the timer alone. Before, nothing retried once no
/// listener ran, and the status kept the stale "no CA" error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ca_created_while_the_daemon_runs_starts_the_listener() {
    for ping in [true, false] {
        let (_home, paths) = home_with(&config(
            "enabled = true\nlisten = \"127.0.0.1:0\"\nhosts = [\"chat.test\"]\n",
        ));
        let daemon = tokio::spawn(run(paths.clone(), ALL));
        let st = status(&paths).await;
        assert_eq!(listening(&st), None, "{st}");
        assert!(st["intercept"]["error"].as_str().unwrap().contains("no CA"));

        ca_store::create_ca(&paths, false, false).unwrap();
        let addr = if ping {
            // What `parda ca create` does next.
            listening(&status(&paths).await)
        } else {
            let deadline = Instant::now() + Duration::from_secs(10);
            while addr_file(&paths).is_none() {
                assert!(Instant::now() < deadline, "the timer never started it");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            listening(&status(&paths).await)
        };
        let st = status(&paths).await;
        let addr = addr.unwrap_or_else(|| panic!("ping={ping}: not listening: {st}"));
        assert!(st["intercept"]["error"].is_null(), "{st}");
        assert_eq!(
            refused_request(&paths, addr, "application/json", "{").await,
            400
        );
        stop(&paths, daemon).await;
    }
}

/// A certificate that is missing for a moment (seen by a status request or
/// the timer) stops the listener; once it is back, intercept runs again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_certificate_missing_for_a_moment_does_not_stop_intercept_for_good() {
    let (_home, paths) = home_with(&config(
        "enabled = true\nlisten = \"127.0.0.1:0\"\nhosts = [\"chat.test\"]\n",
    ));
    ca_store::create_ca(&paths, false, false).unwrap();
    let daemon = tokio::spawn(run(paths.clone(), ALL));
    assert!(listening(&status(&paths).await).is_some());
    let cert = ca_store::ca_cert_path(&paths);
    let aside = cert.with_extension("pem.aside");
    std::fs::rename(&cert, &aside).unwrap();
    assert_eq!(listening(&status(&paths).await), None);
    std::fs::rename(&aside, &cert).unwrap();
    let st = status(&paths).await;
    let addr = listening(&st).unwrap_or_else(|| panic!("not listening again: {st}"));
    assert!(st["intercept"]["error"].is_null(), "{st}");
    assert_eq!(
        refused_request(&paths, addr, "application/json", "{").await,
        400
    );
    stop(&paths, daemon).await;
}

/// `create --force` while the daemon checks the certificate over and over
/// (the TUI polls status every second): the listener survives the rotation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forced_ca_rotation_racing_status_requests_keeps_intercept_on() {
    let (_home, paths) = home_with(&config(
        "enabled = true\nlisten = \"127.0.0.1:0\"\nhosts = [\"chat.test\"]\n",
    ));
    ca_store::create_ca(&paths, false, false).unwrap();
    let daemon = tokio::spawn(run(paths.clone(), ALL));
    assert!(listening(&status(&paths).await).is_some());
    let stop_pings = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let pinger = {
        let (dir, stop_pings) = (paths.runtime_dir.clone(), stop_pings.clone());
        std::thread::spawn(move || {
            let mut c = Client::connect(&dir).unwrap();
            while !stop_pings.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = c.call(Request::Status);
            }
        })
    };
    for _ in 0..20 {
        ca_store::create_ca(&paths, false, true).unwrap();
    }
    stop_pings.store(true, std::sync::atomic::Ordering::Relaxed);
    pinger.join().unwrap();
    let st = status(&paths).await;
    let addr = listening(&st).unwrap_or_else(|| panic!("intercept lost: {st}"));
    assert_eq!(
        refused_request(&paths, addr, "application/json", "{").await,
        400,
        "the newest CA signs"
    );
    stop(&paths, daemon).await;
}

/// A loopback port nothing listens on.
async fn free_port() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listener_moved_away_from_the_system_pac_is_flagged() {
    let at = free_port().await;
    let pac_url = format!("http://{at}/parda.pac");
    let (_home, paths) = home_with(&section(true, &at.to_string(), "[\"chat.test\"]", "allow"));
    ca_store::create_ca(&paths, false, false).unwrap();
    // `parda intercept on` pointed the system at this address.
    write_private(
        &paths.data_dir.join("intercept-state.json"),
        &format!(r#"{{"platform":"MacOs","pac_url":"{pac_url}","saved":[]}}"#),
    )
    .unwrap();
    let daemon = tokio::spawn(run(paths.clone(), ALL));
    let st = status(&paths).await;
    assert_eq!(listening(&st), Some(at));
    assert_eq!(st["intercept"]["pac_matches"], true);
    let moved = |st: &Value| {
        recent(st).into_iter().find(|e| {
            e["level"] == "warn"
                && e["summary"]
                    .as_str()
                    .unwrap()
                    .contains("parda intercept on")
        })
    };
    assert!(moved(&st).is_none(), "{st}");

    // intercept.listen changes live; the system still fetches the old PAC.
    let other = free_port().await;
    let res = set_config(
        &paths,
        section(true, &other.to_string(), "[\"chat.test\"]", "allow"),
    )
    .await;
    assert_eq!(res["intercept"]["listening"], other.to_string());
    assert_eq!(res["intercept"]["pac_matches"], false);
    let st = status(&paths).await;
    assert_eq!(st["intercept"]["pac_matches"], false);
    let warn = moved(&st).expect("a warning event");
    let summary = warn["summary"].as_str().unwrap();
    assert!(
        summary.contains(&pac_url) && summary.contains(&other.to_string()),
        "{summary}"
    );

    // No PAC set: nothing to compare.
    std::fs::remove_file(paths.data_dir.join("intercept-state.json")).unwrap();
    assert_eq!(
        status(&paths).await["intercept"]["pac_matches"],
        Value::Null
    );
    stop(&paths, daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_host_says_browsers_must_fetch_the_pac_again() {
    let at = free_port().await;
    let one = "[\"chat.test\"]";
    let two = "[\"chat.test\", \"new.test\"]";
    let (_home, paths) = home_with(&section(true, &at.to_string(), one, "allow"));
    ca_store::create_ca(&paths, false, false).unwrap();
    let daemon = tokio::spawn(run(paths.clone(), ALL));
    let refetch = |st: &Value| {
        recent(st)
            .into_iter()
            .filter(|e| e["summary"].as_str().unwrap().contains("fetch"))
            .count()
    };
    // No system PAC set yet: nothing to fetch again.
    listening(&status(&paths).await).expect("listening");
    set_config(&paths, section(true, &at.to_string(), two, "allow")).await;
    assert_eq!(refetch(&status(&paths).await), 0);

    write_private(
        &paths.data_dir.join("intercept-state.json"),
        &format!(r#"{{"platform":"MacOs","pac_url":"http://{at}/parda.pac","saved":[]}}"#),
    )
    .unwrap();
    let three = "[\"chat.test\", \"new.test\", \"third.test\"]";
    set_config(&paths, section(true, &at.to_string(), three, "allow")).await;
    let st = status(&paths).await;
    assert_eq!(refetch(&st), 1, "{st}");
    let ev = recent(&st)
        .into_iter()
        .find(|e| e["summary"].as_str().unwrap().contains("fetch"))
        .unwrap();
    let summary = ev["summary"].as_str().unwrap();
    assert!(
        summary.contains("third.test") && !summary.contains("new.test"),
        "{summary}"
    );
    // Removing a host needs nothing (it still reaches parda, tunnelled).
    set_config(&paths, section(true, &at.to_string(), one, "allow")).await;
    assert_eq!(refetch(&status(&paths).await), 1);
    stop(&paths, daemon).await;
}
