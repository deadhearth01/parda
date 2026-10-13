use std::time::{Duration, Instant};

use parda_daemon::{Paths, RunOptions, run, write_private};
use parda_ipc::{Client, Request};
use serde_json::Value;

fn wait_for_client(paths: &Paths) -> Client {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match Client::connect(&paths.runtime_dir) {
            Ok(c) => return c,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("daemon never came up: {e}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_serves_ipc_and_proxy_then_shuts_down() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::under(home.path().to_path_buf());
    paths.ensure().unwrap();
    write_private(
        &paths.config_file(),
        "[detect]\nmodel = \"none\"\n[proxy]\nlisten = \"127.0.0.1:0\"\n[clipboard]\nenabled = false\n[vault]\nuse_keyring = false\n",
    )
    .unwrap();
    write_private(&paths.rules_file(), "[[person]]\nname = \"Ravi Kumar\"\n").unwrap();
    let opts = RunOptions {
        proxy: true,
        clipboard: false,
        ipc: true,
        hotkey: false,
    };
    let daemon = tokio::spawn(run(paths.clone(), opts));

    let p = paths.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = wait_for_client(&p);
        let status = c.call(Request::Status).unwrap();
        let addr = std::fs::read_to_string(p.proxy_addr_file()).unwrap();
        assert_eq!(status["proxy"], Value::String(addr.clone()));
        assert!(addr.starts_with("127.0.0.1:") && !addr.ends_with(":0"));
        assert_eq!(status["model"], Value::Null);

        let text = "Ping Ravi Kumar at ravi.k@gmail.com";
        let red = c
            .call(Request::Redact {
                text: text.into(),
                scope: None,
            })
            .unwrap();
        let red_text = red["text"].as_str().unwrap().to_string();
        assert!(
            !red_text.contains("Ravi") && !red_text.contains("ravi.k@"),
            "{red_text}"
        );
        let back = c
            .call(Request::Restore {
                text: red_text,
                scope: None,
            })
            .unwrap();
        assert_eq!(back["text"], text);

        let scan = c.call(Request::Scan { text: text.into() }).unwrap();
        assert_eq!(scan["detections"].as_array().unwrap().len(), 2);

        let stats = c.call(Request::VaultStats).unwrap();
        assert!(!stats["stats"].as_array().unwrap().is_empty());

        // Rules round-trip through the daemon and the file.
        let rules = c.call(Request::RulesGet).unwrap();
        assert!(rules["toml"].as_str().unwrap().contains("Ravi Kumar"));
        c.call(Request::RulesSet {
            rules_toml: "[[person]]\nname = \"Zubin Wadia\"\n".into(),
        })
        .unwrap();
        assert!(
            std::fs::read_to_string(p.rules_file())
                .unwrap()
                .contains("Zubin")
        );
        let red = c
            .call(Request::Redact {
                text: "Zubin Wadia".into(),
                scope: None,
            })
            .unwrap();
        assert_ne!(red["text"], "Zubin Wadia");

        let bad = c.call(Request::ConfigSet {
            toml: "[nope]".into(),
        });
        assert!(bad.is_err());
        assert!(c.call(Request::PasteSafe).is_err());
        c.call(Request::Shutdown).unwrap();
    })
    .await
    .unwrap();

    let res = tokio::time::timeout(Duration::from_secs(10), daemon)
        .await
        .expect("daemon stopped after Shutdown")
        .unwrap();
    res.unwrap();
    assert!(!paths.proxy_addr_file().exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_daemon_refuses_to_start() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::under(home.path().to_path_buf());
    paths.ensure().unwrap();
    write_private(
        &paths.config_file(),
        "[detect]\nmodel = \"none\"\n[clipboard]\nenabled = false\n[vault]\nuse_keyring = false\n",
    )
    .unwrap();
    let opts = RunOptions {
        proxy: false,
        clipboard: false,
        ipc: true,
        hotkey: false,
    };
    let first = tokio::spawn(run(paths.clone(), opts));
    let p = paths.clone();
    let mut c = tokio::task::spawn_blocking(move || wait_for_client(&p))
        .await
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(10), run(paths.clone(), opts))
        .await
        .expect("second daemon returns");
    let err = format!("{:#}", second.unwrap_err());
    assert!(err.contains("in use"), "{err}");
    // The first daemon is unaffected.
    tokio::task::spawn_blocking(move || {
        c.call(Request::Status).unwrap();
        c.call(Request::Shutdown).unwrap();
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), first)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

const BASE_CONFIG: &str =
    "[detect]\nmodel = \"none\"\n[clipboard]\nenabled = false\n[vault]\nuse_keyring = false\n";

fn home_with(config: &str) -> (tempfile::TempDir, Paths) {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::under(home.path().to_path_buf());
    paths.ensure().unwrap();
    write_private(&paths.config_file(), config).unwrap();
    (home, paths)
}

/// A minimal HTTP/1.1 POST; returns (status, body).
fn http_post(addr: &str, path: &str, body: &str) -> (u16, String) {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         anthropic-version: 2023-06-01\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let status = out[9..12].parse().unwrap();
    let body = out
        .split_once("\r\n\r\n")
        .map(|x| x.1)
        .unwrap_or("")
        .to_string();
    (status, body)
}

const ALL: RunOptions = RunOptions {
    proxy: true,
    clipboard: false,
    ipc: true,
    hotkey: false,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_settings_apply_without_restart() {
    let config = format!(
        "{BASE_CONFIG}[proxy]\nlisten = \"127.0.0.1:0\"\nanthropic_upstream = \"http://127.0.0.1:9\"\n"
    );
    let (_home, paths) = home_with(&config);
    let daemon = tokio::spawn(run(paths.clone(), ALL));
    let p = paths.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = wait_for_client(&p);
        let addr = std::fs::read_to_string(p.proxy_addr_file()).unwrap();
        let image = r#"{"model":"m","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}]}]}"#;
        // Forwarded (and the closed upstream port answers 502).
        assert_eq!(http_post(&addr, "/v1/messages", image).0, 502);

        let toml = format!("{config}unscanned_media = \"block\"\n");
        let res = c.call(Request::ConfigSet { toml }).unwrap();
        assert_eq!(res["restart_required"], false);
        let (status, body) = http_post(&addr, "/v1/messages", image);
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("parda_unscanned_media"), "{body}");

        // A new listen address does need a restart.
        let toml = config.replace("127.0.0.1:0", "127.0.0.1:1");
        let res = c.call(Request::ConfigSet { toml }).unwrap();
        assert_eq!(res["restart_required"], true);
        c.call(Request::Shutdown).unwrap();
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), daemon)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_loopback_listen_is_refused_without_the_flag() {
    let (_home, paths) = home_with(&format!("{BASE_CONFIG}[proxy]\nlisten = \"0.0.0.0:0\"\n"));
    let res = tokio::time::timeout(Duration::from_secs(10), run(paths.clone(), ALL))
        .await
        .expect("daemon returns");
    let err = format!("{:#}", res.unwrap_err());
    assert!(err.contains("allow_non_loopback"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_daemon_leaves_the_first_daemons_files_alone() {
    let (_home, paths) = home_with(&format!("{BASE_CONFIG}[proxy]\nlisten = \"127.0.0.1:0\"\n"));
    let first = tokio::spawn(run(paths.clone(), ALL));
    let p = paths.clone();
    let mut c = tokio::task::spawn_blocking(move || wait_for_client(&p))
        .await
        .unwrap();
    let addr = std::fs::read_to_string(paths.proxy_addr_file()).unwrap();
    let second = tokio::time::timeout(Duration::from_secs(10), run(paths.clone(), ALL))
        .await
        .expect("second daemon returns");
    let err = format!("{:#}", second.unwrap_err());
    assert!(err.contains("already running"), "{err}");
    assert_eq!(
        std::fs::read_to_string(paths.proxy_addr_file()).unwrap(),
        addr
    );
    tokio::task::spawn_blocking(move || {
        c.call(Request::Status).unwrap();
        c.call(Request::Shutdown).unwrap();
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), first)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
