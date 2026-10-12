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
