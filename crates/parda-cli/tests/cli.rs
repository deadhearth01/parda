use assert_cmd::Command;
use predicates::prelude::*;

fn home() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        "[detect]\nmodel = \"none\"\n[vault]\nuse_keyring = false\n[clipboard]\nenabled = false\n",
    )
    .unwrap();
    dir
}

fn parda(home: &tempfile::TempDir) -> Command {
    let mut c = Command::cargo_bin("parda").unwrap();
    c.env("PARDA_HOME", home.path()).env("PARDA_QUIET", "1");
    c
}

#[test]
fn redact_hides_email() {
    let h = home();
    parda(&h)
        .args(["redact", "mail ravi.k@gmail.com"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ravi.k@").not())
        .stdout(predicate::str::contains("mail [EMAIL_1]"));
}

#[test]
fn stdin_redact_then_restore_round_trips() {
    let h = home();
    let text = "Call +91 98765 43210 or write to ravi.k@gmail.com\n";
    let out = parda(&h)
        .args(["redact", "-"])
        .write_stdin(text)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let red = String::from_utf8(out).unwrap();
    assert!(!red.contains("98765") && !red.contains("ravi.k@"), "{red}");
    parda(&h)
        .args(["restore", "-"])
        .write_stdin(red)
        .assert()
        .success()
        .stdout(text);
}

#[test]
fn scan_json_lists_kinds() {
    let h = home();
    let out = parda(&h)
        .args(["scan", "--json", "write to ravi.k@gmail.com"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let arr = v.as_array().unwrap();
    assert!(
        arr.iter()
            .any(|d| d["kind"] == "Email" && d["text"] == "ravi.k@gmail.com"),
        "{v}"
    );
}

#[test]
fn env_claude_prints_base_url() {
    let h = home();
    parda(&h)
        .args(["env", "claude"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "ANTHROPIC_BASE_URL=http://127.0.0.1:8787",
        ));
    parda(&h)
        .args(["env", "codex"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "OPENAI_BASE_URL=http://127.0.0.1:8787/v1",
        ));
}

#[test]
fn add_person_then_redact_hides_name() {
    let h = home();
    parda(&h)
        .args(["redact", "Meet Zubin Wadia today"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Zubin Wadia"));
    parda(&h)
        .args(["rules", "add-person", "Zubin Wadia"])
        .assert()
        .success();
    parda(&h)
        .args(["redact", "Meet Zubin Wadia today"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Zubin").not());
    parda(&h)
        .args(["rules", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Zubin Wadia"));
}

#[test]
fn vault_stats_and_wipe() {
    let h = home();
    parda(&h)
        .args(["redact", "ravi.k@gmail.com"])
        .assert()
        .success();
    parda(&h)
        .args(["vault", "stats"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Email"));
    parda(&h)
        .args(["vault", "wipe", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("removed 1"));
}

#[test]
fn status_without_daemon_and_model_list() {
    let h = home();
    parda(&h)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("not running"));
    parda(&h)
        .args(["model", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("gliner-pii-edge"));
    parda(&h)
        .args(["model", "use", "gliner-pii-small"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not installed"));
}

#[test]
fn doctor_runs() {
    let h = home();
    parda(&h)
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("daemon"));
}

#[test]
fn off_passes_text_through_with_warning_and_on_resumes() {
    let h = home();
    parda(&h)
        .arg("off")
        .assert()
        .success()
        .stdout(predicate::str::contains("OFF"));
    parda(&h)
        .args(["redact", "mail ravi.k@gmail.com"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ravi.k@gmail.com"))
        .stderr(predicate::str::contains("protection is OFF"));
    parda(&h).arg("on").assert().success();
    parda(&h)
        .args(["redact", "mail ravi.k@gmail.com"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ravi.k@").not());
}

#[test]
fn using_the_fp32_model_raises_the_ml_time_budget() {
    let h = home();
    let dir = h.path().join("data/models/parda-pii-edge");
    std::fs::create_dir_all(&dir).unwrap();
    for f in ["model.onnx", "tokenizer.json", "gliner_config.json"] {
        std::fs::write(dir.join(f), b"x").unwrap();
    }
    parda(&h)
        .args(["model", "use", "parda-pii-edge"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ml_timeout_ms = 1000"));
    let cfg = std::fs::read_to_string(h.path().join("config.toml")).unwrap();
    assert!(cfg.contains("ml_timeout_ms = 1000"), "{cfg}");
    assert!(cfg.contains("model = \"parda-pii-edge\""), "{cfg}");
}

#[test]
fn setup_keeps_an_installed_model_you_already_chose() {
    let h = home();
    let dir = h.path().join("data/models/parda-pii-edge");
    std::fs::create_dir_all(&dir).unwrap();
    for f in ["model.onnx", "tokenizer.json", "gliner_config.json"] {
        std::fs::write(dir.join(f), b"x").unwrap();
    }
    parda(&h)
        .args(["model", "use", "parda-pii-edge"])
        .assert()
        .success();
    parda(&h)
        .args(["setup", "--yes", "--no-service"])
        .assert()
        .success();
    let cfg = std::fs::read_to_string(h.path().join("config.toml")).unwrap();
    assert!(cfg.contains("model = \"parda-pii-edge\""), "{cfg}");
    // An explicit --model still wins.
    parda(&h)
        .args(["setup", "--yes", "--no-service", "--model", "none"])
        .assert()
        .success();
    let cfg = std::fs::read_to_string(h.path().join("config.toml")).unwrap();
    assert!(cfg.contains("model = \"none\""), "{cfg}");
}

#[test]
fn doctor_flags_misspelt_action_keys() {
    let h = home();
    let cfg = std::fs::read_to_string(h.path().join("config.toml")).unwrap();
    std::fs::write(
        h.path().join("config.toml"),
        format!("{cfg}[detect.actions]\nAadhar = \"block\"\n"),
    )
    .unwrap();
    parda(&h)
        .arg("doctor")
        .assert()
        .stdout(predicate::str::contains("`Aadhar` is not a built-in kind"));
}

#[test]
fn ca_create_path_and_status_without_touching_the_system() {
    let h = home();
    parda(&h)
        .args(["ca", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not created"));
    parda(&h)
        .args(["ca", "create"])
        .assert()
        .success()
        .stdout(predicate::str::contains("parda ca install"));
    let pem = h.path().join("data/parda-ca.pem");
    assert!(pem.is_file());
    parda(&h)
        .args(["ca", "path"])
        .assert()
        .success()
        .stdout(predicate::str::contains("parda-ca.pem"));
    // A second create keeps the existing certificate.
    parda(&h).args(["ca", "create"]).assert().failure();
    parda(&h)
        .args(["ca", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("created"));
}
