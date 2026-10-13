//! `parda doctor`: check the installation and explain what to do.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use parda_daemon::{load_config, load_rules};
use parda_ipc::Request;
use parda_ml::{ModelManager, default_model_id};
use parda_vault::{KeySource, find_key};

use super::{daemon_client, paths};

struct Report {
    problems: usize,
}

impl Report {
    fn ok(&self, what: &str, detail: impl AsRef<str>) {
        println!("  ✓ {what:<14} {}", detail.as_ref());
    }
    fn warn(&mut self, what: &str, detail: impl AsRef<str>) {
        self.problems += 1;
        println!("  ! {what:<14} {}", detail.as_ref());
    }
    fn info(&self, what: &str, detail: impl AsRef<str>) {
        println!("  · {what:<14} {}", detail.as_ref());
    }
}

pub fn run() -> anyhow::Result<()> {
    let p = paths()?;
    let mut r = Report { problems: 0 };
    println!("parda doctor (v{})", env!("CARGO_PKG_VERSION"));

    r.info("config dir", p.config_dir.display().to_string());
    r.info("data dir", p.data_dir.display().to_string());
    let config = match load_config(&p) {
        Ok(c) => {
            r.ok(
                "config",
                if p.config_file().exists() {
                    "valid"
                } else {
                    "defaults (no config.toml; run `parda setup`)"
                },
            );
            for key in c.suspicious_action_keys() {
                r.warn(
                    "config",
                    format!(
                        "[detect.actions] `{key}` is not a built-in kind (typo?) — it only applies to custom terms named `{key}`"
                    ),
                );
            }
            c
        }
        Err(e) => {
            r.warn("config", format!("{e:#}"));
            parda_core::Config::default()
        }
    };
    match load_rules(&p) {
        Ok(rules) => r.ok(
            "rules",
            format!(
                "{} people, {} terms, {} allowed",
                rules.person.len(),
                rules.term.len(),
                rules.allow.len()
            ),
        ),
        Err(e) => r.warn("rules", format!("{e:#}")),
    }

    match find_key(&p.data_dir, config.vault.use_keyring) {
        Ok(Some(KeySource::Keyring)) => r.ok("vault key", "OS keyring"),
        Ok(Some(KeySource::File(f))) => {
            r.ok("vault key", format!("key file {} (0600)", f.display()))
        }
        Ok(None) => r.info("vault key", "not created yet (created on first use)"),
        Err(e) => r.warn(
            "vault key",
            format!("{e} — `parda vault reset` starts over"),
        ),
    }

    let model = config.detect.model.as_str();
    if model == "none" {
        r.info("model", "disabled: names are only found via rules.toml");
    } else {
        let id = if model == "default" {
            default_model_id()
        } else {
            model
        };
        if ModelManager::new(&p.models_dir()).is_installed(id) {
            r.ok(
                "model",
                format!(
                    "{id} installed (execution provider: {})",
                    config.detect.execution_provider
                ),
            );
        } else {
            r.warn(
                "model",
                format!(
                    "{id} is not installed — in strict mode every request is refused; run `parda model pull {id}`"
                ),
            );
        }
    }
    r.info(
        "mode",
        format!(
            "{:?} (ML timeout {} ms)",
            config.detect.mode, config.detect.ml_timeout_ms
        )
        .to_lowercase(),
    );

    match daemon_client(&p) {
        Ok(Some(mut c)) => {
            let s = c.call(Request::Status)?;
            r.ok("daemon", format!("running (pid {})", s["pid"]));
            if let Some(err) = s["model_error"].as_str() {
                r.warn("daemon model", err);
            }
            match s["proxy"].as_str() {
                Some(a) => r.ok("proxy", format!("http://{a}")),
                None => r.info("proxy", "disabled"),
            }
            if s["clipboard"].as_bool() == Some(true) {
                r.ok(
                    "clipboard",
                    format!(
                        "watching (hotkey {})",
                        s["hotkey"].as_str().unwrap_or("default")
                    ),
                );
            } else {
                r.info("clipboard", "off");
            }
        }
        Ok(None) => {
            r.warn(
                "daemon",
                "not running — `parda service install` (or `parda daemon` in a terminal)",
            );
            let reachable = config
                .proxy
                .listen
                .to_socket_addrs()
                .ok()
                .and_then(|mut a| a.next())
                .is_some_and(|a| {
                    TcpStream::connect_timeout(&a, Duration::from_millis(300)).is_ok()
                });
            if reachable {
                r.warn(
                    "proxy port",
                    format!("{} is in use by another program", config.proxy.listen),
                );
            } else {
                r.ok("proxy port", format!("{} is free", config.proxy.listen));
            }
        }
        Err(e) => r.warn("daemon", format!("{e:#}")),
    }

    match arboard::Clipboard::new() {
        Ok(_) => r.ok("clipboard API", "available"),
        Err(e) => r.warn("clipboard API", format!("unavailable: {e}")),
    }
    if cfg!(target_os = "macos") {
        r.info(
            "accessibility",
            "paste-safe sends Cmd+V: allow parda in System Settings → Privacy & Security → Accessibility",
        );
    }
    if cfg!(target_os = "linux") && std::env::var_os("WAYLAND_DISPLAY").is_some() {
        r.info(
            "wayland",
            "global hotkeys are unavailable; bind a desktop shortcut to `parda paste-safe`",
        );
    }

    println!();
    if r.problems == 0 {
        println!("all good");
    } else {
        println!("{} problem(s) found", r.problems);
    }
    Ok(())
}
