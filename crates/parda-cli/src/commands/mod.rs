//! Subcommands, and the shared "talk to the daemon, else run in-process"
//! plumbing.

pub mod ca;
pub mod daemon;
pub mod doctor;
pub mod env;
pub mod intercept;
pub mod model;
pub mod protection;
pub mod redact;
pub mod rules;
pub mod service;
pub mod setup;
pub mod status;
pub mod tui;
pub mod vault;

use std::io::Read;

use anyhow::Context;
use parda_daemon::{Paths, load_config, load_model, load_rules};
use parda_engine::{Engine, EngineOptions};
use parda_ipc::Client;

pub fn paths() -> anyhow::Result<Paths> {
    Paths::resolve()
}

/// A connected daemon client, or `None` when no daemon runs.
pub fn daemon_client(paths: &Paths) -> anyhow::Result<Option<Client>> {
    match Client::connect(&paths.runtime_dir) {
        Ok(c) => Ok(Some(c)),
        Err(e) if e.is_not_running() => Ok(None),
        Err(e) => Err(e).context("connecting to the parda daemon"),
    }
}

/// An in-process engine with the configured model (slower to start).
pub fn local_engine(paths: &Paths) -> anyhow::Result<Engine> {
    paths.ensure()?;
    let config = load_config(paths)?;
    let rules = load_rules(paths)?;
    let (ml, err) = load_model(paths, &config);
    if let Some(err) = err {
        eprintln!("parda: model not loaded: {err}");
    }
    Engine::open(
        EngineOptions {
            config: config.clone(),
            rules,
            data_dir: paths.data_dir.clone(),
            use_keyring: config.vault.use_keyring,
        },
        ml,
    )
    .context("opening the vault")
}

/// Text from the argument, or stdin when it is `-` or missing.
pub fn input_text(arg: Option<String>) -> anyhow::Result<String> {
    match arg.as_deref() {
        Some("-") | None => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            Ok(s)
        }
        Some(t) => Ok(t.to_string()),
    }
}

pub fn hint_in_process() {
    if std::env::var_os("PARDA_QUIET").is_none() {
        eprintln!(
            "parda: daemon not running; using an in-process engine (start it with `parda daemon` or `parda service install`)"
        );
    }
}
