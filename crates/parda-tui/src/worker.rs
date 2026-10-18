//! The background worker: it owns the IPC client(s), so the UI thread never
//! blocks on the daemon. The UI sends [`Cmd`]s and gets [`Msg`]s back.
//!
//! [`exec`] does the work of one command against any [`Backend`]; the
//! worker thread runs it for the live daemon, and tests (and `--dump`) run
//! it synchronously against a fake. Every second the worker refreshes the
//! status and the configuration, and the data of the visible tab (rules,
//! vault) — never the others.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use parda_core::Config;
use parda_ipc::{Client, Event, IpcError, Request};
use serde_json::Value;

use crate::app::Tab;
use crate::{Backend, UiEvent};

/// How often the worker refreshes status and configuration.
pub const REFRESH: Duration = Duration::from_secs(1);

/// A configuration change, applied to the daemon's current configuration.
pub type ConfigEdit = Box<dyn FnOnce(&mut Config) + Send>;

/// Work for the worker.
pub enum Cmd {
    /// This tab is now visible: refresh status, config and its data now.
    Visible(Tab),
    /// Refresh status, config and the data of `tab`.
    Refresh(Tab),
    /// Read the configuration, change it, save it (ConfigSet).
    SetConfig(ConfigEdit),
    SetRules(String),
    VaultWipe(Option<String>),
    /// Redact (then restore) Inspector text.
    Redact(String),
    /// Start the daemon (only ever sent after the user pressed the key).
    StartDaemon,
}

impl std::fmt::Debug for Cmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cmd::Visible(t) => write!(f, "Visible({t:?})"),
            Cmd::Refresh(t) => write!(f, "Refresh({t:?})"),
            Cmd::SetConfig(_) => write!(f, "SetConfig"),
            Cmd::SetRules(_) => write!(f, "SetRules"),
            Cmd::VaultWipe(s) => write!(f, "VaultWipe({s:?})"),
            Cmd::Redact(_) => write!(f, "Redact"),
            Cmd::StartDaemon => write!(f, "StartDaemon"),
        }
    }
}

/// What the Inspector shows after a redaction.
#[derive(Debug, Clone, PartialEq)]
pub struct Redaction {
    pub text: String,
    pub replaced: Vec<Value>,
    pub restored: Option<String>,
}

/// Results for the UI.
#[derive(Debug, Clone, PartialEq)]
pub enum Msg {
    /// The daemon status; `Err` = unreachable (the offline screen).
    Status(Result<Value, String>),
    /// The daemon's config.toml.
    Config(String),
    Rules(String),
    Vault(Vec<Value>),
    /// ConfigSet's answer. `intercept`: Some(true) switched on, Some(false)
    /// off; `protection`: the new state when it changed.
    ConfigSaved {
        result: Result<Value, String>,
        intercept: Option<bool>,
        protection: Option<bool>,
    },
    RulesSaved(Result<(), String>),
    VaultWiped {
        scope: Option<String>,
        result: Result<Value, String>,
    },
    Redacted(Result<Redaction, String>),
    Started(Result<String, String>),
    Event(Event),
}

fn err(e: anyhow::Error) -> String {
    format!("{e:#}")
}

fn refresh(tab: Tab, b: &mut dyn Backend, out: &mut Vec<Msg>) {
    match b.call(Request::Status) {
        Ok(s) => out.push(Msg::Status(Ok(s))),
        Err(e) => {
            out.push(Msg::Status(Err(err(e))));
            return;
        }
    }
    if let Ok(v) = b.call(Request::ConfigGet)
        && let Some(t) = v["toml"].as_str()
    {
        out.push(Msg::Config(t.to_string()));
    }
    match tab {
        Tab::Rules => load_rules(b, out),
        Tab::Vault => load_vault(b, out),
        _ => {}
    }
}

fn load_rules(b: &mut dyn Backend, out: &mut Vec<Msg>) {
    if let Ok(v) = b.call(Request::RulesGet)
        && let Some(t) = v["toml"].as_str()
    {
        out.push(Msg::Rules(t.to_string()));
    }
}

fn load_vault(b: &mut dyn Backend, out: &mut Vec<Msg>) {
    if let Ok(v) = b.call(Request::VaultStats) {
        out.push(Msg::Vault(
            v["stats"].as_array().cloned().unwrap_or_default(),
        ));
    }
}

/// Do the work of `cmd`, appending the results to `out`.
pub fn exec(cmd: Cmd, b: &mut dyn Backend, out: &mut Vec<Msg>) {
    match cmd {
        Cmd::Visible(tab) | Cmd::Refresh(tab) => refresh(tab, b, out),
        Cmd::SetConfig(edit) => {
            let current = b
                .call(Request::ConfigGet)
                .ok()
                .and_then(|v| v["toml"].as_str().map(str::to_string))
                .and_then(|t| Config::from_toml_str(&t).ok());
            let Some(mut c) = current else {
                out.push(Msg::ConfigSaved {
                    result: Err("cannot read the configuration".into()),
                    intercept: None,
                    protection: None,
                });
                return;
            };
            let (intercept_was, protection_was) = (c.intercept.enabled, c.protection.enabled);
            edit(&mut c);
            let result = c
                .to_toml_string()
                .map_err(anyhow::Error::from)
                .and_then(|toml| b.call(Request::ConfigSet { toml }))
                .map_err(err);
            out.push(Msg::ConfigSaved {
                result,
                intercept: (c.intercept.enabled != intercept_was).then_some(c.intercept.enabled),
                protection: (c.protection.enabled != protection_was)
                    .then_some(c.protection.enabled),
            });
            refresh(Tab::Settings, b, out);
        }
        Cmd::SetRules(toml) => {
            let r = b.call(Request::RulesSet { rules_toml: toml });
            out.push(Msg::RulesSaved(r.map(|_| ()).map_err(err)));
            load_rules(b, out);
        }
        Cmd::VaultWipe(scope) => {
            let result = b
                .call(Request::VaultWipe {
                    scope: scope.clone(),
                })
                .map_err(err);
            out.push(Msg::VaultWiped { scope, result });
            load_vault(b, out);
        }
        Cmd::Redact(text) => {
            let r = b
                .call(Request::Redact { text, scope: None })
                .map(|v| {
                    let red = v["text"].as_str().unwrap_or_default().to_string();
                    let replaced = v["replaced"].as_array().cloned().unwrap_or_default();
                    (red, replaced)
                })
                .map_err(err);
            out.push(Msg::Redacted(r.map(|(red, replaced)| {
                let restored = b
                    .call(Request::Restore {
                        text: red.clone(),
                        scope: None,
                    })
                    .ok()
                    .and_then(|r| r["text"].as_str().map(str::to_string));
                Redaction {
                    text: red,
                    replaced,
                    restored,
                }
            })));
        }
        Cmd::StartDaemon => out.push(Msg::Started(b.start_daemon().map_err(err))),
    }
}

/// Starts the daemon when the user asks for it on the offline screen.
pub struct Starter {
    /// What pressing the key will do, shown on the offline screen.
    pub hint: String,
    pub start: Box<dyn FnMut() -> anyhow::Result<String> + Send>,
}

/// The real daemon: (re)connects on demand and keeps an event subscription
/// for each connection it makes.
pub struct Live {
    dir: PathBuf,
    client: Option<Client>,
    tx: Sender<UiEvent>,
    /// Bumped per subscription; an older subscriber stops forwarding.
    sub_gen: Arc<AtomicU64>,
    starter: Option<Starter>,
}

impl Live {
    pub fn new(dir: &Path, tx: Sender<UiEvent>, starter: Option<Starter>) -> Self {
        Live {
            dir: dir.to_path_buf(),
            client: None,
            tx,
            sub_gen: Arc::new(AtomicU64::new(0)),
            starter,
        }
    }

    fn connect(&mut self) -> anyhow::Result<&mut Client> {
        if self.client.is_none() {
            let c = Client::connect_with_timeout(&self.dir, Duration::from_secs(1)).map_err(
                |e| match e {
                    IpcError::NotRunning => anyhow::anyhow!("the parda daemon is not running"),
                    other => anyhow::anyhow!(other),
                },
            )?;
            self.client = Some(c);
            self.subscribe();
        }
        Ok(self.client.as_mut().expect("connected"))
    }

    fn subscribe(&self) {
        let generation = self.sub_gen.fetch_add(1, Ordering::SeqCst) + 1;
        let current = Arc::clone(&self.sub_gen);
        let tx = self.tx.clone();
        let dir = self.dir.clone();
        std::thread::spawn(move || {
            let Ok(c) = Client::connect(&dir) else { return };
            for ev in c.subscribe() {
                if current.load(Ordering::SeqCst) != generation
                    || tx.send(UiEvent::Msg(Msg::Event(ev))).is_err()
                {
                    break;
                }
            }
        });
    }
}

impl Backend for Live {
    fn call(&mut self, req: Request) -> anyhow::Result<Value> {
        let retry = matches!(
            req,
            Request::Status | Request::ConfigGet | Request::RulesGet | Request::VaultStats
        );
        match self.connect()?.call(req.clone()) {
            Ok(v) => Ok(v),
            Err(e @ IpcError::Remote { .. }) => Err(e.into()),
            Err(e) => {
                // The connection is gone (daemon restarted?): reconnect, and
                // repeat a read once.
                self.client = None;
                if !retry {
                    return Err(e.into());
                }
                Ok(self.connect()?.call(req)?)
            }
        }
    }

    fn start_daemon(&mut self) -> anyhow::Result<String> {
        match &mut self.starter {
            Some(s) => (s.start)(),
            None => {
                anyhow::bail!("start the daemon with `parda daemon` or `parda service install`")
            }
        }
    }
}

/// Spawn the worker thread; it ends when the returned sender is dropped.
pub fn spawn(mut backend: impl Backend + Send + 'static, tx: Sender<UiEvent>) -> Sender<Cmd> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();
    std::thread::spawn(move || {
        let mut tab = Tab::Dashboard;
        let mut next = Instant::now();
        loop {
            let wait = next.saturating_duration_since(Instant::now());
            let cmd = match cmd_rx.recv_timeout(wait) {
                Ok(c) => c,
                Err(RecvTimeoutError::Timeout) => Cmd::Refresh(tab),
                Err(RecvTimeoutError::Disconnected) => break,
            };
            match &cmd {
                Cmd::Visible(t) => {
                    tab = *t;
                    next = Instant::now() + REFRESH;
                }
                Cmd::Refresh(_) => next = Instant::now() + REFRESH,
                _ => {}
            }
            let mut out = Vec::new();
            exec(cmd, &mut backend, &mut out);
            for m in out {
                if tx.send(UiEvent::Msg(m)).is_err() {
                    return;
                }
            }
        }
    });
    cmd_tx
}
