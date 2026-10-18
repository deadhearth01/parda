//! The background worker: it owns the IPC client(s), so the UI thread never
//! blocks on the daemon. The UI sends [`Cmd`]s and gets [`Msg`]s back.
//!
//! [`exec`] does the work of one command against any [`Backend`]; the
//! worker thread runs it for the live daemon, and tests (and `--dump`) run
//! it synchronously against a fake. Every second the worker refreshes the
//! status and the configuration, and the data of the visible tab (rules,
//! vault) — never the others.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
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
    Status(Result<Value, Down>),
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
    /// What the offline screen's start key would do.
    StartHint(String),
    Event(Event),
}

fn err(e: anyhow::Error) -> String {
    format!("{e:#}")
}

/// Why the daemon cannot be used. Only [`Down::NotRunning`] offers a start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Down {
    /// Nothing listens: the start key applies.
    NotRunning,
    /// It accepted the connection but did not answer in time.
    Unresponsive(String),
    /// It answers in a protocol this parda does not speak.
    Incompatible(String),
    /// Anything else (permissions, a broken socket file …).
    Failed(String),
}

impl Down {
    pub fn text(&self) -> String {
        match self {
            Down::NotRunning => "the parda daemon is not running".into(),
            Down::Unresponsive(e) | Down::Incompatible(e) | Down::Failed(e) => e.clone(),
        }
    }
}

/// Sort a failed request into a [`Down`].
pub fn classify(e: &anyhow::Error) -> Down {
    if parda_ipc::is_not_running(e) {
        return Down::NotRunning;
    }
    let text = format!("{e:#}");
    match e.chain().find_map(|c| c.downcast_ref::<IpcError>()) {
        Some(IpcError::Timeout) => Down::Unresponsive(text),
        Some(IpcError::Remote { code, .. }) if code == "version_mismatch" => {
            Down::Incompatible(text)
        }
        Some(IpcError::Protocol(_) | IpcError::Json(_)) => Down::Incompatible(text),
        _ => Down::Failed(text),
    }
}

fn refresh(tab: Tab, b: &mut dyn Backend, out: &mut Vec<Msg>) {
    match b.call(Request::Status) {
        Ok(s) => out.push(Msg::Status(Ok(s))),
        Err(e) => {
            let down = classify(&e);
            let offer = down == Down::NotRunning;
            out.push(Msg::Status(Err(down)));
            // Only a daemon that is not running gets a start plan.
            if offer && let Some(h) = b.start_hint() {
                out.push(Msg::StartHint(h));
            }
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
    /// What pressing the key would do, for the offline screen. Called on
    /// the worker (it may read service files), only once the daemon is
    /// found offline.
    pub describe: Box<dyn FnMut() -> String + Send>,
    pub start: Box<dyn FnMut() -> anyhow::Result<String> + Send>,
}

/// A starter shared by the worker and its replacement after a restart.
pub type SharedStarter = Arc<Mutex<Starter>>;

/// The real daemon: (re)connects on demand and keeps an event subscription
/// for each connection it makes.
pub struct Live {
    dir: PathBuf,
    client: Option<Client>,
    tx: Sender<UiEvent>,
    /// Subscribe to events on each new connection (the main worker only).
    events: bool,
    /// Bumped per subscription; an older subscriber stops forwarding.
    sub_gen: Arc<AtomicU64>,
    starter: Option<SharedStarter>,
    /// The starter's description, worked out once per offline spell.
    hint: Option<String>,
}

impl Live {
    pub fn new(dir: &Path, tx: Sender<UiEvent>, starter: Option<Starter>) -> Self {
        Self::shared(dir, tx, starter.map(|s| Arc::new(Mutex::new(s))), true)
    }

    pub fn shared(
        dir: &Path,
        tx: Sender<UiEvent>,
        starter: Option<SharedStarter>,
        events: bool,
    ) -> Self {
        Live {
            dir: dir.to_path_buf(),
            client: None,
            tx,
            events,
            sub_gen: Arc::new(AtomicU64::new(0)),
            starter,
            hint: None,
        }
    }

    fn connect(&mut self) -> anyhow::Result<&mut Client> {
        if self.client.is_none() {
            let c = Client::connect_with_timeout(&self.dir, Duration::from_secs(1))?;
            self.client = Some(c);
            self.hint = None;
            if self.events {
                self.subscribe();
            }
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

    fn start_hint(&mut self) -> Option<String> {
        if self.hint.is_none() {
            self.hint = self
                .starter
                .as_ref()
                .and_then(|s| s.lock().ok().map(|mut s| (s.describe)()));
        }
        self.hint.clone()
    }

    fn start_daemon(&mut self) -> anyhow::Result<String> {
        match &self.starter {
            Some(s) => (s
                .lock()
                .map_err(|_| anyhow::anyhow!("the start helper failed earlier"))?
                .start)(),
            None => {
                anyhow::bail!("start the daemon with `parda daemon` or `parda service install`")
            }
        }
    }
}

/// Which worker runs a command: Inspector redactions get their own, so a
/// slow status refresh never holds them up (and the other way round).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Main,
    Inspector,
}

impl Cmd {
    pub fn role(&self) -> Role {
        match self {
            Cmd::Redact(_) => Role::Inspector,
            _ => Role::Main,
        }
    }
}

/// Tells the UI when a worker thread dies of a panic.
struct DeathNotice(Sender<UiEvent>, Role);

impl Drop for DeathNotice {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let _ = self.0.send(UiEvent::WorkerDied(self.1));
        }
    }
}

/// Spawn the main worker thread; it ends when the returned sender is dropped.
pub fn spawn(backend: impl Backend + Send + 'static, tx: Sender<UiEvent>) -> Sender<Cmd> {
    spawn_role(Role::Main, backend, tx)
}

/// Spawn a worker. The main one also refreshes on its own timer.
pub fn spawn_role(
    role: Role,
    mut backend: impl Backend + Send + 'static,
    tx: Sender<UiEvent>,
) -> Sender<Cmd> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();
    std::thread::spawn(move || {
        let _notice = DeathNotice(tx.clone(), role);
        let mut tab = Tab::Dashboard;
        let mut next = Instant::now();
        loop {
            let cmd = if role == Role::Main {
                let wait = next.saturating_duration_since(Instant::now());
                match cmd_rx.recv_timeout(wait) {
                    Ok(c) => c,
                    Err(RecvTimeoutError::Timeout) => Cmd::Refresh(tab),
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            } else {
                match cmd_rx.recv() {
                    Ok(c) => c,
                    Err(_) => break,
                }
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

/// Makes the backend for a (re)started worker.
pub type MakeBackend = Box<dyn FnMut(Role) -> Box<dyn Backend + Send>>;

/// The two workers, restarted when one dies.
pub struct Workers {
    make: MakeBackend,
    tx: Sender<UiEvent>,
    main: Sender<Cmd>,
    inspector: Sender<Cmd>,
}

impl Workers {
    pub fn new(mut make: MakeBackend, tx: Sender<UiEvent>) -> Self {
        let main = spawn_role(Role::Main, make(Role::Main), tx.clone());
        let inspector = spawn_role(Role::Inspector, make(Role::Inspector), tx.clone());
        Workers {
            make,
            tx,
            main,
            inspector,
        }
    }

    /// Replace a worker (after [`UiEvent::WorkerDied`]).
    pub fn restart(&mut self, role: Role) {
        let w = spawn_role(role, (self.make)(role), self.tx.clone());
        match role {
            Role::Main => self.main = w,
            Role::Inspector => self.inspector = w,
        }
    }

    /// Send to the right worker. Returns false if it was dead (it is then
    /// restarted and the command resent).
    pub fn send(&mut self, cmd: Cmd) -> bool {
        let role = cmd.role();
        let to = match role {
            Role::Main => &self.main,
            Role::Inspector => &self.inspector,
        };
        match to.send(cmd) {
            Ok(()) => true,
            Err(mpsc::SendError(cmd)) => {
                self.restart(role);
                let to = match role {
                    Role::Main => &self.main,
                    Role::Inspector => &self.inspector,
                };
                let _ = to.send(cmd);
                false
            }
        }
    }
}
