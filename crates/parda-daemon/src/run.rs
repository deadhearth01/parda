//! Daemon start-up, the IPC request handler and shutdown.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use parda_clip::ClipHandle;
use parda_core::{Config, MlDetector};
use parda_detect::RulesFile;
use parda_engine::{Engine, EngineError, EngineOptions};
use parda_intercept::{EngineTransform, HostList, InterceptState, serve_with_shutdown};
use parda_ipc::{Event, Handler, Request, Response};
use parda_ml::ExecutionProvider;
use serde_json::{Value, json};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;

use crate::events::{self, Activity, emit, intercept_notice, notify};
use crate::paths::{Paths, load_config, load_rules, write_private};
use crate::{ca_store, sysproxy};

/// Which services to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunOptions {
    pub proxy: bool,
    pub clipboard: bool,
    pub ipc: bool,
    /// Register the global paste-safe hotkey (foreground runs only).
    pub hotkey: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            proxy: true,
            clipboard: true,
            ipc: true,
            hotkey: true,
        }
    }
}

const PRUNE_EVERY: Duration = Duration::from_secs(3600);
/// How long the proxy and the intercept listener get to finish requests in
/// progress when the daemon stops.
const STOP_WITHIN: Duration = Duration::from_secs(5);
/// How long a restarted intercept listener waits for its old address to be
/// released.
const REBIND_WITHIN: Duration = Duration::from_secs(2);
/// How often the daemon checks whether the root certificate on disk was
/// replaced (`parda ca create --force`) while the listener runs.
const CA_CHECK_EVERY: Duration = Duration::from_secs(2);

/// Why intercept is on but not listening, when no root certificate exists.
const NO_CA: &str = "intercept: no CA — run `parda ca create` (then `parda ca install`); \
                     AI sites are not filtered until then";

/// Lowest model threshold the Settings tab offers; the model decodes at this.
const MODEL_THRESHOLD_FLOOR: f32 = 0.3;

/// Load the configured ML model, or explain why not. A warm-up inference
/// keeps the first real request fast.
pub fn load_model(paths: &Paths, config: &Config) -> (Option<Arc<dyn MlDetector>>, Option<String>) {
    let m = config.detect.model.trim();
    if m == "none" {
        return (None, None);
    }
    let id = if m == "default" || m.is_empty() {
        parda_ml::default_model_id().to_string()
    } else {
        m.to_string()
    };
    let ep: ExecutionProvider = config
        .detect
        .execution_provider
        .parse()
        .unwrap_or(ExecutionProvider::Auto);
    // Decode at a low floor; the engine keeps only findings at or above the
    // configured `ml_threshold`, so changing it applies without a reload.
    let floor = config.detect.ml_threshold.min(MODEL_THRESHOLD_FLOOR);
    match parda_ml::load_detector(&paths.models_dir(), &id, ep, floor) {
        Ok(det) => {
            let t = Instant::now();
            match det.detect_batch(&["Warm-up: Ravi Kumar met Anna Schmidt in Pune."]) {
                Ok(_) => {
                    tracing::info!(model = %id, ms = t.elapsed().as_millis() as u64, "model loaded")
                }
                Err(e) => tracing::warn!(model = %id, error = %e, "model warm-up failed"),
            }
            (Some(det), None)
        }
        Err(e) => {
            let msg = format!("{e:#}");
            tracing::error!(model = %id, error = %msg, "model not loaded");
            (None, Some(msg))
        }
    }
}

/// The running intercept listener.
struct InterceptRun {
    addr: SocketAddr,
    /// The `intercept.listen` it was started with.
    listen: String,
    /// The root certificate (PEM) it signs with, to notice a replaced CA.
    ca_pem: String,
    /// `intercept.hosts` as last applied, to notice added sites.
    hosts: Vec<String>,
    transform: Arc<EngineTransform>,
    stop: watch::Sender<bool>,
    task: JoinHandle<anyhow::Result<()>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

struct Shared {
    paths: Paths,
    opts: RunOptions,
    engine: Engine,
    config: RwLock<Config>,
    events: broadcast::Sender<Event>,
    activity: Arc<Activity>,
    clip: Option<ClipHandle>,
    proxy_addr: RwLock<Option<SocketAddr>>,
    /// The running proxy, for settings that apply without a restart.
    proxy: RwLock<Option<Arc<parda_proxy::ProxyState>>>,
    /// The runtime the services run on (set when serving starts), so IPC
    /// handlers can start the intercept listener.
    rt: OnceLock<tokio::runtime::Handle>,
    intercept: Mutex<Option<InterceptRun>>,
    /// Why intercept is enabled but not listening.
    intercept_error: Mutex<Option<String>>,
    /// Serialises ConfigSet / Reload (write the file, then apply).
    config_lock: Mutex<()>,
    model_error: Option<String>,
    shutdown: watch::Sender<bool>,
    stopped: Arc<AtomicBool>,
    started: Instant,
}

pub struct Daemon {
    shared: Arc<Shared>,
    opts: RunOptions,
}

impl Daemon {
    /// Load configuration, the model and the vault; start the clipboard
    /// thread. Blocking (model loading takes a moment).
    pub fn open(paths: Paths, opts: RunOptions) -> anyhow::Result<Daemon> {
        paths.ensure().context("creating parda directories")?;
        // Before loading the model or touching the clipboard: a second
        // daemon must not start services, nor clean up the live one's files.
        if opts.ipc {
            match parda_ipc::Client::connect(&paths.runtime_dir) {
                Ok(_) => anyhow::bail!(
                    "another parda daemon is already running (its IPC socket is in use); \
                     stop it first with `parda stop`"
                ),
                // Only "nothing there" (no socket, stale file) lets us start. A
                // daemon of another version or one that does not answer is
                // still a daemon: leave its files alone.
                Err(e) if e.is_not_running() => {}
                Err(e) => anyhow::bail!(
                    "something is listening on parda's IPC socket but it is not a compatible \
                     parda daemon ({e}); not starting. If it is an older or hung parda daemon, \
                     stop it first (`parda stop`, or end the process)"
                ),
            }
        }
        let config = load_config(&paths)?;
        for key in config.suspicious_action_keys() {
            tracing::warn!(
                key = %key,
                "[detect.actions] key looks like a misspelt built-in kind; it is treated as a custom kind"
            );
        }
        let rules = load_rules(&paths)?;
        let (ml, model_error) = load_model(&paths, &config);
        let engine = Engine::open(
            EngineOptions {
                config: config.clone(),
                rules,
                data_dir: paths.data_dir.clone(),
                use_keyring: config.vault.use_keyring,
            },
            ml,
        )
        .context("opening the vault")?;
        let (events, _) = broadcast::channel(512);
        let activity = Arc::new(Activity::default());
        let clip = if opts.clipboard && config.clipboard.enabled {
            let tx = events.clone();
            let act = activity.clone();
            match parda_clip::spawn(
                engine.clone(),
                config.clipboard.clone(),
                Box::new(move |e| emit(&tx, &act, events::from_clip(&e))),
            ) {
                Ok(h) => Some(h),
                Err(e) => {
                    tracing::warn!(error = %e, "clipboard service not started");
                    None
                }
            }
        } else {
            None
        };
        let (shutdown, _) = watch::channel(false);
        Ok(Daemon {
            shared: Arc::new(Shared {
                paths,
                opts,
                engine,
                config: RwLock::new(config),
                events,
                activity,
                clip,
                proxy_addr: RwLock::new(None),
                proxy: RwLock::new(None),
                rt: OnceLock::new(),
                intercept: Mutex::new(None),
                intercept_error: Mutex::new(None),
                config_lock: Mutex::new(()),
                model_error,
                shutdown,
                stopped: Arc::new(AtomicBool::new(false)),
                started: Instant::now(),
            }),
            opts,
        })
    }

    pub fn engine(&self) -> &Engine {
        &self.shared.engine
    }

    pub fn clip(&self) -> Option<ClipHandle> {
        self.shared.clip.clone()
    }

    /// Set once the daemon has stopped (the hotkey loop watches it).
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.shared.stopped.clone()
    }

    pub fn hotkey(&self) -> String {
        self.shared
            .config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clipboard
            .hotkey
            .clone()
    }

    /// Run the proxy and IPC endpoint until shutdown (IPC `Shutdown`,
    /// Ctrl-C or SIGTERM).
    pub async fn serve(self) -> anyhow::Result<()> {
        let shared = self.shared.clone();
        let result = self.serve_inner().await;
        shared.stopped.store(true, Ordering::SeqCst);
        let _ = shared.shutdown.send(true);
        if let Some(c) = &shared.clip {
            c.stop();
        }
        // Only remove the address file this daemon wrote (and nobody
        // replaced since).
        if let Some(addr) = *shared.proxy_addr.read().unwrap_or_else(|e| e.into_inner()) {
            remove_addr_file(&shared.paths.proxy_addr_file(), addr);
        }
        tracing::info!("parda daemon stopped");
        result
    }

    async fn serve_inner(self) -> anyhow::Result<()> {
        let shared = self.shared.clone();
        let _ = shared.rt.set(tokio::runtime::Handle::current());
        let config = shared
            .config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut proxy_task = None;
        if self.opts.proxy && config.proxy.enabled {
            // Refuses a non-loopback address unless allow_non_loopback.
            let listener = parda_proxy::bind(&config.proxy).await?;
            let addr = listener.local_addr()?;
            *shared.proxy_addr.write().unwrap_or_else(|e| e.into_inner()) = Some(addr);
            write_private(&shared.paths.proxy_addr_file(), &addr.to_string())?;
            let (ptx, mut prx) = broadcast::channel(256);
            let state =
                parda_proxy::ProxyState::new(shared.engine.clone(), config.proxy.clone(), ptx)?;
            *shared.proxy.write().unwrap_or_else(|e| e.into_inner()) = Some(state.clone());
            let events = shared.events.clone();
            let activity = shared.activity.clone();
            tokio::spawn(async move {
                loop {
                    match prx.recv().await {
                        Ok(ev) => emit(&events, &activity, events::from_proxy(&ev)),
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
            let mut rx = shared.shutdown.subscribe();
            proxy_task = Some(tokio::spawn(parda_proxy::serve_with_shutdown(
                listener,
                state,
                async move {
                    let _ = rx.wait_for(|stop| *stop).await;
                },
            )));
            tracing::info!(%addr, "proxy listening");
        }
        {
            // Reads the CA key: off the async workers.
            let (s, c) = (shared.clone(), config.clone());
            tokio::task::spawn_blocking(move || s.sync_intercept(&c, true)).await?;
        }

        let ipc = {
            let handler: Arc<dyn Handler> = Arc::new(DaemonHandle {
                shared: shared.clone(),
            });
            let runtime_dir = shared.paths.runtime_dir.clone();
            let enabled = self.opts.ipc;
            async move {
                if enabled {
                    parda_ipc::serve(&runtime_dir, handler)
                        .await
                        .context("serving IPC (is another parda daemon running?)")
                } else {
                    std::future::pending().await
                }
            }
        };
        let prune = {
            let shared = shared.clone();
            async move {
                let mut tick = tokio::time::interval(PRUNE_EVERY);
                tick.tick().await;
                loop {
                    tick.tick().await;
                    let s = shared.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        let ttl = s
                            .config
                            .read()
                            .unwrap_or_else(|e| e.into_inner())
                            .vault
                            .ttl_days;
                        match s.engine.vault().prune(ttl) {
                            Ok(n) if n > 0 => {
                                s.engine.forget_scopes();
                                tracing::info!(removed = n, "expired vault mappings pruned");
                            }
                            Ok(_) => {}
                            Err(e) => tracing::warn!(error = %e, "vault prune failed"),
                        }
                    })
                    .await;
                }
            }
        };
        // A replaced certificate sends no config change: notice it here, or
        // the listener keeps signing with a CA the system no longer trusts.
        let ca_watch = {
            let shared = shared.clone();
            async move {
                let mut tick = tokio::time::interval(CA_CHECK_EVERY);
                tick.tick().await;
                loop {
                    tick.tick().await;
                    let s = shared.clone();
                    let _ = tokio::task::spawn_blocking(move || s.check_ca()).await;
                }
            }
        };
        let mut stop_rx = shared.shutdown.subscribe();
        let _ = shared
            .events
            .send(Event::now("daemon", "parda daemon started"));
        tracing::info!(
            ipc = %shared.paths.runtime_dir.display(),
            model = shared.engine.model_name().as_deref().unwrap_or("none"),
            "parda daemon running"
        );

        let result = tokio::select! {
            r = ipc => r,
            _ = stop_rx.wait_for(|stop| *stop) => Ok(()),
            _ = terminate_signal() => Ok(()),
            _ = prune => Ok(()),
            _ = ca_watch => Ok(()),
        };
        let _ = shared.shutdown.send(true);
        // Both get the same 5 s to finish requests in progress.
        let deadline = tokio::time::Instant::now() + STOP_WITHIN;
        let intercept_task = lock(&shared.intercept)
            .take()
            .map(|run| shared.stop_intercept(run));
        for (name, task) in [("proxy", proxy_task), ("intercept", intercept_task)] {
            let Some(t) = task else { continue };
            match tokio::time::timeout_at(deadline, t).await {
                Ok(Ok(Err(e))) => tracing::warn!(error = %e, "{name} stopped with an error"),
                Err(_) => tracing::warn!("{name} did not stop within 5 s"),
                _ => {}
            }
        }
        result
    }
}

/// Remove an address file, but only if it still holds `addr` (another
/// daemon or listener may have replaced it).
fn remove_addr_file(file: &Path, addr: SocketAddr) {
    if std::fs::read_to_string(file).is_ok_and(|s| s.trim() == addr.to_string()) {
        let _ = std::fs::remove_file(file);
    }
}

/// Bind `listen` for the intercept listener: loopback only, never another
/// machine's traffic. `retry` waits briefly for an address a listener that
/// was just stopped is still releasing.
fn bind_loopback(listen: &str, retry: bool) -> Result<std::net::TcpListener, String> {
    let addrs: Vec<SocketAddr> = listen
        .to_socket_addrs()
        .map_err(|e| format!("intercept.listen = {listen:?} is not a host:port address ({e})"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("intercept.listen = {listen:?} names no address"));
    }
    if let Some(bad) = addrs.iter().find(|a| !a.ip().is_loopback()) {
        return Err(format!(
            "parda intercept must listen on a loopback address, not {bad} \
             (intercept.listen, e.g. 127.0.0.1:8788)"
        ));
    }
    let deadline = Instant::now() + if retry { REBIND_WITHIN } else { Duration::ZERO };
    loop {
        match std::net::TcpListener::bind(&addrs[..]) {
            Ok(l) => {
                l.set_nonblocking(true)
                    .map_err(|e| format!("cannot listen on {listen}: {e}"))?;
                return Ok(l);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(format!("intercept: cannot listen on {listen}: {e}")),
        }
    }
}

impl Shared {
    /// A daemon notice: on the feed and in the recent history, never in the
    /// activity totals.
    fn notice(&self, e: Event) {
        notify(&self.events, &self.activity, e);
    }

    /// Make the intercept listener match `config`: start it, restart it (a
    /// new listen address or a replaced CA), change it in place (hosts,
    /// scope, unscanned, skip_keys) or stop it. Never fails: why it is not
    /// listening is kept for the status and sent as a warning event. The CA
    /// is never created here. Blocking (reads the CA key).
    fn sync_intercept(&self, config: &Config, initial: bool) {
        let want = self.opts.proxy && config.intercept.enabled;
        let mut slot = lock(&self.intercept);
        let mut stopped = false;
        if let Some(run) = slot.as_mut() {
            let same_ca = std::fs::read_to_string(ca_store::ca_cert_path(&self.paths))
                .is_ok_and(|pem| pem == run.ca_pem);
            if want && run.listen == config.intercept.listen && same_ca && !run.task.is_finished() {
                run.transform.set_config(&config.intercept);
                let added: Vec<&str> = config
                    .intercept
                    .hosts
                    .iter()
                    .filter(|h| !run.hosts.contains(h))
                    .map(String::as_str)
                    .collect();
                self.warn_if_pac_cached(&added);
                run.hosts = config.intercept.hosts.clone();
                return;
            }
            if let Some(run) = slot.take() {
                // Its requests in progress finish in the background.
                drop(self.stop_intercept(run));
                stopped = true;
            }
        }
        if !want {
            *lock(&self.intercept_error) = None;
            if stopped || initial {
                self.warn_if_pac_set();
            }
            return;
        }
        match self.start_intercept(config, stopped) {
            Ok(run) => {
                *lock(&self.intercept_error) = None;
                self.warn_if_pac_elsewhere(run.addr);
                *slot = Some(run);
            }
            Err(why) => {
                tracing::warn!(error = %why, "intercept is not listening");
                let mut last = lock(&self.intercept_error);
                // Say it once, not on every reload.
                if last.as_deref() != Some(why.as_str()) {
                    self.notice(intercept_notice(why.clone(), true));
                    *last = Some(why);
                    drop(last);
                    self.warn_if_pac_set();
                }
            }
        }
    }

    /// Whether the running listener signs with a root certificate other
    /// than the one on disk (replaced or removed since it started).
    fn ca_replaced(&self) -> bool {
        lock(&self.intercept).as_ref().is_some_and(|run| {
            std::fs::read_to_string(ca_store::ca_cert_path(&self.paths))
                .map_or(true, |pem| pem != run.ca_pem)
        })
    }

    /// Restart the listener with the certificate on disk when it was
    /// replaced (on a timer and before every status answer). Blocking.
    fn check_ca(&self) {
        if !self.ca_replaced() {
            return;
        }
        let _serial = lock(&self.config_lock);
        let config = self
            .config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        tracing::info!("the root certificate changed; restarting the intercept listener");
        self.sync_intercept(&config, false);
    }

    /// The system proxy still points AI sites at parda while nothing
    /// listens: say so (they fail to load rather than go out unfiltered).
    fn warn_if_pac_set(&self) {
        if let Ok(Some(state)) = sysproxy::load_state(&self.paths) {
            self.notice(intercept_notice(
                format!(
                    "intercept: the system proxy still sends AI sites to parda ({}) but \
                     nothing is listening — they will fail to load until intercept is on \
                     again; `parda intercept off` restores your previous settings",
                    state.pac_url
                ),
                true,
            ));
        }
    }

    /// Sites added to `intercept.hosts` while the system proxy points at
    /// parda: the PAC URL stays the same, so browsers and the OS that cached
    /// it keep sending them direct (unfiltered) until they fetch it again.
    fn warn_if_pac_cached(&self, added: &[&str]) {
        if added.is_empty() || !matches!(sysproxy::load_state(&self.paths), Ok(Some(_))) {
            return;
        }
        self.notice(intercept_notice(
            format!(
                "intercept: {} added — filtered once your browsers fetch the PAC file again \
                 (restart them, or `parda intercept off` then `parda intercept on`); until then \
                 they may still go there direct, unfiltered",
                added.join(", ")
            ),
            true,
        ));
    }

    /// The system proxy sends AI sites to a parda PAC on another address
    /// than this listener (`intercept.listen` changed after `parda intercept
    /// on`): nothing serves it, so they fail to load. Say so.
    fn warn_if_pac_elsewhere(&self, addr: SocketAddr) {
        if let Ok(Some(state)) = sysproxy::load_state(&self.paths)
            && !sysproxy::pac_points_at(&state.pac_url, addr)
        {
            self.notice(intercept_notice(
                format!(
                    "intercept: the system proxy still points at {} but parda now listens on \
                     {addr} — AI sites fail to load; run `parda intercept on` again",
                    state.pac_url
                ),
                true,
            ));
        }
    }

    fn start_intercept(&self, config: &Config, rebind: bool) -> Result<InterceptRun, String> {
        if !ca_store::ca_exists(&self.paths) {
            return Err(NO_CA.into());
        }
        let ca_pem = std::fs::read_to_string(ca_store::ca_cert_path(&self.paths))
            .map_err(|e| format!("intercept: cannot read the CA certificate: {e}"))?;
        let ca = ca_store::load_ca(&self.paths, config.vault.use_keyring)
            .map_err(|e| format!("intercept: cannot load the CA: {e:#}"))?;
        let rt = self
            .rt
            .get()
            .ok_or("intercept: the daemon is not serving yet")?
            .clone();
        let listen = config.intercept.listen.clone();
        let listener = bind_loopback(&listen, rebind)?;
        let _rt = rt.enter();
        let listener = tokio::net::TcpListener::from_std(listener)
            .map_err(|e| format!("intercept: cannot listen on {listen}: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("intercept: cannot listen on {listen}: {e}"))?;

        let (tx, mut rx) = broadcast::channel(256);
        let transform = Arc::new(EngineTransform::new(self.engine.clone(), &config.intercept));
        let hosts = HostList::new(&config.intercept.hosts);
        let sites = hosts.entries().len();
        let state = InterceptState::new(Arc::new(ca), hosts, transform.clone(), tx)
            .map_err(|e| format!("intercept: {e:#}"))?;
        write_private(&self.paths.intercept_addr_file(), &addr.to_string())
            .map_err(|e| format!("intercept: cannot write intercept.addr: {e}"))?;

        // Ends when the listener and its last connection are gone.
        let (events, activity, engine) = (
            self.events.clone(),
            self.activity.clone(),
            self.engine.clone(),
        );
        rt.spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        let paused = !engine.config().protection.enabled;
                        emit(&events, &activity, events::from_intercept(&ev, paused));
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        let (stop, mut stop_rx) = watch::channel(false);
        let mut down = self.shutdown.subscribe();
        let task = rt.spawn(serve_with_shutdown(listener, Arc::new(state), async move {
            tokio::select! {
                _ = stop_rx.wait_for(|s| *s) => {}
                _ = down.wait_for(|s| *s) => {}
            }
        }));
        tracing::info!(%addr, sites, "intercept listening");
        self.notice(intercept_notice(
            format!("intercept: listening on {addr} for {sites} AI site(s)"),
            false,
        ));
        Ok(InterceptRun {
            addr,
            listen,
            ca_pem,
            hosts: config.intercept.hosts.clone(),
            transform,
            stop,
            task,
        })
    }

    /// Stop accepting and remove `intercept.addr`; returns the task, which
    /// ends once requests in progress have finished.
    fn stop_intercept(&self, run: InterceptRun) -> JoinHandle<anyhow::Result<()>> {
        run.stop.send_replace(true);
        remove_addr_file(&self.paths.intercept_addr_file(), run.addr);
        tracing::info!(addr = %run.addr, "intercept stopped");
        self.notice(intercept_notice(
            format!("intercept: stopped listening on {}", run.addr),
            false,
        ));
        run.task
    }

    /// `"intercept"` in the status: listener address, CA present, why it is
    /// not listening, the PAC `parda intercept on` set and whether this
    /// listener serves it.
    fn intercept_status(&self, config: &Config) -> Value {
        let listening = lock(&self.intercept)
            .as_ref()
            .filter(|r| !r.task.is_finished())
            .map(|r| r.addr);
        let pac = sysproxy::load_state(&self.paths)
            .ok()
            .flatten()
            .map(|s| s.pac_url);
        // Whether the system PAC is served by this listener (null when
        // either is missing).
        let pac_matches = match (&pac, listening) {
            (Some(url), Some(addr)) => Some(sysproxy::pac_points_at(url, addr)),
            _ => None,
        };
        json!({
            "enabled": config.intercept.enabled,
            "listening": listening.map(|a| a.to_string()),
            "ca": ca_store::ca_exists(&self.paths),
            "error": *lock(&self.intercept_error),
            "pac": pac,
            "pac_matches": pac_matches,
        })
    }
}

async fn terminate_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Run the daemon inside an existing Tokio runtime (no global hotkey).
pub async fn run(paths: Paths, opts: RunOptions) -> anyhow::Result<()> {
    let daemon = tokio::task::spawn_blocking(move || Daemon::open(paths, opts)).await??;
    daemon.serve().await
}

/// Run the daemon in the foreground: services on a Tokio runtime, the
/// global hotkey on this (main) thread, as macOS requires.
pub fn run_foreground(paths: Paths, opts: RunOptions) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("parda-rt")
        .build()?;
    let daemon = Daemon::open(paths, opts)?;
    let hotkey = (opts.hotkey)
        .then(|| daemon.clip().map(|c| (c, daemon.hotkey())))
        .flatten();
    let stop = daemon.stop_flag();
    let worker = std::thread::Builder::new()
        .name("parda-daemon".into())
        .spawn(move || rt.block_on(daemon.serve()))?;
    if let Some((clip, hk)) = hotkey
        && let Err(e) = parda_clip::run_hotkey_loop(clip, &hk, stop)
    {
        tracing::warn!(error = %e, "paste-safe hotkey unavailable; use `parda paste-safe`");
    }
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("the daemon thread panicked"))?
}

struct DaemonHandle {
    shared: Arc<Shared>,
}

fn engine_err(e: EngineError) -> Response {
    match e {
        EngineError::MlUnavailable(why) => Response::err("ml_unavailable", why),
        EngineError::Blocked(kinds) => Response::err(
            "blocked",
            format!(
                "blocked by policy: {}",
                kinds
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
        other => Response::err("engine", other.to_string()),
    }
}

impl DaemonHandle {
    fn config(&self) -> Config {
        self.shared
            .config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn default_scope(&self) -> String {
        self.config().clipboard.scope
    }

    fn status(&self) -> Response {
        let s = &self.shared;
        // Never report a listener as healthy while it signs with a
        // certificate that was replaced.
        s.check_ca();
        let config = self.config();
        let proxy = *s.proxy_addr.read().unwrap_or_else(|e| e.into_inner());
        Response::ok(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
            "uptime_s": s.started.elapsed().as_secs(),
            "proxy": proxy.map(|a| a.to_string()),
            "intercept": s.intercept_status(&config),
            "clipboard": s.clip.is_some(),
            "hotkey": config.clipboard.hotkey,
            "model": s.engine.model_name(),
            "model_configured": config.detect.model,
            "model_error": s.model_error,
            "protection": config.protection.enabled,
            "mode": config.detect.mode,
            "style": config.replace.style,
            "stats": s.engine.stats(),
            "activity": s.activity.snapshot(),
            "paths": {
                "config": s.paths.config_file(),
                "rules": s.paths.rules_file(),
                "data": s.paths.data_dir,
                "runtime": s.paths.runtime_dir,
                "logs": s.paths.log_dir,
            },
        }))
    }

    /// Apply a configuration to the running daemon. Returns true if part
    /// of it (proxy listen address, service on/off, model, hotkey) only
    /// takes effect after a restart; everything else applies now (the
    /// intercept listener starts, stops or moves at once).
    fn apply_config(&self, config: Config) -> bool {
        let old = self.config();
        let restart = old.proxy.listen != config.proxy.listen
            || old.proxy.enabled != config.proxy.enabled
            || old.detect.model != config.detect.model
            || old.detect.execution_provider != config.detect.execution_provider
            || old.clipboard.enabled != config.clipboard.enabled
            || old.clipboard.hotkey != config.clipboard.hotkey;
        self.shared.engine.set_config(config.clone());
        if let Some(proxy) = &*self.shared.proxy.read().unwrap_or_else(|e| e.into_inner()) {
            proxy.set_config(config.proxy.clone());
        }
        if let Some(clip) = &self.shared.clip {
            clip.set_config(config.clipboard.clone());
        }
        self.shared.sync_intercept(&config, false);
        *self
            .shared
            .config
            .write()
            .unwrap_or_else(|e| e.into_inner()) = config;
        restart
    }

    /// The answer to ConfigSet / Reload: whether a restart is needed, and
    /// the intercept listener's state after the change.
    fn applied(&self, restart: bool) -> Response {
        Response::ok(json!({
            "restart_required": restart,
            "intercept": self.shared.intercept_status(&self.config()),
        }))
    }

    fn handle_inner(&self, req: Request) -> anyhow::Result<Response> {
        let s = &self.shared;
        Ok(match req {
            Request::Status => self.status(),
            Request::Redact { text, scope } => {
                let scope = scope.unwrap_or_else(|| self.default_scope());
                match s.engine.redact(&text, &scope) {
                    Ok(r) => {
                        let counts = r.counts();
                        if !counts.is_empty() {
                            let mut e = Event::now(
                                "cli",
                                format!("redacted {} value(s)", counts.values().sum::<u32>()),
                            );
                            e.counts = counts;
                            emit(&s.events, &s.activity, e);
                        }
                        Response::ok(json!({
                            "text": r.text,
                            "replaced": r.replaced,
                            "warned": r.warned,
                            "ml_ms": r.ml_ms,
                            "ml_skipped": r.ml_skipped,
                            "paused": r.paused,
                        }))
                    }
                    Err(e) => engine_err(e),
                }
            }
            Request::Restore { text, scope } => {
                let scope = scope.unwrap_or_else(|| self.default_scope());
                Response::ok(json!({"text": s.engine.restore(&text, &scope)}))
            }
            Request::Scan { text } => match s.engine.scan(&text) {
                Ok(dets) => Response::ok(json!({"detections": dets})),
                Err(e) => engine_err(e),
            },
            Request::PasteSafe => match &s.clip {
                Some(c) => match c.paste_safe() {
                    Ok(outcome) => Response::ok(json!({"outcome": outcome})),
                    Err(e) => Response::err("paste_failed", e.to_string()),
                },
                None => Response::err(
                    "clipboard_unavailable",
                    "the clipboard service is not running (clipboard.enabled = false, or no display)",
                ),
            },
            Request::RulesGet => Response::ok(json!({"toml": s.engine.rules().to_toml_string()?})),
            Request::RulesSet { rules_toml } => match RulesFile::from_toml_str(&rules_toml) {
                Ok(rules) => {
                    write_private(&s.paths.rules_file(), &rules.to_toml_string()?)?;
                    s.engine.reload_rules(rules);
                    Response::ok(json!({}))
                }
                Err(e) => Response::err("invalid_rules", e.to_string()),
            },
            Request::VaultStats => {
                let stats: Vec<_> = s
                    .engine
                    .vault()
                    .stats()?
                    .into_iter()
                    .map(|(scope, kind, count)| json!({"scope": scope, "kind": kind, "count": count}))
                    .collect();
                Response::ok(json!({"stats": stats}))
            }
            Request::VaultWipe { scope } => {
                let removed = s.engine.vault().wipe(scope.as_deref())?;
                s.engine.forget_scopes();
                Response::ok(json!({"removed": removed}))
            }
            Request::ConfigGet => Response::ok(json!({"toml": self.config().to_toml_string()?})),
            Request::ConfigSet { toml } => match Config::from_toml_str(&toml) {
                Ok(config) => {
                    let _serial = s.config_lock.lock().unwrap_or_else(|e| e.into_inner());
                    write_private(&s.paths.config_file(), &config.to_toml_string()?)?;
                    let restart = self.apply_config(config);
                    self.applied(restart)
                }
                Err(e) => Response::err("invalid_config", e.to_string()),
            },
            Request::Reload => {
                let _serial = s.config_lock.lock().unwrap_or_else(|e| e.into_inner());
                let config = load_config(&s.paths)?;
                let rules = load_rules(&s.paths)?;
                s.engine.reload_rules(rules);
                let restart = self.apply_config(config);
                self.applied(restart)
            }
            Request::Shutdown => {
                // Answer first: stopping drops the IPC connections.
                let shared = self.shared.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(150));
                    let _ = shared.shutdown.send(true);
                });
                Response::ok(json!({}))
            }
            Request::Hello { .. } | Request::Subscribe => {
                Response::err("invalid_request", "handled by the transport")
            }
        })
    }
}

impl Handler for DaemonHandle {
    fn handle(&self, req: Request) -> Response {
        self.handle_inner(req)
            .unwrap_or_else(|e| Response::err("internal", format!("{e:#}")))
    }

    fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.shared.events.subscribe()
    }
}
