//! Daemon start-up, the IPC request handler and shutdown.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use parda_clip::ClipHandle;
use parda_core::{Config, MlDetector};
use parda_detect::RulesFile;
use parda_engine::{Engine, EngineError, EngineOptions};
use parda_ipc::{Event, Handler, Request, Response};
use parda_ml::ExecutionProvider;
use serde_json::json;
use tokio::sync::{broadcast, watch};

use crate::events::{self, Activity, emit};
use crate::paths::{Paths, load_config, load_rules, write_private};

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

struct Shared {
    paths: Paths,
    engine: Engine,
    config: RwLock<Config>,
    events: broadcast::Sender<Event>,
    activity: Arc<Activity>,
    clip: Option<ClipHandle>,
    proxy_addr: RwLock<Option<SocketAddr>>,
    /// The running proxy, for settings that apply without a restart.
    proxy: RwLock<Option<Arc<parda_proxy::ProxyState>>>,
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
        if opts.ipc && parda_ipc::Client::connect(&paths.runtime_dir).is_ok() {
            anyhow::bail!(
                "another parda daemon is already running (its IPC socket is in use); \
                 stop it first with `parda stop`"
            );
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
                engine,
                config: RwLock::new(config),
                events,
                activity,
                clip,
                proxy_addr: RwLock::new(None),
                proxy: RwLock::new(None),
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
        let ours = *shared.proxy_addr.read().unwrap_or_else(|e| e.into_inner());
        let file = shared.paths.proxy_addr_file();
        if let Some(addr) = ours
            && std::fs::read_to_string(&file).is_ok_and(|s| s.trim() == addr.to_string())
        {
            let _ = std::fs::remove_file(file);
        }
        tracing::info!("parda daemon stopped");
        result
    }

    async fn serve_inner(self) -> anyhow::Result<()> {
        let shared = self.shared.clone();
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
        };
        let _ = shared.shutdown.send(true);
        if let Some(t) = proxy_task {
            match tokio::time::timeout(Duration::from_secs(5), t).await {
                Ok(Ok(Err(e))) => tracing::warn!(error = %e, "proxy stopped with an error"),
                Err(_) => tracing::warn!("proxy did not stop within 5 s"),
                _ => {}
            }
        }
        result
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
        let config = self.config();
        let proxy = *s.proxy_addr.read().unwrap_or_else(|e| e.into_inner());
        Response::ok(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
            "uptime_s": s.started.elapsed().as_secs(),
            "proxy": proxy.map(|a| a.to_string()),
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
    /// of it (listen address, service on/off, model, hotkey) only takes
    /// effect after a restart; everything else applies now.
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
        *self
            .shared
            .config
            .write()
            .unwrap_or_else(|e| e.into_inner()) = config;
        restart
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
                    Response::ok(json!({"restart_required": restart}))
                }
                Err(e) => Response::err("invalid_config", e.to_string()),
            },
            Request::Reload => {
                let _serial = s.config_lock.lock().unwrap_or_else(|e| e.into_inner());
                let config = load_config(&s.paths)?;
                let rules = load_rules(&s.paths)?;
                s.engine.reload_rules(rules);
                let restart = self.apply_config(config);
                Response::ok(json!({"restart_required": restart}))
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
