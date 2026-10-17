//! `parda intercept on | off | status` — point the system's automatic proxy
//! setting (PAC) at parda so AI sites are filtered, and put it back.
//!
//! Every function here takes a [`Ctx`]: the OS commands go through a
//! [`Runner`] and the daemon through a [`DaemonLink`], so the logic is tested
//! with fakes and never touches the real system in tests.

use std::io::Write;
use std::net::SocketAddr;

use anyhow::{Context, anyhow, bail};
use parda_core::Config;
use parda_daemon::ca_store::{ca_cert_path, ca_exists};
use parda_daemon::sysproxy::{self, Platform, Runner, Saved, SystemRunner};
use parda_daemon::{Paths, cert_trust, load_config, write_private};
use parda_ipc::Request;
use serde_json::Value;

/// The daemon, as far as these commands need it.
pub trait DaemonLink {
    fn call(&mut self, req: Request) -> anyhow::Result<Value>;
}

impl DaemonLink for parda_ipc::Client {
    fn call(&mut self, req: Request) -> anyhow::Result<Value> {
        Ok(parda_ipc::Client::call(self, req)?)
    }
}

pub struct Ctx<'a> {
    pub paths: &'a Paths,
    pub runner: &'a mut dyn Runner,
    pub platform: Platform,
    /// `None` when the daemon is not running.
    pub daemon: Option<&'a mut dyn DaemonLink>,
    pub out: &'a mut dyn Write,
}

/// Run `f` against the real system, the running daemon (if any) and stdout.
pub fn with_system(f: impl FnOnce(&mut Ctx) -> anyhow::Result<()>) -> anyhow::Result<()> {
    let paths = super::paths()?;
    let mut client = super::daemon_client(&paths)?;
    let mut runner = SystemRunner;
    let mut stdout = std::io::stdout();
    let mut cx = Ctx {
        paths: &paths,
        runner: &mut runner,
        platform: Platform::current(),
        daemon: client.as_mut().map(|c| c as &mut dyn DaemonLink),
        out: &mut stdout,
    };
    f(&mut cx)
}

/// The PAC address for `intercept.listen`: a loopback IP (or `localhost`)
/// with a fixed port, so the system setting stays valid across restarts.
pub fn pac_url(listen: &str) -> anyhow::Result<String> {
    let bad = || {
        anyhow!(
            "intercept.listen = {listen:?} must be a loopback address with a fixed port, \
             such as 127.0.0.1:8788"
        )
    };
    let authority = match listen.parse::<SocketAddr>() {
        Ok(a) if a.ip().is_loopback() && a.port() != 0 => a.to_string(),
        Ok(_) => return Err(bad()),
        Err(_) => {
            let (host, port) = listen.rsplit_once(':').ok_or_else(bad)?;
            let port: u16 = port.parse().map_err(|_| bad())?;
            if !host.eq_ignore_ascii_case("localhost") || port == 0 {
                return Err(bad());
            }
            format!("localhost:{port}")
        }
    };
    Ok(format!("http://{authority}/parda.pac"))
}

/// The config the daemon runs with (it writes `config.toml` too), or the
/// file when no daemon runs.
fn read_config(cx: &mut Ctx) -> anyhow::Result<Config> {
    match cx.daemon.as_deref_mut() {
        Some(d) => {
            let v = d.call(Request::ConfigGet)?;
            Config::from_toml_str(v["toml"].as_str().unwrap_or_default())
                .context("the daemon's configuration")
        }
        None => load_config(cx.paths),
    }
}

/// Save the config. A running daemon writes it and applies it at once; its
/// answer (with `"intercept"`, the listener's state) is returned.
fn write_config(cx: &mut Ctx, config: &Config) -> anyhow::Result<Option<Value>> {
    match cx.daemon.as_deref_mut() {
        Some(d) => Ok(Some(d.call(Request::ConfigSet {
            toml: config.to_toml_string()?,
        })?)),
        None => {
            cx.paths.ensure()?;
            write_private(&cx.paths.config_file(), &config.to_toml_string()?)?;
            Ok(None)
        }
    }
}

fn target_label(platform: Platform, target: &str) -> String {
    match platform {
        Platform::MacOs => target.to_string(),
        Platform::Windows => r"Internet Settings (HKCU\…\AutoConfigURL)".into(),
        Platform::Linux => "GNOME proxy settings".into(),
    }
}

/// Targets in words, comma-separated.
fn labels(platform: Platform, targets: &[String]) -> String {
    targets
        .iter()
        .map(|t| target_label(platform, t))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A saved (previous) setting in words.
fn describe_saved(platform: Platform, s: &Saved) -> String {
    match platform {
        Platform::Linux => match &s.url {
            Some(u) => format!("mode {}, PAC {u}", s.target),
            None => format!("mode {}", s.target),
        },
        _ => describe(s.url.as_deref(), s.enabled),
    }
}

fn describe(url: Option<&str>, active: bool) -> String {
    match (url, active) {
        (Some(u), true) => format!("PAC {u}"),
        (Some(u), false) => format!("no automatic proxy (PAC {u} switched off)"),
        (None, _) => "no automatic proxy".into(),
    }
}

const START_DAEMON: &str = "`parda daemon` (or `parda service install` to start it at login)";

/// `parda intercept on`: check the certificate, start the listener, then
/// point the system's automatic proxy setting at it.
pub fn on(cx: &mut Ctx) -> anyhow::Result<()> {
    if !ca_exists(cx.paths) {
        bail!(
            "parda has no root certificate yet — run `parda ca create` first, then \
             `parda ca install`"
        );
    }
    let pem = ca_cert_path(cx.paths);
    if cx.platform == Platform::Linux {
        writeln!(
            cx.out,
            "! Linux: parda cannot check whether {} is trusted; `parda ca install` shows how \
             to add it to the system store and your browsers",
            pem.display()
        )?;
    } else if !cert_trust::is_trusted(cx.runner, cx.platform, &pem) {
        bail!(
            "the root certificate is not trusted yet — run `parda ca install` (you will see a \
             system dialog to approve), then `parda intercept on` again"
        );
    } else {
        writeln!(cx.out, "✓ certificate  trusted")?;
    }

    let mut config = read_config(cx)?;
    let pac = pac_url(&config.intercept.listen)?;
    let was_enabled = config.intercept.enabled;
    config.intercept.enabled = true;
    let answer = write_config(cx, &config)?;
    // Put `enabled` back as it was when the system cannot be pointed at parda.
    let undo = |cx: &mut Ctx, mut config: Config, e: anyhow::Error| -> anyhow::Error {
        if was_enabled {
            return e;
        }
        config.intercept.enabled = false;
        match write_config(cx, &config) {
            Ok(_) => e,
            Err(w) => e.context(format!("and intercept.enabled could not be reset: {w:#}")),
        }
    };
    match &answer {
        Some(a) => match a["intercept"]["listening"].as_str() {
            Some(addr) => writeln!(cx.out, "✓ listener     filtering AI sites on {addr}")?,
            None => {
                let why = a["intercept"]["error"].as_str().unwrap_or(
                    "the daemon runs without its proxy services (started with --no-proxy)",
                );
                let e = anyhow!(
                    "the daemon could not start the intercept listener: {why}. Your system \
                     proxy settings were not changed"
                );
                return Err(undo(cx, config, e));
            }
        },
        None => writeln!(
            cx.out,
            "! daemon       not running — start it with {START_DAEMON}; until it runs, AI \
             sites are not filtered (they fail to load, or go direct if the system cannot fetch \
             the PAC file)"
        )?,
    }

    let state = match sysproxy::enable(cx.runner, cx.paths, cx.platform, &pac) {
        Ok(s) => s,
        Err(e) => return Err(undo(cx, config, e)),
    };
    writeln!(
        cx.out,
        "✓ system proxy AI sites now go to parda ({pac}); every other site stays direct"
    )?;
    let changed: Vec<String> = match sysproxy::inspect(cx.runner, cx.platform, &pac) {
        Ok(now) => now
            .into_iter()
            .filter(|c| c.parda)
            .map(|c| c.target)
            .collect(),
        Err(_) => state.saved.iter().map(|s| s.target.clone()).collect(),
    };
    for target in &changed {
        let before = state
            .saved
            .iter()
            .find(|s| &s.target == target || cx.platform != Platform::MacOs)
            .map(|s| describe_saved(cx.platform, s))
            .unwrap_or_else(|| "no automatic proxy".into());
        writeln!(
            cx.out,
            "    {:<22} before: {before}",
            target_label(cx.platform, target)
        )?;
    }
    writeln!(
        cx.out,
        "  Firefox uses its own settings: Settings → Network Settings → Automatic proxy \
         configuration URL = {pac}, and in about:config set security.enterprise_roots.enabled \
         = true"
    )?;
    writeln!(
        cx.out,
        "undo: `parda intercept off` puts the previous settings back"
    )?;
    Ok(())
}

/// `parda intercept off`: put the saved system settings back, then stop the
/// listener. Works with the daemon down and after a crash (the saved state
/// is on disk). If a setting cannot be put back, the listener keeps running
/// so the sites still sent to parda keep loading, and the command fails.
pub fn off(cx: &mut Ctx) -> anyhow::Result<()> {
    let restored = sysproxy::disable(cx.runner, cx.paths).context(
        "could not put the previous proxy settings back (intercept stays on so AI sites keep \
         loading)",
    )?;
    let failed = match restored {
        None => switch_off_found(cx)?,
        Some(r) => {
            let list = |v: &[String]| labels(cx.platform, v);
            if !r.restored.is_empty() {
                writeln!(cx.out, "✓ restored     {}", list(&r.restored))?;
            }
            if !r.gone.is_empty() {
                writeln!(
                    cx.out,
                    "· gone         {} (the network service no longer exists)",
                    list(&r.gone)
                )?;
            }
            if !r.kept.is_empty() {
                writeln!(
                    cx.out,
                    "· kept         {} (changed while parda was on — left as it is)",
                    list(&r.kept)
                )?;
            }
            if !r.failed.is_empty() {
                writeln!(
                    cx.out,
                    "✗ failed       {} (still sends AI sites to parda; saved for the next \
                     `parda intercept off`)",
                    list(&r.failed)
                )?;
            }
            r.failed
        }
    };
    if !failed.is_empty() {
        bail!(
            "{} setting(s) could not be put back; parda keeps filtering so those AI sites still \
             load — run `parda intercept off` again",
            failed.len()
        );
    }
    let mut config = read_config(cx)?;
    if config.intercept.enabled {
        config.intercept.enabled = false;
        let answer = write_config(cx, &config)?;
        if answer.is_some() {
            writeln!(cx.out, "✓ listener     stopped")?;
        } else {
            writeln!(
                cx.out,
                "✓ intercept    off (intercept.enabled = false; the daemon is not running)"
            )?;
        }
    } else {
        writeln!(cx.out, "· intercept    already off")?;
    }
    Ok(())
}

/// `off` with no saved settings: the system may still point at parda (the
/// state file was deleted, or `on` ran under another PARDA_HOME). Switch off
/// any parda PAC found, so AI sites do not fail to load once the listener
/// stops. Returns the settings that could not be switched off.
fn switch_off_found(cx: &mut Ctx) -> anyhow::Result<Vec<String>> {
    let config = read_config(cx)?;
    let pac = known_pac(cx.paths, &config);
    let label = |v: &[String]| labels(cx.platform, v);
    match sysproxy::switch_off_parda(cx.runner, cx.platform, &pac) {
        Err(e) => {
            writeln!(
                cx.out,
                "· system proxy no saved settings to restore, and the current setting could not \
                 be read ({e:#})"
            )?;
            Ok(Vec::new())
        }
        Ok(r) if r.restored.is_empty() && r.failed.is_empty() => {
            writeln!(
                cx.out,
                "· system proxy parda had not changed it — nothing to restore"
            )?;
            Ok(Vec::new())
        }
        Ok(r) => {
            if !r.restored.is_empty() {
                writeln!(
                    cx.out,
                    "✓ switched off {} (no saved settings; switched off parda's PAC — automatic \
                     proxy configuration is off there now)",
                    label(&r.restored)
                )?;
            }
            if !r.failed.is_empty() {
                writeln!(
                    cx.out,
                    "✗ failed       {} (still sends AI sites to parda)",
                    label(&r.failed)
                )?;
            }
            Ok(r.failed)
        }
    }
}

/// The daemon's `"intercept"` status, `None` when no daemon runs.
fn daemon_intercept(cx: &mut Ctx) -> anyhow::Result<Option<Value>> {
    match cx.daemon.as_deref_mut() {
        Some(d) => Ok(Some(d.call(Request::Status)?["intercept"].clone())),
        None => Ok(None),
    }
}

/// The certificate's state in one line, and whether it is a problem.
fn certificate_line(
    paths: &Paths,
    runner: &mut dyn Runner,
    platform: Platform,
) -> (CaState, String) {
    let pem = ca_cert_path(paths);
    if !ca_exists(paths) {
        return (
            CaState::Missing,
            "not created — `parda ca create`, then `parda ca install`".into(),
        );
    }
    match platform {
        Platform::Linux => (
            CaState::Unknown,
            format!(
                "created ({}); trust cannot be checked on Linux",
                pem.display()
            ),
        ),
        _ if cert_trust::is_trusted(runner, platform, &pem) => {
            (CaState::Trusted, format!("trusted ({})", pem.display()))
        }
        _ => (
            CaState::Untrusted,
            "created but NOT trusted — run `parda ca install`".into(),
        ),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CaState {
    Missing,
    Untrusted,
    Trusted,
    Unknown,
}

/// The PAC URL to recognise as parda's: the saved one, else the configured.
fn known_pac(paths: &Paths, config: &Config) -> String {
    sysproxy::load_state(paths)
        .ok()
        .flatten()
        .map(|s| s.pac_url)
        .or_else(|| pac_url(&config.intercept.listen).ok())
        .unwrap_or_default()
}

const FAIL_TO_LOAD: &str = "AI sites will fail to load — start the daemon or run `parda \
                            intercept off`";

/// `parda intercept status`. Only reads: never changes a file, a setting or
/// the daemon.
pub fn status(cx: &mut Ctx) -> anyhow::Result<()> {
    let config = load_config(cx.paths)?;
    let (_, cert) = certificate_line(cx.paths, cx.runner, cx.platform);
    writeln!(cx.out, "certificate:  {cert}")?;
    writeln!(
        cx.out,
        "intercept:    {}",
        if config.intercept.enabled {
            "on (intercept.enabled = true)"
        } else {
            "off — `parda intercept on`"
        }
    )?;
    let daemon = daemon_intercept(cx)?;
    let listening = daemon
        .as_ref()
        .and_then(|i| i["listening"].as_str().map(String::from));
    match (&daemon, &listening) {
        (None, _) => writeln!(
            cx.out,
            "listener:     daemon not running — start it with {START_DAEMON}"
        )?,
        (Some(_), Some(addr)) => writeln!(cx.out, "listener:     listening on {addr}")?,
        (Some(i), None) => writeln!(
            cx.out,
            "listener:     not listening{}",
            i["error"]
                .as_str()
                .map(|e| format!(" — {e}"))
                .unwrap_or_default()
        )?,
    }
    let pac = known_pac(cx.paths, &config);
    let mut pointed = false;
    match sysproxy::inspect(cx.runner, cx.platform, &pac) {
        Ok(now) => {
            pointed = now.iter().any(|c| c.parda);
            writeln!(
                cx.out,
                "system proxy: {}",
                if pointed {
                    "AI sites go to parda"
                } else {
                    "not pointing at parda"
                }
            )?;
            for c in &now {
                let what = if c.parda {
                    format!("parda ({})", c.url.as_deref().unwrap_or_default())
                } else {
                    describe(c.url.as_deref(), c.active)
                };
                writeln!(
                    cx.out,
                    "    {:<22} {what}",
                    target_label(cx.platform, &c.target)
                )?;
            }
        }
        Err(e) => writeln!(cx.out, "system proxy: could not be read ({e:#})")?,
    }
    if let Ok(Some(state)) = sysproxy::load_state(cx.paths) {
        writeln!(
            cx.out,
            "saved:        previous settings of {} kept for `parda intercept off`",
            state
                .saved
                .iter()
                .map(|s| target_label(cx.platform, &s.target))
                .collect::<Vec<_>>()
                .join(", ")
        )?;
    }
    writeln!(
        cx.out,
        "hosts:        {}",
        config.intercept.hosts.join(", ")
    )?;
    writeln!(cx.out, "scope:        {}", config.intercept.scope)?;
    let unscanned = serde_json::to_value(config.intercept.unscanned)?;
    writeln!(
        cx.out,
        "unscanned:    {} (file uploads and other parts parda cannot read)",
        unscanned.as_str().unwrap_or("?")
    )?;
    if pointed && listening.is_none() {
        writeln!(cx.out, "! {FAIL_TO_LOAD}")?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub level: Level,
    pub what: &'static str,
    pub detail: String,
}

/// The intercept lines of `parda doctor`. Only reads. `daemon_status` is the
/// daemon's status, `None` when it is not running.
pub fn doctor_checks(
    paths: &Paths,
    runner: &mut dyn Runner,
    platform: Platform,
    config: &Config,
    daemon_status: Option<&Value>,
) -> Vec<Check> {
    let mut out = Vec::new();
    let mut add = |level, what, detail: String| {
        out.push(Check {
            level,
            what,
            detail,
        })
    };
    let enabled = config.intercept.enabled;
    let pac = known_pac(paths, config);
    let now = sysproxy::inspect(runner, platform, &pac);
    let pointed: Vec<String> = now
        .as_ref()
        .map(|v| {
            v.iter()
                .filter(|c| c.parda)
                .map(|c| target_label(platform, &c.target))
                .collect()
        })
        .unwrap_or_default();
    let in_use = enabled || !pointed.is_empty();

    let (ca, line) = certificate_line(paths, runner, platform);
    let ca_level = match ca {
        CaState::Trusted => Level::Ok,
        CaState::Missing | CaState::Untrusted if in_use => Level::Warn,
        _ => Level::Info,
    };
    add(ca_level, "certificate", line);

    let intercept = daemon_status.map(|s| &s["intercept"]);
    let listening = intercept.and_then(|i| i["listening"].as_str());
    match (enabled, intercept, listening) {
        (false, _, _) => add(
            Level::Info,
            "intercept",
            "off (protect AI websites and apps: `parda intercept on`)".into(),
        ),
        (true, _, Some(addr)) => add(Level::Ok, "intercept", format!("listening on {addr}")),
        (true, Some(i), None) => add(
            Level::Warn,
            "intercept",
            format!(
                "on but not listening — {}",
                i["error"]
                    .as_str()
                    .unwrap_or("the daemon runs without its proxy services")
            ),
        ),
        // The daemon line already says it is down.
        (true, None, None) => add(
            Level::Info,
            "intercept",
            "on (starts with the daemon)".into(),
        ),
    }

    match now {
        Err(e) => add(
            Level::Info,
            "system proxy",
            format!("could not be read ({e:#})"),
        ),
        Ok(_) if !pointed.is_empty() && listening.is_none() => add(
            Level::Warn,
            "system proxy",
            format!(
                "{} send AI sites to parda but nothing listens: {FAIL_TO_LOAD}",
                pointed.join(", ")
            ),
        ),
        Ok(_) if !pointed.is_empty() => add(
            Level::Ok,
            "system proxy",
            format!("AI sites go to parda ({})", pointed.join(", ")),
        ),
        Ok(_) if enabled => add(
            Level::Warn,
            "system proxy",
            "not pointing at parda — run `parda intercept on`".into(),
        ),
        Ok(_) => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use parda_core::UnscannedMedia;
    use parda_daemon::ca_store::create_ca;
    use serde_json::json;

    use super::*;

    const PAC: &str = "http://127.0.0.1:8788/parda.pac";

    /// A pretend Mac: network services and the trust state of parda's CA.
    #[derive(Default)]
    struct Mac {
        /// service → (PAC url, auto-proxy on)
        services: BTreeMap<String, (Option<String>, bool)>,
        trusted: bool,
        failing: Vec<String>,
        calls: Vec<String>,
    }

    impl Runner for Mac {
        fn run(&mut self, program: &str, args: &[&str]) -> anyhow::Result<String> {
            let line = format!("{program} {}", args.join(" "));
            self.calls.push(line.clone());
            if self.failing.iter().any(|f| line.starts_with(f.as_str())) {
                bail!("failed: {line}");
            }
            Ok(match (program, args) {
                ("security", ["verify-cert", ..]) if self.trusted => {
                    "...certificate verification successful.\n".into()
                }
                ("security", ["verify-cert", ..]) => bail!("CSSMERR_TP_NOT_TRUSTED"),
                ("networksetup", ["-listallnetworkservices"]) => {
                    let mut out =
                        "An asterisk (*) denotes that a network service is disabled.\n".to_string();
                    for name in self.services.keys() {
                        out.push_str(&format!("{name}\n"));
                    }
                    out
                }
                ("networksetup", ["-getautoproxyurl", svc]) => {
                    let Some((url, on)) = self.services.get(*svc) else {
                        bail!("no such service")
                    };
                    format!(
                        "URL: {}\nEnabled: {}\n",
                        url.as_deref().unwrap_or("(null)"),
                        if *on { "Yes" } else { "No" }
                    )
                }
                ("networksetup", ["-setautoproxyurl", svc, url]) => {
                    let e = self.services.get_mut(*svc).unwrap();
                    *e = (Some(url.to_string()), true);
                    String::new()
                }
                ("networksetup", ["-setautoproxystate", svc, state]) => {
                    self.services.get_mut(*svc).unwrap().1 = *state == "on";
                    String::new()
                }
                _ => bail!("unexpected command: {line}"),
            })
        }
    }

    impl Mac {
        fn new(trusted: bool) -> Mac {
            let mut m = Mac {
                trusted,
                ..Default::default()
            };
            m.services.insert("Wi-Fi".into(), (None, false));
            m.services.insert(
                "Ethernet".into(),
                (Some("http://corp/proxy.pac".into()), true),
            );
            m
        }

        /// Commands that change trust or network settings.
        fn writes(&self) -> Vec<&String> {
            self.calls
                .iter()
                .filter(|c| {
                    c.starts_with("networksetup -set")
                        || c.contains("add-trusted-cert")
                        || c.contains("delete-certificate")
                })
                .collect()
        }
    }

    /// A running daemon that keeps its config and starts the listener when
    /// `intercept.enabled` (unless `error` says why it cannot).
    struct FakeDaemon {
        config: Config,
        error: Option<String>,
        sets: usize,
    }

    impl FakeDaemon {
        fn new(config: Config) -> FakeDaemon {
            FakeDaemon {
                config,
                error: None,
                sets: 0,
            }
        }

        fn intercept(&self) -> Value {
            let on = self.config.intercept.enabled;
            json!({
                "enabled": on,
                "listening": (on && self.error.is_none()).then_some("127.0.0.1:8788"),
                "ca": true,
                "error": if on { self.error.clone() } else { None },
                "pac": null,
            })
        }
    }

    impl DaemonLink for FakeDaemon {
        fn call(&mut self, req: Request) -> anyhow::Result<Value> {
            match req {
                Request::ConfigGet => Ok(json!({"toml": self.config.to_toml_string()?})),
                Request::ConfigSet { toml } => {
                    self.config = Config::from_toml_str(&toml)?;
                    self.sets += 1;
                    Ok(json!({"restart_required": false, "intercept": self.intercept()}))
                }
                Request::Status => Ok(json!({"pid": 1, "intercept": self.intercept()})),
                other => bail!("unexpected request {other:?}"),
            }
        }
    }

    fn home() -> (tempfile::TempDir, Paths) {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path().to_path_buf());
        write_private(&p.config_file(), "[vault]\nuse_keyring = false\n").unwrap();
        (d, p)
    }

    fn home_with_ca() -> (tempfile::TempDir, Paths) {
        let (d, p) = home();
        create_ca(&p, false, false).unwrap();
        (d, p)
    }

    fn exec<T>(
        p: &Paths,
        os: &mut Mac,
        daemon: Option<&mut FakeDaemon>,
        f: impl FnOnce(&mut Ctx) -> anyhow::Result<T>,
    ) -> (anyhow::Result<T>, String) {
        let mut out = Vec::new();
        let r = {
            let mut cx = Ctx {
                paths: p,
                runner: os,
                platform: Platform::MacOs,
                daemon: daemon.map(|d| d as &mut dyn DaemonLink),
                out: &mut out,
            };
            f(&mut cx)
        };
        (r, String::from_utf8(out).unwrap())
    }

    fn enabled_in_file(p: &Paths) -> bool {
        load_config(p).unwrap().intercept.enabled
    }

    #[test]
    fn pac_url_needs_a_loopback_address_with_a_fixed_port() {
        assert_eq!(pac_url("127.0.0.1:8788").unwrap(), PAC);
        assert_eq!(
            pac_url("[::1]:9000").unwrap(),
            "http://[::1]:9000/parda.pac"
        );
        assert_eq!(
            pac_url("localhost:8788").unwrap(),
            "http://localhost:8788/parda.pac"
        );
        for bad in [
            "0.0.0.0:8788",
            "10.0.0.2:8788",
            "127.0.0.1:0",
            "example.com:80",
            "8788",
            "",
        ] {
            assert!(pac_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn on_without_a_certificate_says_create_it_and_changes_nothing() {
        let (_d, p) = home();
        let mut os = Mac::new(true);
        let (r, _) = exec(&p, &mut os, None, on);
        let e = format!("{:#}", r.unwrap_err());
        assert!(e.contains("parda ca create"), "{e}");
        assert!(os.writes().is_empty(), "{:?}", os.calls);
        assert!(!enabled_in_file(&p));
        assert!(
            !parda_daemon::ca_store::ca_exists(&p),
            "never created implicitly"
        );
        assert!(sysproxy::load_state(&p).unwrap().is_none());
    }

    #[test]
    fn on_with_an_untrusted_certificate_says_install_it_and_changes_nothing() {
        let (_d, p) = home_with_ca();
        let mut os = Mac::new(false);
        let mut daemon = FakeDaemon::new(load_config(&p).unwrap());
        let (r, _) = exec(&p, &mut os, Some(&mut daemon), on);
        let e = format!("{:#}", r.unwrap_err());
        assert!(
            e.contains("parda ca install") && e.contains("dialog"),
            "{e}"
        );
        assert!(
            os.writes().is_empty(),
            "never installed implicitly: {:?}",
            os.calls
        );
        assert_eq!(daemon.sets, 0);
        assert!(sysproxy::load_state(&p).unwrap().is_none());
    }

    #[test]
    fn on_with_the_daemon_running_starts_the_listener_then_points_the_system_at_it() {
        let (_d, p) = home_with_ca();
        let mut os = Mac::new(true);
        let mut daemon = FakeDaemon::new(load_config(&p).unwrap());
        let (r, out) = exec(&p, &mut os, Some(&mut daemon), on);
        r.unwrap();
        assert!(daemon.config.intercept.enabled);
        assert_eq!(daemon.sets, 1);
        for svc in ["Wi-Fi", "Ethernet"] {
            assert_eq!(os.services[svc], (Some(PAC.to_string()), true), "{svc}");
        }
        assert!(out.contains("127.0.0.1:8788"), "{out}");
        assert!(out.contains("Wi-Fi") && out.contains("Ethernet"), "{out}");
        assert!(
            out.contains("http://corp/proxy.pac"),
            "shows what was there: {out}"
        );
        assert!(out.contains("parda intercept off"), "{out}");
        assert!(out.contains("Firefox"), "{out}");
        assert!(sysproxy::load_state(&p).unwrap().is_some());
    }

    #[test]
    fn on_with_the_daemon_down_writes_the_config_and_says_how_to_start_it() {
        let (_d, p) = home_with_ca();
        let mut os = Mac::new(true);
        let (r, out) = exec(&p, &mut os, None, on);
        r.unwrap();
        assert!(enabled_in_file(&p));
        assert!(
            out.contains("not running") && out.contains("parda daemon"),
            "{out}"
        );
        assert_eq!(os.services["Wi-Fi"], (Some(PAC.to_string()), true));
    }

    #[test]
    fn on_leaves_the_system_alone_when_the_daemon_cannot_listen() {
        let (_d, p) = home_with_ca();
        let mut os = Mac::new(true);
        let mut daemon = FakeDaemon::new(load_config(&p).unwrap());
        daemon.error = Some("intercept: cannot listen on 127.0.0.1:8788: address in use".into());
        let (r, _) = exec(&p, &mut os, Some(&mut daemon), on);
        let e = format!("{:#}", r.unwrap_err());
        assert!(
            e.contains("address in use") && e.contains("not changed"),
            "{e}"
        );
        assert!(os.writes().is_empty(), "{:?}", os.calls);
        assert!(!daemon.config.intercept.enabled, "switched back off");
    }

    #[test]
    fn on_rejects_a_listen_address_that_cannot_carry_a_pac_url() {
        let (_d, p) = home_with_ca();
        write_private(
            &p.config_file(),
            "[vault]\nuse_keyring = false\n[intercept]\nlisten = \"127.0.0.1:0\"\n",
        )
        .unwrap();
        let mut os = Mac::new(true);
        let (r, _) = exec(&p, &mut os, None, on);
        assert!(format!("{:#}", r.unwrap_err()).contains("intercept.listen"));
        assert!(os.writes().is_empty());
        assert!(!enabled_in_file(&p));
    }

    #[test]
    fn a_failed_system_change_is_rolled_back_and_intercept_switched_off_again() {
        let (_d, p) = home_with_ca();
        let mut os = Mac::new(true);
        os.failing
            .push("networksetup -setautoproxyurl Wi-Fi".into());
        let before = os.services.clone();
        let (r, _) = exec(&p, &mut os, None, on);
        assert!(r.is_err());
        assert_eq!(os.services, before);
        assert!(!enabled_in_file(&p));
    }

    #[test]
    fn off_restores_the_previous_settings_and_stops_the_listener() {
        let (_d, p) = home_with_ca();
        let mut os = Mac::new(true);
        let before = os.services.clone();
        let mut daemon = FakeDaemon::new(load_config(&p).unwrap());
        exec(&p, &mut os, Some(&mut daemon), on).0.unwrap();
        let (r, out) = exec(&p, &mut os, Some(&mut daemon), off);
        r.unwrap();
        assert_eq!(os.services["Ethernet"], before["Ethernet"]);
        assert!(!os.services["Wi-Fi"].1, "Wi-Fi auto-proxy off again");
        assert!(!daemon.config.intercept.enabled);
        assert!(
            out.contains("restored") && out.contains("Ethernet"),
            "{out}"
        );
        assert!(sysproxy::load_state(&p).unwrap().is_none());
    }

    #[test]
    fn off_works_with_the_daemon_down_after_a_crash() {
        let (_d, p) = home_with_ca();
        let mut os = Mac::new(true);
        exec(&p, &mut os, None, on).0.unwrap();
        // The daemon died; only the state file and config.toml remain.
        let (r, out) = exec(&p, &mut os, None, off);
        r.unwrap();
        assert!(!enabled_in_file(&p));
        assert_eq!(
            os.services["Ethernet"],
            (Some("http://corp/proxy.pac".into()), true)
        );
        assert!(out.contains("restored"), "{out}");
    }

    #[test]
    fn off_reports_what_was_kept_and_gone() {
        let (_d, p) = home_with_ca();
        let mut os = Mac::new(true);
        exec(&p, &mut os, None, on).0.unwrap();
        os.services.get_mut("Ethernet").unwrap().0 = Some("http://mine/new.pac".into());
        os.services.remove("Wi-Fi");
        let (r, out) = exec(&p, &mut os, None, off);
        r.unwrap();
        assert!(
            out.contains("Wi-Fi") && out.contains("no longer exists"),
            "{out}"
        );
        assert!(
            out.contains("Ethernet") && out.contains("left as it is"),
            "{out}"
        );
        assert_eq!(
            os.services["Ethernet"].0.as_deref(),
            Some("http://mine/new.pac")
        );
    }

    #[test]
    fn off_that_cannot_restore_fails_and_keeps_the_listener_for_the_sites_still_pointing_at_it() {
        let (_d, p) = home_with_ca();
        let mut os = Mac::new(true);
        let mut daemon = FakeDaemon::new(load_config(&p).unwrap());
        exec(&p, &mut os, Some(&mut daemon), on).0.unwrap();
        os.failing
            .push("networksetup -setautoproxyurl Ethernet".into());
        let (r, out) = exec(&p, &mut os, Some(&mut daemon), off);
        let e = format!("{:#}", r.unwrap_err());
        assert!(e.contains("parda intercept off"), "{e}");
        assert!(out.contains("Ethernet") && out.contains("failed"), "{out}");
        assert!(daemon.config.intercept.enabled, "listener kept");
        // A second off finishes the job.
        os.failing.clear();
        exec(&p, &mut os, Some(&mut daemon), off).0.unwrap();
        assert!(!daemon.config.intercept.enabled);
        assert!(sysproxy::load_state(&p).unwrap().is_none());
    }

    #[test]
    fn off_when_nothing_was_changed_just_switches_intercept_off() {
        let (_d, p) = home();
        let mut os = Mac::new(true);
        let (r, out) = exec(&p, &mut os, None, off);
        r.unwrap();
        assert!(out.contains("nothing to restore"), "{out}");
        assert!(os.writes().is_empty(), "{:?}", os.calls);
        assert!(!enabled_in_file(&p));
    }

    /// The system points at parda but intercept-state.json is gone (data
    /// folder cleaned, another PARDA_HOME, deleted by hand).
    fn pointed_without_state(p: &Paths) -> (Mac, FakeDaemon) {
        let mut os = Mac::new(true);
        for v in os.services.values_mut() {
            *v = (Some(PAC.into()), true);
        }
        let mut cfg = load_config(p).unwrap();
        cfg.intercept.enabled = true;
        (os, FakeDaemon::new(cfg))
    }

    #[test]
    fn off_without_saved_settings_switches_off_the_parda_pac_it_finds() {
        let (_d, p) = home_with_ca();
        let (mut os, mut daemon) = pointed_without_state(&p);
        let (r, out) = exec(&p, &mut os, Some(&mut daemon), off);
        r.unwrap();
        for svc in ["Wi-Fi", "Ethernet"] {
            assert!(!os.services[svc].1, "{svc} auto-proxy off: {out}");
        }
        assert!(
            out.contains("no saved settings") && out.contains("Ethernet"),
            "{out}"
        );
        assert!(!daemon.config.intercept.enabled, "listener stopped");
        // Nothing points at parda now: doctor is content.
        let c = checks(&p, &mut os, None);
        assert!(c.iter().all(|c| c.level != Level::Warn), "{c:?}");
    }

    #[test]
    fn off_without_saved_settings_that_cannot_switch_off_keeps_the_listener() {
        let (_d, p) = home_with_ca();
        let (mut os, mut daemon) = pointed_without_state(&p);
        os.failing
            .push("networksetup -setautoproxystate Ethernet".into());
        let (r, out) = exec(&p, &mut os, Some(&mut daemon), off);
        let e = format!("{:#}", r.unwrap_err());
        assert!(e.contains("parda intercept off"), "{e}");
        assert!(out.contains("Ethernet") && out.contains("failed"), "{out}");
        assert!(daemon.config.intercept.enabled, "listener kept");
        os.failing.clear();
        exec(&p, &mut os, Some(&mut daemon), off).0.unwrap();
        assert!(!daemon.config.intercept.enabled);
        assert!(os.services.values().all(|(_, on)| !on));
    }

    /// Every file under the home folder with its contents.
    fn snapshot(p: &Paths) -> BTreeMap<String, Vec<u8>> {
        fn walk(dir: &std::path::Path, out: &mut BTreeMap<String, Vec<u8>>) {
            for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let path = e.path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.insert(path.display().to_string(), std::fs::read(&path).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(p.home.as_ref().unwrap(), &mut out);
        out
    }

    #[test]
    fn status_only_reads_and_reports_everything() {
        let (_d, p) = home_with_ca();
        let mut os = Mac::new(true);
        let mut cfg = load_config(&p).unwrap();
        cfg.intercept.unscanned = UnscannedMedia::Block;
        write_private(&p.config_file(), &cfg.to_toml_string().unwrap()).unwrap();
        let mut daemon = FakeDaemon::new(cfg);
        exec(&p, &mut os, Some(&mut daemon), on).0.unwrap();
        os.calls.clear();
        let files = snapshot(&p);
        let sets = daemon.sets;

        let (r, out) = exec(&p, &mut os, Some(&mut daemon), status);
        r.unwrap();
        assert!(os.writes().is_empty(), "{:?}", os.calls);
        assert_eq!(daemon.sets, sets, "no config change");
        assert_eq!(snapshot(&p), files, "no file changed");
        for want in [
            "trusted",
            "listening on 127.0.0.1:8788",
            "Wi-Fi",
            "Ethernet",
            PAC,
            "chatgpt.com",
            "per-host",
            "block",
        ] {
            assert!(out.contains(want), "missing {want:?} in\n{out}");
        }
        assert!(!out.contains("fail to load"), "{out}");
    }

    #[test]
    fn status_warns_when_the_system_points_at_parda_but_the_daemon_is_down() {
        let (_d, p) = home_with_ca();
        let mut os = Mac::new(true);
        exec(&p, &mut os, None, on).0.unwrap();
        os.calls.clear();
        let (r, out) = exec(&p, &mut os, None, status);
        r.unwrap();
        assert!(out.contains("daemon not running"), "{out}");
        assert!(
            out.contains("fail to load") && out.contains("parda intercept off"),
            "{out}"
        );
        assert!(os.writes().is_empty(), "{:?}", os.calls);
    }

    #[test]
    fn status_without_a_certificate_runs_no_trust_check() {
        let (_d, p) = home();
        let mut os = Mac::new(true);
        let (r, out) = exec(&p, &mut os, None, status);
        r.unwrap();
        assert!(
            out.contains("not created") && out.contains("parda ca create"),
            "{out}"
        );
        assert!(
            !os.calls.iter().any(|c| c.starts_with("security")),
            "{:?}",
            os.calls
        );
        assert!(os.writes().is_empty());
    }

    fn checks(p: &Paths, os: &mut Mac, status: Option<&Value>) -> Vec<Check> {
        doctor_checks(p, os, Platform::MacOs, &load_config(p).unwrap(), status)
    }

    #[test]
    fn doctor_warns_when_the_pac_is_active_but_nothing_listens() {
        let (_d, p) = home_with_ca();
        let mut os = Mac::new(true);
        exec(&p, &mut os, None, on).0.unwrap();
        os.calls.clear();
        let down = checks(&p, &mut os, None);
        let warn = down
            .iter()
            .find(|c| c.level == Level::Warn && c.detail.contains("fail to load"))
            .unwrap_or_else(|| panic!("{down:?}"));
        assert!(warn.detail.contains("parda intercept off"), "{warn:?}");
        assert!(os.writes().is_empty());

        let running =
            json!({"intercept": {"enabled": true, "listening": "127.0.0.1:8788", "ca": true}});
        let up = checks(&p, &mut os, Some(&running));
        assert!(up.iter().all(|c| c.level != Level::Warn), "{up:?}");
        assert!(up.iter().any(|c| c.detail.contains("trusted")), "{up:?}");
    }

    #[test]
    fn doctor_flags_an_untrusted_certificate_and_a_listener_that_failed() {
        let (_d, p) = home_with_ca();
        let mut cfg = load_config(&p).unwrap();
        cfg.intercept.enabled = true;
        write_private(&p.config_file(), &cfg.to_toml_string().unwrap()).unwrap();
        let mut os = Mac::new(false);
        let st = json!({"intercept": {"enabled": true, "listening": null, "ca": true,
                                      "error": "intercept: cannot listen on 127.0.0.1:8788"}});
        let c = checks(&p, &mut os, Some(&st));
        assert!(
            c.iter()
                .any(|c| c.level == Level::Warn && c.detail.contains("parda ca install")),
            "{c:?}"
        );
        assert!(
            c.iter()
                .any(|c| c.level == Level::Warn && c.detail.contains("cannot listen")),
            "{c:?}"
        );
    }

    #[test]
    fn doctor_is_quiet_when_intercept_was_never_set_up() {
        let (_d, p) = home();
        let mut os = Mac::new(false);
        let c = checks(&p, &mut os, None);
        assert!(c.iter().all(|c| c.level == Level::Info), "{c:?}");
        assert!(os.calls.iter().all(|c| !c.starts_with("security")));
    }
}
