//! Pointing the operating system's automatic proxy configuration (PAC) at
//! parda, and putting the previous setting back.
//!
//! The previous settings are saved to `intercept-state.json` *before*
//! anything is changed. [`disable`] restores every entry it can, keeps the
//! ones that failed in the state file for a later retry, and drops entries
//! whose network service no longer exists — so `parda intercept off` always
//! makes progress, even after a crash.

use std::path::PathBuf;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use crate::paths::{Paths, write_private};
pub use crate::system::{Platform, Runner, SystemRunner};

const STATE_FILE: &str = "intercept-state.json";
const WIN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// One saved setting: a macOS network service, the Windows user setting, or
/// the GNOME proxy setting (`target` holds the previous GNOME mode).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    pub target: String,
    pub url: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub platform: Platform,
    pub pac_url: String,
    pub saved: Vec<Saved>,
}

/// Outcome of [`disable`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Restored {
    /// Entries put back as they were.
    pub restored: Vec<String>,
    /// Entries whose network service no longer exists (nothing to restore).
    pub gone: Vec<String>,
    /// Entries that could not be restored; kept in the state file.
    pub failed: Vec<String>,
    /// Entries changed by someone else while protection was on; left as they are.
    pub kept: Vec<String>,
}

fn state_path(paths: &Paths) -> PathBuf {
    paths.data_dir.join(STATE_FILE)
}

/// Where the saved settings live (`intercept-state.json` in the data folder).
pub fn state_file(paths: &Paths) -> PathBuf {
    state_path(paths)
}

/// Move the state file aside (to `intercept-state.json.damaged`), for
/// `parda intercept off --forget` when it cannot be read. Returns where it
/// went, `None` when there was none.
pub fn set_aside_state(paths: &Paths) -> anyhow::Result<Option<PathBuf>> {
    let from = state_path(paths);
    let to = from.with_extension("json.damaged");
    match std::fs::rename(&from, &to) {
        Ok(()) => Ok(Some(to)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("moving {} aside", from.display())),
    }
}

pub fn load_state(paths: &Paths) -> anyhow::Result<Option<State>> {
    match std::fs::read_to_string(state_path(paths)) {
        Ok(s) => Ok(Some(
            serde_json::from_str(&s).context("intercept-state.json is damaged")?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn save_state(paths: &Paths, state: &State) -> anyhow::Result<()> {
    paths.ensure()?;
    write_private(&state_path(paths), &serde_json::to_string_pretty(state)?)?;
    Ok(())
}

/// Whether `url` is a parda PAC address: the current one, or any loopback
/// `…/parda.pac` (e.g. from an earlier run on another port).
pub fn is_parda_pac(url: &str, pac_url: &str) -> bool {
    if url == pac_url {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(h, _)| h)
        .trim_start_matches('[')
        .trim_end_matches(']');
    path == "parda.pac" && matches!(host, "127.0.0.1" | "localhost" | "::1")
}

/// Whether the parda PAC at `url` is served by a listener bound to `addr`:
/// same port, and the same loopback address (`localhost` matches either).
/// A PAC left on an old port makes AI sites fail to load.
pub fn pac_points_at(url: &str, addr: std::net::SocketAddr) -> bool {
    let Some(authority) = url
        .strip_prefix("http://")
        .and_then(|rest| rest.strip_suffix("/parda.pac"))
    else {
        return false;
    };
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    if port.parse::<u16>().ok() != Some(addr.port()) {
        return false;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return addr.ip().is_loopback();
    }
    host.parse::<std::net::IpAddr>().ok() == Some(addr.ip())
}

/// A setting that already points at parda is not an "original" setting.
fn forget_ours(mut s: Saved, pac_url: &str) -> Saved {
    if s.url.as_deref().is_some_and(|u| is_parda_pac(u, pac_url)) {
        s.url = None;
        s.enabled = false;
    }
    s
}

/// Keep `now` as `target`'s original, unless an earlier `on` saved one and
/// the setting still points at parda (`ours`). A setting someone changed
/// while parda was on (a VPN's PAC, auto-proxy switched off) is the new
/// original: `off` must put *that* back, not the one from before.
fn remember(saved: &mut Vec<Saved>, target: &str, ours: bool, now: Saved) {
    match saved.iter_mut().find(|s| s.target == target) {
        Some(_) if ours => {}
        Some(s) => *s = now,
        None => saved.push(now),
    }
}

/// [`remember`] for the single Windows / GNOME entry (whose `target` is
/// not a fixed name).
fn remember_only(saved: &mut Vec<Saved>, ours: bool, now: Saved) {
    if saved.is_empty() || !ours {
        *saved = vec![now];
    }
}

// ---------- macOS ----------

/// Network services as `(name, enabled)`. A name listed twice (two
/// "iPhone USB" services) can only be addressed once by name.
fn mac_services(r: &mut dyn Runner) -> anyhow::Result<Vec<(String, bool)>> {
    let out = r.run("networksetup", &["-listallnetworkservices"])?;
    let mut seen = std::collections::HashSet::new();
    Ok(out
        .lines()
        .skip(1) // "An asterisk (*) denotes that a network service is disabled."
        .map(|l| l.trim_matches(|c: char| c == '\r' || c == '\n'))
        .filter(|l| !l.trim().is_empty())
        .map(|l| match l.strip_prefix('*') {
            Some(name) => (name.to_string(), false),
            None => (l.to_string(), true),
        })
        .filter(|(name, _)| seen.insert(name.clone()))
        .collect())
}

fn mac_get(r: &mut dyn Runner, service: &str) -> anyhow::Result<Saved> {
    let out = r.run("networksetup", &["-getautoproxyurl", service])?;
    let mut url = None;
    let mut enabled = false;
    for line in out.lines() {
        if let Some(v) = line.strip_prefix("URL:") {
            let v = v.trim();
            if !v.is_empty() && v != "(null)" {
                url = Some(v.to_string());
            }
        } else if let Some(v) = line.strip_prefix("Enabled:") {
            enabled = v.trim().eq_ignore_ascii_case("yes");
        }
    }
    Ok(Saved {
        target: service.to_string(),
        url,
        enabled,
    })
}

fn mac_restore(r: &mut dyn Runner, s: &Saved) -> anyhow::Result<()> {
    if let Some(url) = &s.url {
        // Setting the URL also switches the service on; set the state after.
        r.run("networksetup", &["-setautoproxyurl", &s.target, url])?;
    }
    let state = if s.enabled { "on" } else { "off" };
    r.run("networksetup", &["-setautoproxystate", &s.target, state])?;
    Ok(())
}

// ---------- Windows ----------

fn win_query(r: &mut dyn Runner) -> Option<String> {
    // `reg query` fails when the value does not exist.
    r.run("reg", &["query", WIN_KEY, "/v", "AutoConfigURL"])
        .ok()
        .and_then(|out| {
            out.lines()
                .find(|l| l.trim_start().starts_with("AutoConfigURL"))
                .and_then(|l| l.split("REG_SZ").nth(1))
                .map(|v| v.trim().to_string())
        })
        .filter(|v| !v.is_empty())
}

fn win_get(r: &mut dyn Runner) -> Saved {
    let url = win_query(r);
    Saved {
        target: "user".into(),
        enabled: url.is_some(),
        url,
    }
}

fn win_set(r: &mut dyn Runner, url: Option<&str>) -> anyhow::Result<()> {
    match url {
        Some(url) => {
            r.run(
                "reg",
                &[
                    "add",
                    WIN_KEY,
                    "/v",
                    "AutoConfigURL",
                    "/t",
                    "REG_SZ",
                    "/d",
                    url,
                    "/f",
                ],
            )?;
        }
        // Only delete a value that exists, so a real failure is not mistaken
        // for "already gone".
        None if win_query(r).is_some() => {
            r.run("reg", &["delete", WIN_KEY, "/v", "AutoConfigURL", "/f"])?;
        }
        None => {}
    }
    r.refresh_proxy_settings();
    Ok(())
}

// ---------- Linux (GNOME) ----------

fn unquote(s: &str) -> String {
    s.trim().trim_matches('\'').to_string()
}

fn gnome_get(r: &mut dyn Runner) -> anyhow::Result<Saved> {
    let mode = unquote(&r.run("gsettings", &["get", "org.gnome.system.proxy", "mode"])?);
    let url = unquote(&r.run(
        "gsettings",
        &["get", "org.gnome.system.proxy", "autoconfig-url"],
    )?);
    Ok(Saved {
        target: mode,
        url: (!url.is_empty()).then_some(url),
        enabled: true,
    })
}

fn gnome_set(r: &mut dyn Runner, mode: &str, url: &str) -> anyhow::Result<()> {
    r.run(
        "gsettings",
        &["set", "org.gnome.system.proxy", "autoconfig-url", url],
    )?;
    r.run(
        "gsettings",
        &["set", "org.gnome.system.proxy", "mode", mode],
    )?;
    Ok(())
}

// ---------- public API ----------

/// Point the system at `pac_url`. The original settings are saved first; an
/// existing state file (from an earlier `on`, or a crash) keeps its originals
/// for settings that still point at parda, takes the current value of those
/// changed since (by the user or a VPN), and adds services enabled since then. If any change fails,
/// everything done so far is rolled back before the error is returned.
pub fn enable(
    r: &mut dyn Runner,
    paths: &Paths,
    platform: Platform,
    pac_url: &str,
) -> anyhow::Result<State> {
    let existing = load_state(paths)?;
    let mut state = existing.unwrap_or(State {
        platform,
        pac_url: pac_url.to_string(),
        saved: Vec::new(),
    });
    state.pac_url = pac_url.to_string();
    let mut targets: Vec<String> = Vec::new();
    match platform {
        Platform::MacOs => {
            let services: Vec<String> = mac_services(r)?
                .into_iter()
                .filter_map(|(name, on)| on.then_some(name))
                .collect();
            if services.is_empty() {
                bail!("no enabled network service found (networksetup -listallnetworkservices)");
            }
            for svc in &services {
                let now = mac_get(r, svc)?;
                let ours =
                    now.enabled && now.url.as_deref().is_some_and(|u| is_parda_pac(u, pac_url));
                remember(&mut state.saved, svc, ours, forget_ours(now, pac_url));
            }
            targets = services;
        }
        Platform::Windows => {
            let now = win_get(r);
            let ours = now.url.as_deref().is_some_and(|u| is_parda_pac(u, pac_url));
            remember_only(&mut state.saved, ours, forget_ours(now, pac_url));
        }
        Platform::Linux => {
            let mut now = gnome_get(r)?;
            let ours = now.target == "auto"
                && now.url.as_deref().is_some_and(|u| is_parda_pac(u, pac_url));
            if ours {
                now.target = "none".into();
                now.url = None;
            }
            remember_only(&mut state.saved, ours, now);
        }
    }
    save_state(paths, &state)?;
    let applied = (|| -> anyhow::Result<()> {
        match platform {
            Platform::MacOs => {
                for svc in &targets {
                    r.run("networksetup", &["-setautoproxyurl", svc, pac_url])?;
                    r.run("networksetup", &["-setautoproxystate", svc, "on"])?;
                }
            }
            Platform::Windows => win_set(r, Some(pac_url))?,
            Platform::Linux => gnome_set(r, "auto", pac_url)?,
        }
        Ok(())
    })();
    if let Err(e) = applied {
        return Err(match disable(r, paths) {
            Ok(Some(r)) if r.failed.is_empty() => e.context(
                "could not point the system at parda; every change was undone (protection is off)",
            ),
            Ok(Some(r)) => e.context(format!(
                "could not point the system at parda, and these settings could not be put back: {} — run `parda intercept off` to retry",
                r.failed.join(", ")
            )),
            Ok(None) => e.context("could not point the system at parda"),
            Err(r_err) => e.context(format!(
                "could not point the system at parda, and undoing the changes failed too ({r_err:#}); run `parda intercept off`"
            )),
        });
    }
    Ok(state)
}

/// The automatic proxy setting one target uses right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Current {
    /// macOS network service, `user` (Windows) or `GNOME`.
    pub target: String,
    /// The configured PAC URL, if any (it may be switched off).
    pub url: Option<String>,
    /// Whether the PAC URL is in use.
    pub active: bool,
    /// In use, and it is a parda PAC (any port).
    pub parda: bool,
}

/// What the system uses now — every enabled macOS network service, the
/// Windows user setting or the GNOME setting. Only reads; never changes
/// anything (for `parda intercept status` and `parda doctor`).
pub fn inspect(
    r: &mut dyn Runner,
    platform: Platform,
    pac_url: &str,
) -> anyhow::Result<Vec<Current>> {
    let current = |target: String, url: Option<String>, active: bool| {
        let parda = active && url.as_deref().is_some_and(|u| is_parda_pac(u, pac_url));
        Current {
            target,
            url,
            active,
            parda,
        }
    };
    Ok(match platform {
        Platform::MacOs => {
            let mut out = Vec::new();
            for (name, on) in mac_services(r)? {
                if on {
                    let s = mac_get(r, &name)?;
                    out.push(current(s.target, s.url, s.enabled));
                }
            }
            out
        }
        Platform::Windows => {
            let url = win_query(r);
            let active = url.is_some();
            vec![current("user".into(), url, active)]
        }
        Platform::Linux => {
            let s = gnome_get(r)?;
            vec![current("GNOME".into(), s.url, s.target == "auto")]
        }
    })
}

/// Switch off every automatic proxy setting that uses a parda PAC, without
/// saved state: for `parda intercept off` when intercept-state.json is
/// missing or damaged but the system still sends AI sites to parda. macOS:
/// auto-proxy off for that service; Windows: AutoConfigURL removed; GNOME:
/// mode `none`. Other settings are never touched. `restored` lists what was
/// switched off, `failed` what could not be.
pub fn switch_off_parda(
    r: &mut dyn Runner,
    platform: Platform,
    pac_url: &str,
) -> anyhow::Result<Restored> {
    let mut out = Restored::default();
    for c in inspect(r, platform, pac_url)?
        .into_iter()
        .filter(|c| c.parda)
    {
        let done = match platform {
            Platform::MacOs => r
                .run("networksetup", &["-setautoproxystate", &c.target, "off"])
                .map(drop),
            Platform::Windows => win_set(r, None),
            Platform::Linux => r
                .run(
                    "gsettings",
                    &["set", "org.gnome.system.proxy", "mode", "none"],
                )
                .map(drop),
        };
        match done {
            Ok(()) => out.restored.push(c.target),
            Err(e) => {
                tracing::warn!(target = %c.target, error = %e, "could not switch off parda's PAC");
                out.failed.push(c.target);
            }
        }
    }
    Ok(out)
}

/// Whether the current setting of `s.target` still points at parda.
fn still_ours(
    r: &mut dyn Runner,
    platform: Platform,
    s: &Saved,
    pac_url: &str,
) -> anyhow::Result<bool> {
    Ok(match platform {
        Platform::MacOs => {
            // Ours only while the service still uses parda's PAC: a user who
            // switched auto-proxy off meanwhile keeps it off.
            let now = mac_get(r, &s.target)?;
            now.enabled && now.url.as_deref().is_some_and(|u| is_parda_pac(u, pac_url))
        }
        Platform::Windows => win_query(r).is_some_and(|u| is_parda_pac(&u, pac_url)),
        Platform::Linux => {
            let now = gnome_get(r)?;
            now.target == "auto" && now.url.as_deref().is_some_and(|u| is_parda_pac(u, pac_url))
        }
    })
}

/// Put back what [`enable`] saved. Every entry is attempted. A setting that
/// no longer points at parda (changed by someone else meanwhile) is left as
/// it is; failures stay in the state file (and are reported) so a later call
/// can finish the job. Returns `None` when nothing was saved.
pub fn disable(r: &mut dyn Runner, paths: &Paths) -> anyhow::Result<Option<Restored>> {
    let Some(mut state) = load_state(paths)? else {
        return Ok(None);
    };
    let mut out = Restored::default();
    let listed: Option<Vec<String>> = match state.platform {
        Platform::MacOs => Some(mac_services(r)?.into_iter().map(|(n, _)| n).collect()),
        _ => None,
    };
    let mut remaining = Vec::new();
    for s in std::mem::take(&mut state.saved) {
        if let Some(names) = &listed
            && !names.contains(&s.target)
        {
            out.gone.push(s.target.clone());
            continue;
        }
        let result = still_ours(r, state.platform, &s, &state.pac_url).and_then(|ours| {
            if !ours {
                return Ok(false);
            }
            match state.platform {
                Platform::MacOs => mac_restore(r, &s)?,
                Platform::Windows => win_set(r, s.url.as_deref().filter(|_| s.enabled))?,
                Platform::Linux => gnome_set(r, &s.target, s.url.as_deref().unwrap_or(""))?,
            }
            Ok(true)
        });
        match result {
            Ok(true) => out.restored.push(s.target.clone()),
            Ok(false) => out.kept.push(s.target.clone()),
            Err(e) => {
                tracing::warn!(target = %s.target, error = %e, "could not restore proxy setting");
                out.failed.push(s.target.clone());
                remaining.push(s);
            }
        }
    }
    if remaining.is_empty() {
        std::fs::remove_file(state_path(paths))?;
    } else {
        state.saved = remaining;
        save_state(paths, &state)?;
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A pretend OS that remembers settings, so tests observe real effects.
    #[derive(Default)]
    struct Os {
        /// macOS: service → (url, enabled, service enabled)
        mac: BTreeMap<String, (Option<String>, bool, bool)>,
        /// Windows AutoConfigURL
        win: Option<String>,
        /// GNOME (mode, autoconfig-url)
        gnome: (String, String),
        /// Command prefixes that fail.
        failing: Vec<String>,
        calls: Vec<String>,
        refreshed: usize,
    }

    impl Runner for Os {
        fn run(&mut self, program: &str, args: &[&str]) -> anyhow::Result<String> {
            let line = format!("{program} {}", args.join(" "));
            self.calls.push(line.clone());
            if self.failing.iter().any(|f| line.starts_with(f.as_str())) {
                bail!("failed: {line}");
            }
            Ok(match (program, args) {
                ("networksetup", ["-listallnetworkservices"]) => {
                    let mut out =
                        "An asterisk (*) denotes that a network service is disabled.\n".to_string();
                    for (name, (_, _, svc_on)) in &self.mac {
                        out.push_str(&format!("{}{name}\n", if *svc_on { "" } else { "*" }));
                    }
                    out
                }
                ("networksetup", ["-getautoproxyurl", svc]) => {
                    let Some((url, on, _)) = self.mac.get(*svc) else {
                        bail!("no such service")
                    };
                    format!(
                        "URL: {}\nEnabled: {}\n",
                        url.as_deref().unwrap_or("(null)"),
                        if *on { "Yes" } else { "No" }
                    )
                }
                ("networksetup", ["-setautoproxyurl", svc, url]) => {
                    let Some(e) = self.mac.get_mut(*svc) else {
                        bail!("no such service")
                    };
                    e.0 = Some(url.to_string());
                    e.1 = true;
                    String::new()
                }
                ("networksetup", ["-setautoproxystate", svc, state]) => {
                    let Some(e) = self.mac.get_mut(*svc) else {
                        bail!("no such service")
                    };
                    e.1 = *state == "on";
                    String::new()
                }
                ("reg", ["query", ..]) => match &self.win {
                    Some(u) => {
                        format!("\r\n{WIN_KEY}\r\n    AutoConfigURL    REG_SZ    {u}\r\n\r\n")
                    }
                    None => bail!("value not found"),
                },
                ("reg", ["add", .., url, "/f"]) => {
                    self.win = Some(url.to_string());
                    String::new()
                }
                ("reg", ["delete", ..]) => {
                    self.win = None;
                    String::new()
                }
                ("gsettings", ["get", _, "mode"]) => format!("'{}'\n", self.gnome.0),
                ("gsettings", ["get", _, "autoconfig-url"]) => format!("'{}'\n", self.gnome.1),
                ("gsettings", ["set", _, "mode", m]) => {
                    self.gnome.0 = m.to_string();
                    String::new()
                }
                ("gsettings", ["set", _, "autoconfig-url", u]) => {
                    self.gnome.1 = u.to_string();
                    String::new()
                }
                _ => String::new(),
            })
        }

        fn refresh_proxy_settings(&mut self) {
            self.refreshed += 1;
        }
    }

    fn paths() -> (tempfile::TempDir, Paths) {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path().to_path_buf());
        (d, p)
    }

    const PAC: &str = "http://127.0.0.1:8788/parda.pac";

    fn mac() -> Os {
        let mut os = Os::default();
        os.mac.insert("Wi-Fi".into(), (None, false, true));
        os.mac.insert("Bluetooth PAN".into(), (None, false, false));
        os.mac.insert(
            "Thunderbolt Bridge".into(),
            (Some("http://corp/proxy.pac".into()), true, true),
        );
        os.mac.insert(
            "iPhone USB".into(),
            (Some("http://old/proxy.pac".into()), false, true),
        );
        os
    }

    fn snapshot(os: &Os) -> BTreeMap<String, (Option<String>, bool, bool)> {
        os.mac.clone()
    }

    #[test]
    fn macos_on_then_off_restores_every_setting_exactly() {
        let (_d, p) = paths();
        let mut os = mac();
        let before = snapshot(&os);
        enable(&mut os, &p, Platform::MacOs, PAC).unwrap();
        for svc in ["Wi-Fi", "Thunderbolt Bridge", "iPhone USB"] {
            assert_eq!(os.mac[svc].0.as_deref(), Some(PAC), "{svc}");
            assert!(os.mac[svc].1, "{svc}");
        }
        assert_eq!(
            os.mac["Bluetooth PAN"].0, None,
            "disabled services are left alone"
        );
        let r = disable(&mut os, &p).unwrap().unwrap();
        assert_eq!(r.restored.len(), 3);
        // URL fields cannot be cleared through networksetup; the switch is what matters.
        let after = snapshot(&os);
        assert_eq!(after["Thunderbolt Bridge"], before["Thunderbolt Bridge"]);
        assert_eq!(after["iPhone USB"], before["iPhone USB"]);
        assert!(!after["Wi-Fi"].1, "Wi-Fi auto-proxy is off again");
        assert!(load_state(&p).unwrap().is_none());
        assert!(
            disable(&mut os, &p).unwrap().is_none(),
            "second off is a no-op"
        );
    }

    #[test]
    fn a_service_deleted_meanwhile_is_reported_gone_and_does_not_block_off() {
        let (_d, p) = paths();
        let mut os = mac();
        enable(&mut os, &p, Platform::MacOs, PAC).unwrap();
        os.mac.remove("iPhone USB");
        let r = disable(&mut os, &p).unwrap().unwrap();
        assert_eq!(r.gone, ["iPhone USB"]);
        assert_eq!(r.restored.len(), 2);
        assert!(load_state(&p).unwrap().is_none());
    }

    #[test]
    fn a_service_disabled_meanwhile_is_still_restored() {
        let (_d, p) = paths();
        let mut os = mac();
        enable(&mut os, &p, Platform::MacOs, PAC).unwrap();
        os.mac.get_mut("Thunderbolt Bridge").unwrap().2 = false; // user turned the service off
        let r = disable(&mut os, &p).unwrap().unwrap();
        assert!(r.restored.contains(&"Thunderbolt Bridge".to_string()));
        assert_eq!(
            os.mac["Thunderbolt Bridge"].0.as_deref(),
            Some("http://corp/proxy.pac")
        );
    }

    #[test]
    fn a_setting_changed_by_the_user_meanwhile_is_left_alone() {
        let (_d, p) = paths();
        let mut os = mac();
        enable(&mut os, &p, Platform::MacOs, PAC).unwrap();
        os.mac.get_mut("Wi-Fi").unwrap().0 = Some("http://my-new/proxy.pac".into());
        let r = disable(&mut os, &p).unwrap().unwrap();
        assert_eq!(r.kept, ["Wi-Fi"]);
        assert_eq!(
            os.mac["Wi-Fi"].0.as_deref(),
            Some("http://my-new/proxy.pac")
        );
    }

    #[test]
    fn a_failed_restore_is_kept_for_retry_and_the_rest_still_restored() {
        let (_d, p) = paths();
        let mut os = mac();
        enable(&mut os, &p, Platform::MacOs, PAC).unwrap();
        os.failing
            .push("networksetup -setautoproxyurl Thunderbolt".into());
        let r = disable(&mut os, &p).unwrap().unwrap();
        assert_eq!(r.failed, ["Thunderbolt Bridge"]);
        assert_eq!(load_state(&p).unwrap().unwrap().saved.len(), 1);
        os.failing.clear();
        let r = disable(&mut os, &p).unwrap().unwrap();
        assert_eq!(r.restored, ["Thunderbolt Bridge"]);
        assert!(load_state(&p).unwrap().is_none());
    }

    #[test]
    fn a_failed_on_rolls_back_what_it_already_changed() {
        let (_d, p) = paths();
        let mut os = mac();
        let before = snapshot(&os);
        os.failing
            .push("networksetup -setautoproxyurl iPhone".into());
        let e = enable(&mut os, &p, Platform::MacOs, PAC).unwrap_err();
        assert!(
            format!("{e:#}").contains("every change was undone"),
            "{e:#}"
        );
        assert_eq!(
            snapshot(&os)["Thunderbolt Bridge"],
            before["Thunderbolt Bridge"]
        );
        assert!(!os.mac["Wi-Fi"].1, "Wi-Fi switched back off");
        assert!(load_state(&p).unwrap().is_none());
    }

    #[test]
    fn a_rollback_that_fails_names_what_is_left() {
        let (_d, p) = paths();
        let mut os = mac();
        // Applying fails at iPhone USB; putting Thunderbolt back fails too.
        os.failing
            .push("networksetup -setautoproxyurl iPhone USB http://127".into());
        os.failing
            .push("networksetup -setautoproxyurl Thunderbolt Bridge http://corp".into());
        let e = format!(
            "{:#}",
            enable(&mut os, &p, Platform::MacOs, PAC).unwrap_err()
        );
        assert!(
            e.contains("Thunderbolt Bridge") && e.contains("parda intercept off"),
            "{e}"
        );
        assert!(load_state(&p).unwrap().is_some(), "kept for a later off");
    }

    #[test]
    fn auto_proxy_switched_off_by_the_user_stays_off() {
        let (_d, p) = paths();
        let mut os = mac();
        enable(&mut os, &p, Platform::MacOs, PAC).unwrap();
        os.mac.get_mut("Thunderbolt Bridge").unwrap().1 = false;
        let r = disable(&mut os, &p).unwrap().unwrap();
        assert!(r.kept.contains(&"Thunderbolt Bridge".to_string()));
        assert!(!os.mac["Thunderbolt Bridge"].1);
    }

    #[test]
    fn on_again_keeps_originals_adds_new_services_and_never_saves_a_parda_pac() {
        let (_d, p) = paths();
        let mut os = mac();
        enable(&mut os, &p, Platform::MacOs, PAC).unwrap();
        // A VPN appears that already carries a parda PAC from an older run on another port.
        os.mac.insert(
            "ProtonVPN".into(),
            (Some("http://127.0.0.1:9999/parda.pac".into()), true, true),
        );
        let st = enable(&mut os, &p, Platform::MacOs, PAC).unwrap();
        let get = |t: &str| st.saved.iter().find(|s| s.target == t).unwrap().clone();
        assert_eq!(get("Wi-Fi").url, None, "original kept, not parda's");
        assert_eq!(
            get("ProtonVPN").url,
            None,
            "an old parda PAC is not an original"
        );
    }

    #[test]
    fn on_again_after_an_outside_change_saves_that_change_for_off() {
        let (_d, p) = paths();
        let mut os = mac();
        enable(&mut os, &p, Platform::MacOs, PAC).unwrap();
        // A VPN client points Thunderbolt Bridge at its own PAC; the user
        // switches iPhone USB's auto-proxy off; Wi-Fi stays parda's.
        os.mac.get_mut("Thunderbolt Bridge").unwrap().0 = Some("http://vpn/new.pac".into());
        os.mac.get_mut("iPhone USB").unwrap().1 = false;
        enable(&mut os, &p, Platform::MacOs, PAC).unwrap();
        assert_eq!(os.mac["Thunderbolt Bridge"].0.as_deref(), Some(PAC));
        let r = disable(&mut os, &p).unwrap().unwrap();
        assert_eq!(r.restored.len(), 3, "{r:?}");
        assert_eq!(
            os.mac["Thunderbolt Bridge"],
            (Some("http://vpn/new.pac".into()), true, true),
            "the VPN's PAC is back, not the one from before the first on"
        );
        assert!(!os.mac["iPhone USB"].1, "switched off as the user left it");
        assert!(!os.mac["Wi-Fi"].1, "Wi-Fi's original (no proxy) kept");
    }

    #[test]
    fn on_again_after_an_outside_change_on_windows_and_gnome() {
        let (_d, p) = paths();
        let mut os = Os {
            win: Some("http://corp/w.pac".into()),
            ..Default::default()
        };
        enable(&mut os, &p, Platform::Windows, PAC).unwrap();
        os.win = Some("http://vpn/w.pac".into());
        enable(&mut os, &p, Platform::Windows, PAC).unwrap();
        disable(&mut os, &p).unwrap().unwrap();
        assert_eq!(os.win.as_deref(), Some("http://vpn/w.pac"));

        let (_d, p) = paths();
        let mut os = Os {
            gnome: ("none".into(), String::new()),
            ..Default::default()
        };
        enable(&mut os, &p, Platform::Linux, PAC).unwrap();
        os.gnome = ("manual".into(), String::new());
        enable(&mut os, &p, Platform::Linux, PAC).unwrap();
        disable(&mut os, &p).unwrap().unwrap();
        assert_eq!(os.gnome.0, "manual");

        // Still parda's on the second on: the original stays.
        let (_d, p) = paths();
        let mut os = Os {
            win: Some("http://corp/w.pac".into()),
            ..Default::default()
        };
        enable(&mut os, &p, Platform::Windows, PAC).unwrap();
        enable(&mut os, &p, Platform::Windows, PAC).unwrap();
        disable(&mut os, &p).unwrap().unwrap();
        assert_eq!(os.win.as_deref(), Some("http://corp/w.pac"));
    }

    #[test]
    fn no_enabled_service_is_an_error_and_changes_nothing() {
        let (_d, p) = paths();
        let mut os = Os::default();
        os.mac.insert("Wi-Fi".into(), (None, false, false));
        assert!(enable(&mut os, &p, Platform::MacOs, PAC).is_err());
        assert!(load_state(&p).unwrap().is_none());
    }

    #[test]
    fn windows_round_trip_with_previous_url_and_refresh() {
        let (_d, p) = paths();
        let mut os = Os {
            win: Some("http://corp/w.pac".into()),
            ..Default::default()
        };
        enable(&mut os, &p, Platform::Windows, PAC).unwrap();
        assert_eq!(os.win.as_deref(), Some(PAC));
        assert_eq!(os.refreshed, 1);
        disable(&mut os, &p).unwrap().unwrap();
        assert_eq!(os.win.as_deref(), Some("http://corp/w.pac"));
        assert_eq!(os.refreshed, 2);
    }

    #[test]
    fn windows_removes_the_value_when_there_was_none() {
        let (_d, p) = paths();
        let mut os = Os::default();
        enable(&mut os, &p, Platform::Windows, PAC).unwrap();
        assert_eq!(os.win.as_deref(), Some(PAC));
        disable(&mut os, &p).unwrap().unwrap();
        assert_eq!(os.win, None);
    }

    #[test]
    fn gnome_restores_a_previous_manual_mode_and_url() {
        let (_d, p) = paths();
        let mut os = Os {
            gnome: ("manual".into(), "http://corp/g.pac".into()),
            ..Default::default()
        };
        enable(&mut os, &p, Platform::Linux, PAC).unwrap();
        assert_eq!(os.gnome, ("auto".to_string(), PAC.to_string()));
        disable(&mut os, &p).unwrap().unwrap();
        assert_eq!(
            os.gnome,
            ("manual".to_string(), "http://corp/g.pac".to_string())
        );
    }

    /// Calls that would change a setting.
    fn writes(os: &Os) -> Vec<&String> {
        os.calls
            .iter()
            .filter(|c| {
                c.starts_with("networksetup -set")
                    || c.starts_with("reg add")
                    || c.starts_with("reg delete")
                    || c.starts_with("gsettings set")
            })
            .collect()
    }

    #[test]
    fn inspect_reads_every_enabled_macos_service_without_changing_anything() {
        let (_d, p) = paths();
        let mut os = mac();
        enable(&mut os, &p, Platform::MacOs, PAC).unwrap();
        os.mac.get_mut("iPhone USB").unwrap().1 = false; // user switched it off
        os.calls.clear();
        let before = snapshot(&os);
        let now = inspect(&mut os, Platform::MacOs, PAC).unwrap();
        assert!(writes(&os).is_empty(), "{:?}", os.calls);
        assert_eq!(snapshot(&os), before);
        let get = |t: &str| now.iter().find(|c| c.target == t).cloned();
        assert!(
            get("Bluetooth PAN").is_none(),
            "disabled services are skipped"
        );
        let wifi = get("Wi-Fi").unwrap();
        assert!(wifi.active && wifi.parda, "{wifi:?}");
        assert_eq!(wifi.url.as_deref(), Some(PAC));
        let usb = get("iPhone USB").unwrap();
        assert!(!usb.active && !usb.parda, "{usb:?}");
    }

    #[test]
    fn inspect_recognises_an_old_port_and_other_pacs_on_windows_and_gnome() {
        let mut os = Os {
            win: Some("http://127.0.0.1:9999/parda.pac".into()),
            gnome: ("manual".into(), PAC.into()),
            ..Default::default()
        };
        let w = inspect(&mut os, Platform::Windows, PAC).unwrap();
        assert_eq!(w.len(), 1);
        assert!(w[0].active && w[0].parda, "{w:?}");
        let g = inspect(&mut os, Platform::Linux, PAC).unwrap();
        assert!(
            !g[0].active && !g[0].parda,
            "manual mode: the PAC is unused"
        );
        os.gnome.0 = "auto".into();
        assert!(inspect(&mut os, Platform::Linux, PAC).unwrap()[0].parda);
        os.win = None;
        let w = inspect(&mut os, Platform::Windows, PAC).unwrap();
        assert!(!w[0].active && w[0].url.is_none());
        assert!(writes(&os).is_empty(), "{:?}", os.calls);
        assert_eq!(os.refreshed, 0);
    }

    #[test]
    fn switch_off_parda_turns_off_every_parda_pac_without_saved_state() {
        let mut os = mac();
        os.mac.get_mut("Wi-Fi").unwrap().0 = Some(PAC.into());
        os.mac.get_mut("Wi-Fi").unwrap().1 = true;
        // An older run on another port.
        os.mac.get_mut("iPhone USB").unwrap().0 = Some("http://127.0.0.1:9999/parda.pac".into());
        os.mac.get_mut("iPhone USB").unwrap().1 = true;
        let before = snapshot(&os);
        let r = switch_off_parda(&mut os, Platform::MacOs, PAC).unwrap();
        assert_eq!(r.restored, ["Wi-Fi", "iPhone USB"]);
        assert!(r.failed.is_empty());
        assert!(!os.mac["Wi-Fi"].1 && !os.mac["iPhone USB"].1);
        assert_eq!(
            os.mac["Thunderbolt Bridge"], before["Thunderbolt Bridge"],
            "someone else's PAC is left alone"
        );
        // Nothing of parda's left: nothing to do.
        os.calls.clear();
        let r = switch_off_parda(&mut os, Platform::MacOs, PAC).unwrap();
        assert_eq!(r, Restored::default());
        assert!(writes(&os).is_empty(), "{:?}", os.calls);

        os.mac.get_mut("Wi-Fi").unwrap().1 = true;
        os.failing
            .push("networksetup -setautoproxystate Wi-Fi".into());
        let r = switch_off_parda(&mut os, Platform::MacOs, PAC).unwrap();
        assert_eq!(r.failed, ["Wi-Fi"]);

        let mut os = Os {
            win: Some(PAC.into()),
            gnome: ("auto".into(), PAC.into()),
            ..Default::default()
        };
        assert_eq!(
            switch_off_parda(&mut os, Platform::Windows, PAC)
                .unwrap()
                .restored,
            ["user"]
        );
        assert_eq!(os.win, None);
        assert_eq!(
            switch_off_parda(&mut os, Platform::Linux, PAC)
                .unwrap()
                .restored,
            ["GNOME"]
        );
        assert_eq!(os.gnome.0, "none");
        // Not parda's: left alone.
        let mut os = Os {
            win: Some("http://corp/w.pac".into()),
            gnome: ("auto".into(), "http://corp/g.pac".into()),
            ..Default::default()
        };
        assert!(
            switch_off_parda(&mut os, Platform::Windows, PAC)
                .unwrap()
                .restored
                .is_empty()
        );
        assert!(
            switch_off_parda(&mut os, Platform::Linux, PAC)
                .unwrap()
                .restored
                .is_empty()
        );
        assert!(writes(&os).is_empty(), "{:?}", os.calls);
    }

    #[test]
    fn a_pac_points_at_the_listener_only_with_its_port_and_address() {
        let at = |u: &str, a: &str| pac_points_at(u, a.parse().unwrap());
        assert!(at(PAC, "127.0.0.1:8788"));
        assert!(!at(PAC, "127.0.0.1:9999"), "another port");
        assert!(at("http://localhost:8788/parda.pac", "127.0.0.1:8788"));
        assert!(at("http://localhost:8788/parda.pac", "[::1]:8788"));
        assert!(at("http://[::1]:8788/parda.pac", "[::1]:8788"));
        assert!(!at("http://[::1]:8788/parda.pac", "127.0.0.1:8788"));
        assert!(!at("http://127.0.0.1/parda.pac", "127.0.0.1:80"), "no port");
        assert!(!at("http://corp:8788/parda.pac", "127.0.0.1:8788"));
        assert!(!at("http://127.0.0.1:8788/other.pac", "127.0.0.1:8788"));
    }

    #[test]
    fn parda_pac_addresses_are_recognised() {
        assert!(is_parda_pac(PAC, PAC));
        assert!(is_parda_pac("http://localhost:9000/parda.pac", PAC));
        assert!(is_parda_pac("http://[::1]:8788/parda.pac", PAC));
        assert!(!is_parda_pac("http://corp/parda.pac", PAC));
        assert!(!is_parda_pac("http://127.0.0.1:8788/other.pac", PAC));
    }
}
