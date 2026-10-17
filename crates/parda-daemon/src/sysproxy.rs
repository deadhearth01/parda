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

/// A setting that already points at parda is not an "original" setting.
fn forget_ours(mut s: Saved, pac_url: &str) -> Saved {
    if s.url.as_deref().is_some_and(|u| is_parda_pac(u, pac_url)) {
        s.url = None;
        s.enabled = false;
    }
    s
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
/// existing state file (from an earlier `on`, or a crash) keeps its originals,
/// and services enabled since then are added to it. If any change fails,
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
                if !state.saved.iter().any(|s| &s.target == svc) {
                    state.saved.push(forget_ours(mac_get(r, svc)?, pac_url));
                }
            }
            targets = services;
        }
        Platform::Windows => {
            if state.saved.is_empty() {
                state.saved.push(forget_ours(win_get(r), pac_url));
            }
        }
        Platform::Linux => {
            if state.saved.is_empty() {
                let mut s = gnome_get(r)?;
                if s.target == "auto" && s.url.as_deref().is_some_and(|u| is_parda_pac(u, pac_url))
                {
                    s.target = "none".into();
                    s.url = None;
                }
                state.saved.push(s);
            }
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
        assert!(!g[0].active && !g[0].parda, "manual mode: the PAC is unused");
        os.gnome.0 = "auto".into();
        assert!(inspect(&mut os, Platform::Linux, PAC).unwrap()[0].parda);
        os.win = None;
        let w = inspect(&mut os, Platform::Windows, PAC).unwrap();
        assert!(!w[0].active && w[0].url.is_none());
        assert!(writes(&os).is_empty(), "{:?}", os.calls);
        assert_eq!(os.refreshed, 0);
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
