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

/// A setting that already points at parda is not an "original" setting.
fn forget_ours(mut s: Saved, pac_url: &str) -> Saved {
    if s.url.as_deref() == Some(pac_url) {
        s.url = None;
        s.enabled = false;
    }
    s
}

// ---------- macOS ----------

fn mac_services(r: &mut dyn Runner) -> anyhow::Result<Vec<String>> {
    let out = r.run("networksetup", &["-listallnetworkservices"])?;
    let mut seen = std::collections::HashSet::new();
    Ok(out
        .lines()
        .skip(1) // "An asterisk (*) denotes that a network service is disabled."
        .map(|l| l.trim_matches(|c: char| c == '\r' || c == '\n'))
        .filter(|l| !l.trim().is_empty() && !l.starts_with('*'))
        .filter(|l| seen.insert(l.to_string())) // the same name twice addresses one service
        .map(str::to_string)
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
/// and services enabled since then are added to it.
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
    match platform {
        Platform::MacOs => {
            let services = mac_services(r)?;
            if services.is_empty() {
                bail!("no enabled network service found (networksetup -listallnetworkservices)");
            }
            for svc in services {
                if !state.saved.iter().any(|s| s.target == svc) {
                    state.saved.push(forget_ours(mac_get(r, &svc)?, pac_url));
                }
            }
        }
        Platform::Windows => {
            if state.saved.is_empty() {
                state.saved.push(forget_ours(win_get(r), pac_url));
            }
        }
        Platform::Linux => {
            if state.saved.is_empty() {
                let mut s = gnome_get(r)?;
                if s.target == "auto" && s.url.as_deref() == Some(pac_url) {
                    s.target = "none".into();
                    s.url = None;
                }
                state.saved.push(s);
            }
        }
    }
    save_state(paths, &state)?;
    match platform {
        Platform::MacOs => {
            for s in &state.saved {
                r.run("networksetup", &["-setautoproxyurl", &s.target, pac_url])?;
                r.run("networksetup", &["-setautoproxystate", &s.target, "on"])?;
            }
        }
        Platform::Windows => win_set(r, Some(pac_url))?,
        Platform::Linux => gnome_set(r, "auto", pac_url)?,
    }
    Ok(state)
}

/// Put back what [`enable`] saved. Every entry is attempted; failures stay in
/// the state file (and are reported) so a later call can finish the job.
/// Returns `None` when nothing was saved.
pub fn disable(r: &mut dyn Runner, paths: &Paths) -> anyhow::Result<Option<Restored>> {
    let Some(mut state) = load_state(paths)? else {
        return Ok(None);
    };
    let mut out = Restored::default();
    let current = match state.platform {
        Platform::MacOs => Some(mac_services(r)?),
        _ => None,
    };
    let mut remaining = Vec::new();
    for s in std::mem::take(&mut state.saved) {
        if let Some(services) = &current
            && !services.contains(&s.target)
        {
            out.gone.push(s.target.clone());
            continue;
        }
        let result = match state.platform {
            Platform::MacOs => mac_restore(r, &s),
            Platform::Windows => win_set(r, s.url.as_deref().filter(|_| s.enabled)),
            Platform::Linux => gnome_set(r, &s.target, s.url.as_deref().unwrap_or("")),
        };
        match result {
            Ok(()) => out.restored.push(s.target.clone()),
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
    use std::collections::HashMap;

    #[derive(Default)]
    struct Fake {
        replies: HashMap<String, String>,
        failing: Vec<String>,
        calls: Vec<String>,
        refreshed: usize,
    }

    impl Runner for Fake {
        fn run(&mut self, program: &str, args: &[&str]) -> anyhow::Result<String> {
            let line = format!("{program} {}", args.join(" "));
            self.calls.push(line.clone());
            if self.failing.iter().any(|f| line.starts_with(f)) {
                bail!("failed: {line}");
            }
            Ok(self.replies.get(&line).cloned().unwrap_or_default())
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
    const LIST: &str = "networksetup -listallnetworkservices";

    fn mac_fake() -> Fake {
        let mut f = Fake::default();
        f.replies.insert(
            LIST.into(),
            "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nThunderbolt Bridge\niPhone USB\n".into(),
        );
        f.replies.insert(
            "networksetup -getautoproxyurl Wi-Fi".into(),
            "URL: (null)\nEnabled: No\n".into(),
        );
        f.replies.insert(
            "networksetup -getautoproxyurl Thunderbolt Bridge".into(),
            "URL: http://corp/proxy.pac\nEnabled: Yes\n".into(),
        );
        f.replies.insert(
            "networksetup -getautoproxyurl iPhone USB".into(),
            "URL: http://old/proxy.pac\nEnabled: No\n".into(),
        );
        f
    }

    #[test]
    fn macos_enable_saves_then_points_every_enabled_service_at_parda() {
        let (_d, p) = paths();
        let mut f = mac_fake();
        let st = enable(&mut f, &p, Platform::MacOs, PAC).unwrap();
        assert_eq!(st.saved.len(), 3, "disabled services are skipped");
        for svc in ["Wi-Fi", "Thunderbolt Bridge", "iPhone USB"] {
            assert!(
                f.calls
                    .contains(&format!("networksetup -setautoproxyurl {svc} {PAC}"))
            );
            assert!(
                f.calls
                    .contains(&format!("networksetup -setautoproxystate {svc} on"))
            );
        }
        assert!(load_state(&p).unwrap().is_some());
    }

    #[test]
    fn macos_disable_restores_exactly_including_url_set_but_disabled() {
        let (_d, p) = paths();
        let mut f = mac_fake();
        enable(&mut f, &p, Platform::MacOs, PAC).unwrap();
        f.calls.clear();
        let r = disable(&mut f, &p).unwrap().unwrap();
        assert_eq!(r.restored.len(), 3);
        let changes: Vec<_> = f.calls.iter().filter(|c| c != &LIST).cloned().collect();
        assert_eq!(
            changes,
            [
                "networksetup -setautoproxystate Wi-Fi off",
                "networksetup -setautoproxyurl Thunderbolt Bridge http://corp/proxy.pac",
                "networksetup -setautoproxystate Thunderbolt Bridge on",
                "networksetup -setautoproxyurl iPhone USB http://old/proxy.pac",
                "networksetup -setautoproxystate iPhone USB off",
            ]
        );
        assert!(load_state(&p).unwrap().is_none());
        assert!(
            disable(&mut f, &p).unwrap().is_none(),
            "second off is a no-op"
        );
    }

    #[test]
    fn a_vanished_service_does_not_block_off() {
        let (_d, p) = paths();
        let mut f = mac_fake();
        enable(&mut f, &p, Platform::MacOs, PAC).unwrap();
        // The iPhone was unplugged before `off`.
        f.replies.insert(
            LIST.into(),
            "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nThunderbolt Bridge\n".into(),
        );
        let r = disable(&mut f, &p).unwrap().unwrap();
        assert_eq!(r.gone, ["iPhone USB"]);
        assert_eq!(r.restored.len(), 2);
        assert!(load_state(&p).unwrap().is_none());
    }

    #[test]
    fn a_failed_restore_is_kept_for_retry_and_the_rest_still_restored() {
        let (_d, p) = paths();
        let mut f = mac_fake();
        enable(&mut f, &p, Platform::MacOs, PAC).unwrap();
        f.failing
            .push("networksetup -setautoproxyurl Thunderbolt".into());
        let r = disable(&mut f, &p).unwrap().unwrap();
        assert_eq!(r.failed, ["Thunderbolt Bridge"]);
        assert_eq!(r.restored, ["Wi-Fi", "iPhone USB"]);
        let left = load_state(&p).unwrap().unwrap();
        assert_eq!(left.saved.len(), 1);
        f.failing.clear();
        let r = disable(&mut f, &p).unwrap().unwrap();
        assert_eq!(r.restored, ["Thunderbolt Bridge"]);
        assert!(load_state(&p).unwrap().is_none());
    }

    #[test]
    fn enabling_again_keeps_originals_adds_new_services_and_ignores_our_own_pac() {
        let (_d, p) = paths();
        let mut f = mac_fake();
        enable(&mut f, &p, Platform::MacOs, PAC).unwrap();
        // The system now reports parda's PAC; a VPN service appeared.
        f.replies.insert(
            "networksetup -getautoproxyurl Wi-Fi".into(),
            format!("URL: {PAC}\nEnabled: Yes\n"),
        );
        f.replies.insert(
            LIST.into(),
            "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nThunderbolt Bridge\niPhone USB\nProtonVPN\n".into(),
        );
        f.replies.insert(
            "networksetup -getautoproxyurl ProtonVPN".into(),
            format!("URL: {PAC}\nEnabled: Yes\n"),
        );
        let st = enable(&mut f, &p, Platform::MacOs, PAC).unwrap();
        let get = |t: &str| st.saved.iter().find(|s| s.target == t).unwrap().clone();
        assert_eq!(get("Wi-Fi").url, None);
        assert!(!get("Wi-Fi").enabled);
        assert_eq!(get("ProtonVPN").url, None, "our own PAC is not an original");
    }

    #[test]
    fn no_enabled_service_is_an_error_and_changes_nothing() {
        let (_d, p) = paths();
        let mut f = Fake::default();
        f.replies.insert(
            LIST.into(),
            "An asterisk (*) denotes that a network service is disabled.\n*Wi-Fi\n".into(),
        );
        assert!(enable(&mut f, &p, Platform::MacOs, PAC).is_err());
        assert!(load_state(&p).unwrap().is_none());
    }

    #[test]
    fn windows_parses_restores_previous_url_and_refreshes() {
        let (_d, p) = paths();
        let mut f = Fake::default();
        let q = format!("reg query {WIN_KEY} /v AutoConfigURL");
        f.replies.insert(
            q.clone(),
            format!("\r\n{WIN_KEY}\r\n    AutoConfigURL    REG_SZ    http://corp/w.pac\r\n\r\n"),
        );
        enable(&mut f, &p, Platform::Windows, PAC).unwrap();
        assert!(
            f.calls
                .iter()
                .any(|c| c.starts_with("reg add") && c.contains(PAC))
        );
        assert_eq!(f.refreshed, 1);
        f.calls.clear();
        disable(&mut f, &p).unwrap().unwrap();
        assert!(
            f.calls
                .iter()
                .any(|c| c.starts_with("reg add") && c.contains("http://corp/w.pac"))
        );
        assert_eq!(f.refreshed, 2);
    }

    #[test]
    fn windows_removes_the_value_when_there_was_none() {
        let (_d, p) = paths();
        let mut f = Fake::default();
        f.failing.push("reg query".into()); // no AutoConfigURL before
        enable(&mut f, &p, Platform::Windows, PAC).unwrap();
        // Now the value exists (ours).
        f.failing.clear();
        f.replies.insert(
            format!("reg query {WIN_KEY} /v AutoConfigURL"),
            format!("    AutoConfigURL    REG_SZ    {PAC}\r\n"),
        );
        f.calls.clear();
        disable(&mut f, &p).unwrap().unwrap();
        assert!(f.calls.iter().any(|c| c.starts_with("reg delete")));
    }

    #[test]
    fn gnome_restores_a_previous_manual_mode_and_url() {
        let (_d, p) = paths();
        let mut f = Fake::default();
        f.replies.insert(
            "gsettings get org.gnome.system.proxy mode".into(),
            "'manual'\n".into(),
        );
        f.replies.insert(
            "gsettings get org.gnome.system.proxy autoconfig-url".into(),
            "'http://corp/g.pac'\n".into(),
        );
        enable(&mut f, &p, Platform::Linux, PAC).unwrap();
        assert!(
            f.calls
                .contains(&"gsettings set org.gnome.system.proxy mode auto".to_string())
        );
        f.calls.clear();
        disable(&mut f, &p).unwrap().unwrap();
        assert_eq!(
            f.calls,
            [
                "gsettings set org.gnome.system.proxy autoconfig-url http://corp/g.pac",
                "gsettings set org.gnome.system.proxy mode manual",
            ]
        );
    }
}
