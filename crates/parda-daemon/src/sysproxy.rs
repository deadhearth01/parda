//! Pointing the operating system's automatic proxy configuration (PAC) at
//! parda, and putting the previous setting back.
//!
//! The previous settings are saved to `intercept-state.json` *before*
//! anything is changed and that file is only removed after a successful
//! restore, so `parda intercept off` works even after a crash. All commands go
//! through [`Runner`] so the logic is tested without touching the real system.

use std::path::PathBuf;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use crate::paths::{Paths, write_private};

const STATE_FILE: &str = "intercept-state.json";
const WIN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    MacOs,
    Windows,
    Linux,
}

impl Platform {
    pub fn current() -> Platform {
        if cfg!(target_os = "macos") {
            Platform::MacOs
        } else if cfg!(windows) {
            Platform::Windows
        } else {
            Platform::Linux
        }
    }
}

/// Runs a program and returns its standard output.
pub trait Runner {
    fn run(&mut self, program: &str, args: &[&str]) -> anyhow::Result<String>;
}

/// The real system.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> anyhow::Result<String> {
        let out = std::process::Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("running {program}"))?;
        if !out.status.success() {
            bail!(
                "{program} {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// One saved setting: a macOS network service, the Windows user setting, or
/// the GNOME proxy setting.
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

// ---------- macOS ----------

fn mac_services(r: &mut dyn Runner) -> anyhow::Result<Vec<String>> {
    let out = r.run("networksetup", &["-listallnetworkservices"])?;
    Ok(out
        .lines()
        .skip(1) // "An asterisk (*) denotes that a network service is disabled."
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
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

fn mac_apply(r: &mut dyn Runner, s: &Saved) -> anyhow::Result<()> {
    if let Some(url) = &s.url {
        r.run("networksetup", &["-setautoproxyurl", &s.target, url])?;
    }
    let state = if s.enabled { "on" } else { "off" };
    r.run("networksetup", &["-setautoproxystate", &s.target, state])?;
    Ok(())
}

// ---------- Windows ----------

fn win_get(r: &mut dyn Runner) -> Saved {
    // `reg query` fails when the value does not exist.
    let url = r
        .run("reg", &["query", WIN_KEY, "/v", "AutoConfigURL"])
        .ok()
        .and_then(|out| {
            out.lines()
                .find(|l| l.trim_start().starts_with("AutoConfigURL"))
                .and_then(|l| l.split("REG_SZ").nth(1))
                .map(|v| v.trim().to_string())
        })
        .filter(|v| !v.is_empty());
    Saved {
        target: "user".into(),
        enabled: url.is_some(),
        url,
    }
}

fn win_apply(r: &mut dyn Runner, s: &Saved) -> anyhow::Result<()> {
    match (&s.url, s.enabled) {
        (Some(url), true) => {
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
        _ => {
            // Absent before: remove ours (ignore "not found").
            let _ = r.run("reg", &["delete", WIN_KEY, "/v", "AutoConfigURL", "/f"]);
        }
    }
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
        target: mode, // previous mode (none / manual / auto)
        url: (!url.is_empty()).then_some(url),
        enabled: true,
    })
}

fn gnome_apply(r: &mut dyn Runner, s: &Saved) -> anyhow::Result<()> {
    let url = s.url.clone().unwrap_or_default();
    r.run(
        "gsettings",
        &["set", "org.gnome.system.proxy", "autoconfig-url", &url],
    )?;
    r.run(
        "gsettings",
        &["set", "org.gnome.system.proxy", "mode", &s.target],
    )?;
    Ok(())
}

// ---------- public API ----------

/// Point the system at `pac_url`. Saves the previous settings first (keeping
/// an existing state file, which holds the true originals after a crash).
pub fn enable(
    r: &mut dyn Runner,
    paths: &Paths,
    platform: Platform,
    pac_url: &str,
) -> anyhow::Result<State> {
    let state = match load_state(paths)? {
        Some(existing) => existing,
        None => {
            let saved = match platform {
                Platform::MacOs => {
                    let mut v = Vec::new();
                    for svc in mac_services(r)? {
                        v.push(mac_get(r, &svc)?);
                    }
                    v
                }
                Platform::Windows => vec![win_get(r)],
                Platform::Linux => vec![gnome_get(r)?],
            };
            let state = State {
                platform,
                pac_url: pac_url.to_string(),
                saved,
            };
            paths.ensure()?;
            write_private(&state_path(paths), &serde_json::to_string_pretty(&state)?)?;
            state
        }
    };
    for s in &state.saved {
        let ours = Saved {
            target: match platform {
                Platform::Linux => "auto".into(),
                _ => s.target.clone(),
            },
            url: Some(pac_url.to_string()),
            enabled: true,
        };
        match platform {
            Platform::MacOs => mac_apply(r, &ours)?,
            Platform::Windows => win_apply(r, &ours)?,
            Platform::Linux => gnome_apply(r, &ours)?,
        }
    }
    Ok(state)
}

/// Put back what [`enable`] saved. Returns false when nothing was saved.
pub fn disable(r: &mut dyn Runner, paths: &Paths) -> anyhow::Result<bool> {
    let Some(state) = load_state(paths)? else {
        return Ok(false);
    };
    for s in &state.saved {
        match state.platform {
            Platform::MacOs => {
                if s.url.is_none() {
                    // There was no URL before: switch auto-proxy off.
                    r.run("networksetup", &["-setautoproxystate", &s.target, "off"])?;
                } else {
                    mac_apply(r, s)?;
                }
            }
            Platform::Windows => win_apply(r, s)?,
            Platform::Linux => gnome_apply(r, s)?,
        }
    }
    std::fs::remove_file(state_path(paths))?;
    Ok(true)
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
    }

    fn paths() -> (tempfile::TempDir, Paths) {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path().to_path_buf());
        (d, p)
    }

    const PAC: &str = "http://127.0.0.1:8788/parda.pac";

    fn mac_fake() -> Fake {
        let mut f = Fake::default();
        f.replies.insert(
            "networksetup -listallnetworkservices".into(),
            "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nThunderbolt Bridge\n".into(),
        );
        f.replies.insert(
            "networksetup -getautoproxyurl Wi-Fi".into(),
            "URL: (null)\nEnabled: No\n".into(),
        );
        f.replies.insert(
            "networksetup -getautoproxyurl Thunderbolt Bridge".into(),
            "URL: http://corp/proxy.pac\nEnabled: Yes\n".into(),
        );
        f
    }

    #[test]
    fn macos_enable_saves_then_points_every_enabled_service_at_parda() {
        let (_d, p) = paths();
        let mut f = mac_fake();
        let st = enable(&mut f, &p, Platform::MacOs, PAC).unwrap();
        assert_eq!(st.saved.len(), 2, "disabled services are skipped");
        assert!(
            f.calls
                .contains(&format!("networksetup -setautoproxyurl Wi-Fi {PAC}"))
        );
        assert!(f.calls.contains(&format!(
            "networksetup -setautoproxyurl Thunderbolt Bridge {PAC}"
        )));
        assert!(
            f.calls
                .contains(&"networksetup -setautoproxystate Wi-Fi on".to_string())
        );
        assert!(load_state(&p).unwrap().is_some());
    }

    #[test]
    fn macos_disable_restores_exactly_and_removes_the_state() {
        let (_d, p) = paths();
        let mut f = mac_fake();
        enable(&mut f, &p, Platform::MacOs, PAC).unwrap();
        f.calls.clear();
        assert!(disable(&mut f, &p).unwrap());
        assert_eq!(
            f.calls,
            [
                "networksetup -setautoproxystate Wi-Fi off",
                "networksetup -setautoproxyurl Thunderbolt Bridge http://corp/proxy.pac",
                "networksetup -setautoproxystate Thunderbolt Bridge on",
            ]
        );
        assert!(load_state(&p).unwrap().is_none());
        assert!(!disable(&mut f, &p).unwrap(), "second off is a no-op");
    }

    #[test]
    fn enabling_twice_keeps_the_original_settings() {
        let (_d, p) = paths();
        let mut f = mac_fake();
        enable(&mut f, &p, Platform::MacOs, PAC).unwrap();
        // Now the system reports parda's PAC; a second `on` (e.g. after a crash)
        // must not save parda's URL as the "previous" setting.
        f.replies.insert(
            "networksetup -getautoproxyurl Wi-Fi".into(),
            format!("URL: {PAC}\nEnabled: Yes\n"),
        );
        let st = enable(&mut f, &p, Platform::MacOs, PAC).unwrap();
        let wifi = st.saved.iter().find(|s| s.target == "Wi-Fi").unwrap();
        assert_eq!(wifi.url, None);
        assert!(!wifi.enabled);
    }

    #[test]
    fn failed_change_keeps_the_state_for_a_later_off() {
        let (_d, p) = paths();
        let mut f = mac_fake();
        f.failing
            .push("networksetup -setautoproxyurl Thunderbolt".into());
        assert!(enable(&mut f, &p, Platform::MacOs, PAC).is_err());
        assert!(
            load_state(&p).unwrap().is_some(),
            "state saved before changing anything"
        );
        f.failing.clear();
        assert!(disable(&mut f, &p).unwrap());
    }

    #[test]
    fn windows_sets_and_removes_the_user_pac() {
        let (_d, p) = paths();
        let mut f = Fake::default();
        f.failing.push("reg query".into()); // no AutoConfigURL before
        enable(&mut f, &p, Platform::Windows, PAC).unwrap();
        assert!(
            f.calls
                .iter()
                .any(|c| c.starts_with("reg add") && c.contains(PAC))
        );
        f.calls.clear();
        disable(&mut f, &p).unwrap();
        assert!(
            f.calls
                .iter()
                .any(|c| c.starts_with("reg delete") && c.contains("AutoConfigURL"))
        );
    }

    #[test]
    fn gnome_switches_to_auto_and_back() {
        let (_d, p) = paths();
        let mut f = Fake::default();
        f.replies.insert(
            "gsettings get org.gnome.system.proxy mode".into(),
            "'none'\n".into(),
        );
        f.replies.insert(
            "gsettings get org.gnome.system.proxy autoconfig-url".into(),
            "''\n".into(),
        );
        enable(&mut f, &p, Platform::Linux, PAC).unwrap();
        assert!(
            f.calls
                .contains(&"gsettings set org.gnome.system.proxy mode auto".to_string())
        );
        f.calls.clear();
        disable(&mut f, &p).unwrap();
        assert_eq!(
            f.calls,
            [
                "gsettings set org.gnome.system.proxy autoconfig-url ",
                "gsettings set org.gnome.system.proxy mode none",
            ]
        );
    }
}
