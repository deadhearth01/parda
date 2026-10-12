//! Start-at-login service: a LaunchAgent on macOS, a systemd user unit on
//! Linux, a logon task on Windows. Each runs `parda daemon`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;

use crate::paths::Paths;

pub const LAUNCHD_LABEL: &str = "dev.parda.daemon";
pub const SYSTEMD_UNIT: &str = "parda.service";
pub const WINDOWS_TASK: &str = "parda";

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn render_launchd(exe: &Path, paths: &Paths) -> String {
    let exe = xml_escape(&exe.display().to_string());
    let log = |name: &str| xml_escape(&paths.log_dir.join(name).display().to_string());
    let env = match &paths.home {
        Some(home) => format!(
            "    <key>EnvironmentVariables</key>\n    <dict>\n        <key>PARDA_HOME</key>\n        <string>{}</string>\n    </dict>\n",
            xml_escape(&home.display().to_string())
        ),
        None => String::new(),
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>StandardOutPath</key>
    <string>{out}</string>
    <key>StandardErrorPath</key>
    <string>{err}</string>
{env}</dict>
</plist>
"#,
        out = log("launchd.out.log"),
        err = log("launchd.err.log"),
    )
}

pub fn render_systemd(exe: &Path, paths: &Paths) -> String {
    let env = match &paths.home {
        Some(home) => format!("Environment=\"PARDA_HOME={}\"\n", home.display()),
        None => String::new(),
    };
    format!(
        "[Unit]\n\
         Description=parda - local PII filter for AI apps\n\
         After=graphical-session.target\n\
         \n\
         [Service]\n\
         ExecStart=\"{}\" daemon\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         {env}\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exe.display()
    )
}

pub fn windows_task_args(exe: &Path) -> Vec<String> {
    [
        "/Create",
        "/F",
        "/TN",
        WINDOWS_TASK,
        "/SC",
        "ONLOGON",
        "/RL",
        "LIMITED",
        "/TR",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain(std::iter::once(format!("\"{}\" daemon", exe.display())))
    .collect()
}

fn home() -> anyhow::Result<PathBuf> {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .context("cannot determine the home directory")
}

fn run(cmd: &str, args: &[&str]) -> anyhow::Result<std::process::Output> {
    Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running {cmd}"))
}

fn launchd_plist() -> anyhow::Result<PathBuf> {
    Ok(home()?
        .join("Library/LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist")))
}

fn systemd_unit() -> anyhow::Result<PathBuf> {
    Ok(home()?.join(".config/systemd/user").join(SYSTEMD_UNIT))
}

fn gui_domain() -> anyhow::Result<String> {
    let out = run("id", &["-u"])?;
    Ok(format!(
        "gui/{}",
        String::from_utf8_lossy(&out.stdout).trim()
    ))
}

/// Install and start the service. Returns a human-readable summary.
pub fn install(exe: &Path, paths: &Paths) -> anyhow::Result<String> {
    if cfg!(target_os = "macos") {
        let plist = launchd_plist()?;
        std::fs::create_dir_all(plist.parent().unwrap_or(Path::new(".")))?;
        std::fs::write(&plist, render_launchd(exe, paths))?;
        let domain = gui_domain()?;
        let _ = run(
            "launchctl",
            &["bootout", &format!("{domain}/{LAUNCHD_LABEL}")],
        );
        let out = run(
            "launchctl",
            &["bootstrap", &domain, &plist.display().to_string()],
        )?;
        if !out.status.success() {
            anyhow::bail!(
                "launchctl bootstrap failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(format!("installed LaunchAgent {}", plist.display()))
    } else if cfg!(target_os = "linux") {
        let unit = systemd_unit()?;
        std::fs::create_dir_all(unit.parent().unwrap_or(Path::new(".")))?;
        std::fs::write(&unit, render_systemd(exe, paths))?;
        run("systemctl", &["--user", "daemon-reload"])?;
        let out = run("systemctl", &["--user", "enable", "--now", SYSTEMD_UNIT])?;
        if !out.status.success() {
            anyhow::bail!(
                "systemctl enable failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(format!("installed systemd user unit {}", unit.display()))
    } else if cfg!(target_os = "windows") {
        let args = windows_task_args(exe);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = run("schtasks", &refs)?;
        if !out.status.success() {
            anyhow::bail!(
                "schtasks failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let _ = run("schtasks", &["/Run", "/TN", WINDOWS_TASK]);
        Ok(format!("installed logon task `{WINDOWS_TASK}`"))
    } else {
        anyhow::bail!(
            "service install is not supported on this platform; run `parda daemon` yourself"
        )
    }
}

pub fn uninstall() -> anyhow::Result<String> {
    if cfg!(target_os = "macos") {
        let plist = launchd_plist()?;
        let domain = gui_domain()?;
        let _ = run(
            "launchctl",
            &["bootout", &format!("{domain}/{LAUNCHD_LABEL}")],
        );
        if plist.exists() {
            std::fs::remove_file(&plist)?;
        }
        Ok("removed the LaunchAgent".into())
    } else if cfg!(target_os = "linux") {
        let _ = run("systemctl", &["--user", "disable", "--now", SYSTEMD_UNIT]);
        let unit = systemd_unit()?;
        if unit.exists() {
            std::fs::remove_file(&unit)?;
        }
        let _ = run("systemctl", &["--user", "daemon-reload"]);
        Ok("removed the systemd user unit".into())
    } else if cfg!(target_os = "windows") {
        let _ = run("schtasks", &["/End", "/TN", WINDOWS_TASK]);
        let out = run("schtasks", &["/Delete", "/F", "/TN", WINDOWS_TASK])?;
        if !out.status.success() {
            anyhow::bail!(
                "schtasks /Delete failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok("removed the logon task".into())
    } else {
        anyhow::bail!("service install is not supported on this platform")
    }
}

pub fn status() -> anyhow::Result<String> {
    if cfg!(target_os = "macos") {
        let plist = launchd_plist()?;
        if !plist.exists() {
            return Ok("not installed".into());
        }
        let out = run(
            "launchctl",
            &["print", &format!("{}/{LAUNCHD_LABEL}", gui_domain()?)],
        )?;
        Ok(if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let state = text
                .lines()
                .find_map(|l| l.trim().strip_prefix("state = "))
                .unwrap_or("loaded");
            format!("installed ({state})")
        } else {
            "installed (not loaded)".into()
        })
    } else if cfg!(target_os = "linux") {
        if !systemd_unit()?.exists() {
            return Ok("not installed".into());
        }
        let out = run("systemctl", &["--user", "is-active", SYSTEMD_UNIT])?;
        Ok(format!(
            "installed ({})",
            String::from_utf8_lossy(&out.stdout).trim()
        ))
    } else if cfg!(target_os = "windows") {
        let out = run("schtasks", &["/Query", "/TN", WINDOWS_TASK])?;
        Ok(if out.status.success() {
            "installed".into()
        } else {
            "not installed".into()
        })
    } else {
        Ok("unsupported platform".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launchd_plist_shape() {
        let p = Paths::under(PathBuf::from("/tmp/parda home"));
        let s = render_launchd(Path::new("/usr/local/bin/parda"), &p);
        assert!(s.contains("<string>daemon</string>"));
        assert!(s.contains("<string>/usr/local/bin/parda</string>"));
        assert!(s.contains("RunAtLoad") && s.contains("KeepAlive"));
        assert!(s.contains("<key>PARDA_HOME</key>") && s.contains("/tmp/parda home"));
        let no_home = Paths {
            home: None,
            ..p.clone()
        };
        assert!(!render_launchd(Path::new("/x/parda"), &no_home).contains("PARDA_HOME"));
    }

    #[test]
    fn systemd_unit_shape() {
        let p = Paths::under(PathBuf::from("/srv/parda"));
        let s = render_systemd(Path::new("/opt/parda/bin/parda"), &p);
        assert!(s.contains("ExecStart=\"/opt/parda/bin/parda\" daemon"));
        assert!(s.contains("Restart=on-failure"));
        assert!(s.contains("PARDA_HOME=/srv/parda"));
        assert!(s.contains("WantedBy=default.target"));
    }

    #[test]
    fn windows_args() {
        let a = windows_task_args(Path::new(r"C:\Program Files\parda\parda.exe"));
        assert_eq!(
            a.last().unwrap(),
            r#""C:\Program Files\parda\parda.exe" daemon"#
        );
        assert!(a.contains(&"ONLOGON".to_string()));
    }
}
