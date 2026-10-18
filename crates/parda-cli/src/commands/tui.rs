//! `parda` / `parda tui`: the dashboard, and how its offline screen starts
//! the daemon.

use std::fs::OpenOptions;
use std::process::{Command, Stdio};

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use parda_daemon::Paths;
use parda_daemon::service::{self, Installed};

pub fn run(dump: bool) -> anyhow::Result<()> {
    let paths = super::paths()?;
    if dump {
        print!("{}", parda_tui::dump(&paths.runtime_dir, 110, 30)?);
        return Ok(());
    }
    parda_tui::run(&paths.runtime_dir, Some(starter(&paths)))
}

/// How the offline screen's start key starts the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Plan {
    /// The installed login service runs this same PARDA_HOME.
    Service,
    /// `parda daemon` in the background. `other`: a login service exists
    /// but for another home (`Some(None)`: one without PARDA_HOME).
    Spawn { other: Option<Option<PathBuf>> },
}

fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p)
        .or_else(|_| std::path::absolute(p))
        .unwrap_or_else(|_| p.to_path_buf())
}

fn same_home(a: Option<&Path>, b: Option<&Path>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => canonical(a) == canonical(b),
        _ => false,
    }
}

/// Use the service only when it runs the same PARDA_HOME as this shell.
fn plan(service: Option<&Installed>, home: Option<&Path>) -> Plan {
    match service {
        Some(s) if same_home(s.home.as_deref(), home) => Plan::Service,
        Some(s) => Plan::Spawn {
            other: Some(s.home.clone()),
        },
        None => Plan::Spawn { other: None },
    }
}

fn home_label(home: Option<&Path>) -> String {
    match home {
        Some(h) => format!("PARDA_HOME {}", h.display()),
        None => "the default folders (no PARDA_HOME)".into(),
    }
}

/// The offline screen's line under the start key.
fn hint(plan: &Plan, home: Option<&Path>) -> String {
    match plan {
        Plan::Service => format!(
            "starts the login service (`parda service install`) for {}",
            home_label(home)
        ),
        Plan::Spawn { other: None } => {
            format!(
                "runs `parda daemon` in the background for {}",
                home_label(home)
            )
        }
        Plan::Spawn { other: Some(o) } => format!(
            "runs `parda daemon` in the background for {} — the login service is for {}",
            home_label(home),
            home_label(o.as_deref())
        ),
    }
}

/// Works out (lazily, on the TUI's worker thread) and runs the start plan.
struct Launcher {
    paths: Paths,
}

impl Launcher {
    fn plan(&self) -> Plan {
        let installed = service::installed().ok().flatten();
        plan(installed.as_ref(), self.paths.home.as_deref())
    }

    fn describe(&mut self) -> String {
        hint(&self.plan(), self.paths.home.as_deref())
    }

    fn start(&mut self) -> anyhow::Result<String> {
        match self.plan() {
            Plan::Service => start_service(),
            Plan::Spawn { .. } => spawn_daemon(&self.paths),
        }
    }
}

/// The offline screen's start key. Nothing is looked up or run until the
/// daemon is found offline (describe) or the key is pressed (start).
fn starter(paths: &Paths) -> parda_tui::Starter {
    let l = Arc::new(Mutex::new(Launcher {
        paths: paths.clone(),
    }));
    let l2 = Arc::clone(&l);
    parda_tui::Starter {
        describe: Box::new(move || l.lock().map(|mut l| l.describe()).unwrap_or_default()),
        start: Box::new(move || {
            l2.lock()
                .map_err(|_| anyhow::anyhow!("the start helper failed earlier"))?
                .start()
        }),
    }
}

fn run_ok(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| anyhow::anyhow!("running {cmd}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "{cmd} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

fn start_service() -> anyhow::Result<String> {
    if cfg!(target_os = "macos") {
        let uid = Command::new("id").arg("-u").output()?;
        let uid = String::from_utf8_lossy(&uid.stdout).trim().to_string();
        let target = format!("gui/{uid}/{}", service::LAUNCHD_LABEL);
        if run_ok("launchctl", &["kickstart", &target]).is_err() {
            // Installed but not loaded (e.g. after `launchctl bootout`).
            let plist = std::env::var_os("HOME")
                .map(|h| {
                    std::path::PathBuf::from(h)
                        .join("Library/LaunchAgents")
                        .join(format!("{}.plist", service::LAUNCHD_LABEL))
                })
                .ok_or_else(|| anyhow::anyhow!("cannot find the home directory"))?;
            run_ok(
                "launchctl",
                &[
                    "bootstrap",
                    &format!("gui/{uid}"),
                    &plist.display().to_string(),
                ],
            )?;
        }
    } else if cfg!(target_os = "linux") {
        run_ok("systemctl", &["--user", "start", service::SYSTEMD_UNIT])?;
    } else if cfg!(target_os = "windows") {
        run_ok("schtasks", &["/Run", "/TN", service::WINDOWS_TASK])?;
    } else {
        anyhow::bail!("no login service on this platform; run `parda daemon`");
    }
    Ok("asked the login service to start parda — waiting for it".into())
}

fn spawn_daemon(paths: &Paths) -> anyhow::Result<String> {
    std::fs::create_dir_all(&paths.log_dir)?;
    let log_path = paths.log_dir.join("daemon.out.log");
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("daemon")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    if let Some(home) = &paths.home {
        cmd.env("PARDA_HOME", home);
    }
    // Its own process group / console, so Ctrl-C and closing this terminal
    // do not stop it.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    let mut child = cmd.spawn()?;
    let pid = child.id();
    // Reap it if it exits while the dashboard runs.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(format!(
        "started `parda daemon` (pid {pid}) — output in {}",
        log_path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(home: Option<&Path>) -> Installed {
        Installed {
            exe: Some(PathBuf::from("/Users/x/.local/bin/parda")),
            home: home.map(Path::to_path_buf),
        }
    }

    #[test]
    fn the_service_is_used_only_for_the_same_home() {
        let dir = std::env::temp_dir().join(format!("parda-plan-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let same = dir.join("sub").join("..");
        assert_eq!(plan(None, None), Plan::Spawn { other: None });
        assert_eq!(plan(Some(&svc(None)), None), Plan::Service);
        // The dev env sets PARDA_HOME, the installed service has none.
        assert_eq!(
            plan(Some(&svc(None)), Some(&dir)),
            Plan::Spawn { other: Some(None) }
        );
        assert_eq!(
            plan(Some(&svc(Some(&dir))), None),
            Plan::Spawn {
                other: Some(Some(dir.clone()))
            }
        );
        // Same folder, spelled differently.
        assert_eq!(plan(Some(&svc(Some(&same))), Some(&dir)), Plan::Service);
        assert_eq!(
            plan(Some(&svc(Some(Path::new("/elsewhere")))), Some(&dir)),
            Plan::Spawn {
                other: Some(Some(PathBuf::from("/elsewhere")))
            }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_hint_names_the_home_it_starts() {
        let home = Path::new("/dev/.parda-dev");
        let h = hint(&Plan::Spawn { other: Some(None) }, Some(home));
        assert!(
            h.contains("/dev/.parda-dev") && h.contains("parda daemon"),
            "{h}"
        );
        assert!(
            h.contains("login service"),
            "says why the service is not used: {h}"
        );
        let h = hint(&Plan::Service, None);
        assert!(h.contains("login service") && h.contains("default"), "{h}");
    }
}
