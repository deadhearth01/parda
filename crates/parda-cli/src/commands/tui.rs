//! `parda` / `parda tui`: the dashboard, and how its offline screen starts
//! the daemon.

use std::fs::OpenOptions;
use std::process::{Command, Stdio};

use parda_daemon::{Paths, service};

pub fn run(dump: bool) -> anyhow::Result<()> {
    let paths = super::paths()?;
    if dump {
        print!("{}", parda_tui::dump(&paths.runtime_dir, 110, 30)?);
        return Ok(());
    }
    parda_tui::run(&paths.runtime_dir, Some(starter(&paths)))
}

/// Whether `parda service install` set up a login service for this user.
fn service_installed() -> bool {
    service::status().is_ok_and(|s| s.starts_with("installed"))
}

/// What the offline screen's start key runs: the login service when one is
/// installed, otherwise `parda daemon` detached from this terminal with the
/// same PARDA_HOME. Nothing runs until the key is pressed.
fn starter(paths: &Paths) -> parda_tui::Starter {
    let log = paths.log_dir.join("daemon.out.log");
    let use_service = service_installed();
    let hint = if use_service {
        "starts the login service installed by `parda service install`".to_string()
    } else {
        format!(
            "runs `parda daemon` in the background · output: {}",
            log.display()
        )
    };
    let paths = paths.clone();
    parda_tui::Starter {
        hint,
        start: Box::new(move || {
            if use_service {
                start_service()
            } else {
                spawn_daemon(&paths)
            }
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
