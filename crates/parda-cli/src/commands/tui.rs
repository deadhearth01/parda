//! `parda` / `parda tui`: the dashboard, and how its offline screen starts
//! the daemon.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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
    /// The daemon this dashboard started, while it may still be running.
    child: Option<Child>,
    /// How to start it (tests use a harmless stand-in).
    spawn: fn(&Paths) -> anyhow::Result<Child>,
    /// How long to watch a fresh daemon for an immediate exit.
    settle: Duration,
}

impl Launcher {
    fn new(paths: Paths) -> Self {
        Launcher {
            paths,
            child: None,
            spawn: |p| Ok(daemon_command(p)?.spawn()?),
            settle: Duration::from_millis(800),
        }
    }

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
            Plan::Spawn { .. } => self.spawn_once(),
        }
    }

    /// Start `parda daemon` unless the one started earlier still runs.
    fn spawn_once(&mut self) -> anyhow::Result<String> {
        if let Some(c) = &mut self.child
            && c.try_wait()?.is_none()
        {
            anyhow::bail!(
                "`parda daemon` (pid {}) started from here is still running — waiting for it",
                c.id()
            );
        }
        self.child = None;
        self.paths.ensure()?;
        let mut child = (self.spawn)(&self.paths)?;
        // Its output goes nowhere (it logs to its own files), so catch a
        // daemon that dies at once (vault locked, bad config) here.
        let deadline = Instant::now() + self.settle;
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait()? {
                anyhow::bail!(
                    "`parda daemon` exited at once ({status}) — run `parda daemon` in a terminal \
                     to see why"
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let pid = child.id();
        self.child = Some(child);
        Ok(format!(
            "started `parda daemon` (pid {pid}) for {} — logs in {}",
            home_label(self.paths.home.as_deref()),
            self.paths.log_dir.display()
        ))
    }
}

/// The offline screen's start key. Nothing is looked up or run until the
/// daemon is found offline (describe) or the key is pressed (start).
fn starter(paths: &Paths) -> parda_tui::Starter {
    let l = Arc::new(Mutex::new(Launcher::new(paths.clone())));
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

/// A system tool by absolute path, never whatever `PATH` finds first.
fn tool(name: &str) -> PathBuf {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot")
            .filter(|r| !r.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        return root.join("System32").join(format!("{name}.exe"));
    }
    let candidates: &[&str] = match name {
        "launchctl" => &["/bin/launchctl"],
        "id" => &["/usr/bin/id"],
        "systemctl" => &["/usr/bin/systemctl", "/bin/systemctl"],
        _ => &[],
    };
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .or_else(|| candidates.first().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/usr/bin").join(name))
}

/// Run a tool; its stdout, or an error with its stderr if it failed.
fn run_ok(name: &str, args: &[&str]) -> anyhow::Result<Vec<u8>> {
    let out = Command::new(tool(name))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| anyhow::anyhow!("running {name}: {e}"))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        anyhow::bail!(
            "{name} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

fn parse_uid(out: &[u8]) -> anyhow::Result<u32> {
    String::from_utf8_lossy(out)
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("`id -u` gave no user id"))
}

fn start_service() -> anyhow::Result<String> {
    if cfg!(target_os = "macos") {
        let uid = parse_uid(&run_ok("id", &["-u"])?)?;
        let target = format!("gui/{uid}/{}", service::LAUNCHD_LABEL);
        if run_ok("launchctl", &["kickstart", &target]).is_err() {
            // Installed but not loaded (e.g. after `launchctl bootout`).
            let plist = service::launchd_plist()?;
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

/// `parda daemon` for this home, detached from the terminal: its own
/// session, no stdio (it logs to its own files), the home as its working
/// directory and PARDA_HOME, both absolute.
fn daemon_command(paths: &Paths) -> anyhow::Result<Command> {
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match &paths.home {
        Some(home) => {
            let home = std::path::absolute(home)?;
            cmd.current_dir(&home).env("PARDA_HOME", &home);
        }
        None => {
            cmd.current_dir(std::path::absolute(&paths.data_dir)?)
                .env_remove("PARDA_HOME");
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid is async-signal-safe and touches no memory of
        // this process; it runs in the forked child before exec, so
        // closing the terminal or Ctrl-C in it does not reach the daemon.
        #[allow(unsafe_code)]
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    Ok(cmd)
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

    #[cfg(unix)]
    #[test]
    fn m1_a_second_start_waits_for_the_daemon_started_from_here() {
        let dir = std::env::temp_dir().join(format!("parda-launch-{}", std::process::id()));
        let mut l = Launcher::new(Paths::under(dir.clone()));
        // A harmless stand-in for the daemon; tests never start one.
        l.spawn = |_| Ok(Command::new("/bin/sleep").arg("30").spawn()?);
        l.settle = Duration::from_millis(50);
        assert!(l.spawn_once().is_ok());
        let e = l.spawn_once().unwrap_err().to_string();
        assert!(e.contains("still running"), "{e}");
        let c = l.child.as_mut().unwrap();
        c.kill().unwrap();
        c.wait().unwrap();
        assert!(l.spawn_once().is_ok(), "once it has exited, start again");
        let c = l.child.as_mut().unwrap();
        c.kill().unwrap();
        c.wait().unwrap();
        // A daemon that dies at once says so instead of a silent wait.
        l.spawn = |_| Ok(Command::new("/usr/bin/false").spawn()?);
        l.settle = Duration::from_millis(1500);
        let e = l.spawn_once().unwrap_err().to_string();
        assert!(e.contains("exited at once"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn m2_the_daemon_runs_detached_in_its_absolute_home() {
        let cmd = daemon_command(&Paths::under(PathBuf::from("rel-parda-home"))).unwrap();
        assert_eq!(cmd.get_args().collect::<Vec<_>>(), ["daemon"]);
        let dir = cmd.get_current_dir().unwrap().to_path_buf();
        assert!(
            dir.is_absolute() && dir.ends_with("rel-parda-home"),
            "{dir:?}"
        );
        let env: Vec<_> = cmd.get_envs().collect();
        assert!(
            env.contains(&(std::ffi::OsStr::new("PARDA_HOME"), Some(dir.as_os_str()))),
            "{env:?}"
        );
        let no_home = Paths {
            home: None,
            ..Paths::under(PathBuf::from("/x"))
        };
        let cmd = daemon_command(&no_home).unwrap();
        assert!(cmd.get_current_dir().unwrap().is_absolute());
        assert!(
            cmd.get_envs()
                .any(|(k, v)| k == "PARDA_HOME" && v.is_none()),
            "an inherited PARDA_HOME is removed"
        );
    }

    #[test]
    fn m3_system_tools_by_absolute_path_and_checked_output() {
        let tools: &[&str] = if cfg!(target_os = "macos") {
            &["launchctl", "id"]
        } else if cfg!(target_os = "linux") {
            &["systemctl"]
        } else if cfg!(windows) {
            &["schtasks"]
        } else {
            &[]
        };
        for t in tools {
            assert!(tool(t).is_absolute(), "{t}: {:?}", tool(t));
        }
        assert_eq!(parse_uid(b"501\n").unwrap(), 501);
        assert!(parse_uid(b"").is_err());
        assert!(parse_uid(b"root").is_err());
    }
}
