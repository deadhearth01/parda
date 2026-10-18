//! Running the OS tools parda uses for system wiring (`networksetup`,
//! `security`, `reg`, `certutil`, `gsettings`) behind a [`Runner`], so the
//! logic is tested without touching the real system.

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

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

    /// Tell running apps that the proxy settings changed (Windows WinINet).
    fn refresh_proxy_settings(&mut self) {}
}

/// The real system. Tools that change trust or network settings are run from
/// their fixed system locations, not looked up on `PATH`.
pub struct SystemRunner;

fn resolve(program: &str) -> String {
    match program {
        "networksetup" if cfg!(target_os = "macos") => "/usr/sbin/networksetup".into(),
        "security" if cfg!(target_os = "macos") => "/usr/bin/security".into(),
        "reg" | "certutil" if cfg!(windows) => {
            let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
            format!(r"{root}\System32\{program}.exe")
        }
        other => other.into(),
    }
}

impl Runner for SystemRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> anyhow::Result<String> {
        let out = std::process::Command::new(resolve(program))
            .args(args)
            .output()
            .with_context(|| format!("running {program}"))?;
        if !out.status.success() {
            bail!(
                "{program} {} failed: {}",
                args.first().copied().unwrap_or_default(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn refresh_proxy_settings(&mut self) {
        #[cfg(windows)]
        wininet_refresh();
    }
}

/// Tell WinINet (and the apps using it) to re-read the proxy settings.
#[cfg(windows)]
#[allow(unsafe_code)]
fn wininet_refresh() {
    use windows_sys::Win32::Networking::WinInet::{
        INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
    };
    // SAFETY: documented calls with a null handle and no buffer.
    unsafe {
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        );
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null(),
            0,
        );
    }
}
