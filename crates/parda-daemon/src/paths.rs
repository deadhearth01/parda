//! Where parda keeps things. `PARDA_HOME` puts everything under one folder:
//!
//! ```text
//! $PARDA_HOME/config.toml, rules.toml
//! $PARDA_HOME/data/vault.db, vault.key, models/
//! $PARDA_HOME/run/parda.sock, proxy.addr, intercept.addr
//! $PARDA_HOME/logs/parda.log.*
//! ```
//!
//! Otherwise the platform's config / data / runtime directories are used.

use std::io;
use std::path::{Path, PathBuf};

use anyhow::Context;
use parda_core::Config;
use parda_detect::RulesFile;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub log_dir: PathBuf,
    /// Set when everything lives under one folder (`PARDA_HOME`).
    pub home: Option<PathBuf>,
}

impl Paths {
    /// `PARDA_HOME` if set, else the platform directories.
    pub fn resolve() -> anyhow::Result<Paths> {
        if let Some(home) = std::env::var_os("PARDA_HOME").filter(|h| !h.is_empty()) {
            return Ok(Paths::under(PathBuf::from(home)));
        }
        let pd = directories::ProjectDirs::from("dev", "parda", "parda")
            .context("cannot determine the home directory")?;
        let data = pd.data_dir().to_path_buf();
        Ok(Paths {
            config_dir: pd.config_dir().to_path_buf(),
            runtime_dir: pd
                .runtime_dir()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| data.join("run")),
            log_dir: data.join("logs"),
            data_dir: data,
            home: None,
        })
    }

    /// Everything under `home`.
    pub fn under(home: PathBuf) -> Paths {
        Paths {
            config_dir: home.clone(),
            data_dir: home.join("data"),
            runtime_dir: home.join("run"),
            log_dir: home.join("logs"),
            home: Some(home),
        }
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    pub fn rules_file(&self) -> PathBuf {
        self.config_dir.join("rules.toml")
    }

    pub fn models_dir(&self) -> PathBuf {
        self.data_dir.join("models")
    }

    pub fn vault_db(&self) -> PathBuf {
        self.data_dir.join("vault.db")
    }

    /// Written by the daemon with the proxy's actual address.
    pub fn proxy_addr_file(&self) -> PathBuf {
        self.runtime_dir.join("proxy.addr")
    }

    /// Written by the daemon with the intercept listener's actual address
    /// while it listens.
    pub fn intercept_addr_file(&self) -> PathBuf {
        self.runtime_dir.join("intercept.addr")
    }

    /// Create every directory, owner-only.
    pub fn ensure(&self) -> io::Result<()> {
        for d in [
            &self.config_dir,
            &self.data_dir,
            &self.runtime_dir,
            &self.log_dir,
        ] {
            std::fs::create_dir_all(d)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(())
    }
}

/// `config.toml`, or defaults when it does not exist.
pub fn load_config(paths: &Paths) -> anyhow::Result<Config> {
    match std::fs::read_to_string(paths.config_file()) {
        Ok(s) => Config::from_toml_str(&s)
            .with_context(|| format!("in {}", paths.config_file().display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", paths.config_file().display())),
    }
}

/// `rules.toml`, or an empty rule set when it does not exist.
pub fn load_rules(paths: &Paths) -> anyhow::Result<RulesFile> {
    match std::fs::read_to_string(paths.rules_file()) {
        Ok(s) => RulesFile::from_toml_str(&s)
            .with_context(|| format!("in {}", paths.rules_file().display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(RulesFile::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", paths.rules_file().display())),
    }
}

/// Write a file atomically with owner-only permissions.
pub fn write_private(path: &Path, contents: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_home_layout_and_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::under(dir.path().to_path_buf());
        p.ensure().unwrap();
        assert_eq!(p.config_file(), dir.path().join("config.toml"));
        assert_eq!(p.vault_db(), dir.path().join("data/vault.db"));
        assert_eq!(p.models_dir(), dir.path().join("data/models"));
        assert!(p.runtime_dir.is_dir() && p.log_dir.is_dir());
        assert_eq!(load_config(&p).unwrap().proxy.listen, "127.0.0.1:8787");
        assert!(load_rules(&p).unwrap().person.is_empty());
        write_private(&p.config_file(), "[detect]\nmode = \"fast\"\n").unwrap();
        assert_eq!(load_config(&p).unwrap().detect.mode, parda_core::Mode::Fast);
        write_private(&p.config_file(), "[detect]\nmode = 3\n").unwrap();
        assert!(load_config(&p).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p.runtime_dir)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }
}
