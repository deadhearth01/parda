//! `parda ca create | path | install | uninstall | status` — the local root
//! certificate used by `parda intercept`.

use parda_daemon::ca_store::{ca_cert_path, ca_exists, create_ca, load_ca};
use parda_daemon::sysproxy::{self, Platform, SystemRunner};
use parda_daemon::{Paths, cert_trust, load_config};
use parda_ipc::Request;

use super::{daemon_client, paths};

/// A running daemon checks the certificate file before answering a status
/// request (and every few seconds): ask now, so its listener signs with the
/// new certificate at once.
fn tell_daemon(p: &Paths) {
    if let Ok(Some(mut c)) = daemon_client(p) {
        match c.call(Request::Status) {
            Ok(_) => println!("the running daemon now uses this certificate"),
            Err(e) => {
                println!("! could not reach the daemon ({e}); restart it to use this certificate")
            }
        }
    }
}

/// Why removing the certificate from the trust store would break AI sites
/// right now, if it would: intercept is switched on, or the system proxy
/// still sends AI sites to parda.
fn uninstall_blocker(p: &Paths) -> Option<String> {
    if sysproxy::load_state(p).map_or(true, |s| s.is_some()) {
        return Some(
            "the system proxy still sends AI sites to parda — without a trusted certificate they \
             fail to load (HTTPS errors you cannot click through). Run `parda intercept off` \
             first, or pass --force"
                .into(),
        );
    }
    if load_config(p).map_or(true, |c| c.intercept.enabled) {
        return Some(
            "intercept is on (intercept.enabled = true) — AI apps that use parda would fail \
             with certificate errors. Run `parda intercept off` first, or pass --force"
                .into(),
        );
    }
    None
}

pub fn create(force: bool) -> anyhow::Result<()> {
    let p = paths()?;
    let config = load_config(&p)?;
    if force
        && ca_cert_path(&p).is_file()
        && cert_trust::is_trusted(&mut SystemRunner, Platform::current(), &ca_cert_path(&p))
    {
        anyhow::bail!(
            "the current certificate is still trusted by your system; remove it first with \
             `parda ca uninstall`, then run `parda ca create --force`"
        );
    }
    create_ca(&p, config.vault.use_keyring, force)?;
    println!("created {}", ca_cert_path(&p).display());
    tell_daemon(&p);
    println!("next: `parda ca install` to trust it (your OS will ask you to confirm)");
    Ok(())
}

pub fn path() -> anyhow::Result<()> {
    println!("{}", ca_cert_path(&paths()?).display());
    Ok(())
}

pub fn install() -> anyhow::Result<()> {
    let p = paths()?;
    if !ca_exists(&p) {
        let config = load_config(&p)?;
        create_ca(&p, config.vault.use_keyring, false)?;
        println!("created {}", ca_cert_path(&p).display());
        tell_daemon(&p);
    }
    let pem = ca_cert_path(&p);
    println!(
        "asking your OS to trust {} — approve the dialog that appears",
        pem.display()
    );
    cert_trust::install(&mut SystemRunner, Platform::current(), &pem)?;
    if cert_trust::is_trusted(&mut SystemRunner, Platform::current(), &pem) {
        println!(
            "✓ trusted — parda can now protect AI sites in your browsers and apps (`parda intercept on`)"
        );
    } else {
        println!("! the OS did not confirm the trust setting; check with `parda ca status`");
    }
    Ok(())
}

pub fn uninstall(force: bool) -> anyhow::Result<()> {
    let p = paths()?;
    let pem = ca_cert_path(&p);
    if !pem.is_file() {
        anyhow::bail!("no parda certificate at {}", pem.display());
    }
    if let Some(why) = uninstall_blocker(&p) {
        if !force {
            anyhow::bail!("not removing the certificate: {why}");
        }
        println!("! {why}");
    }
    cert_trust::uninstall(&mut SystemRunner, Platform::current(), &pem)?;
    println!("removed parda's certificate from your trust store");
    Ok(())
}

pub fn status() -> anyhow::Result<()> {
    let p = paths()?;
    let pem = ca_cert_path(&p);
    if !pem.is_file() {
        println!("certificate: not created (`parda ca create` or `parda ca install`)");
        return Ok(());
    }
    let trusted = cert_trust::is_trusted(&mut SystemRunner, Platform::current(), &pem);
    println!("certificate: created ({})", pem.display());
    let config = load_config(&p)?;
    // Never create a vault key just to report status.
    match parda_vault::find_key(&p.data_dir, config.vault.use_keyring) {
        Ok(Some(_)) => {
            if let Err(e) = load_ca(&p, config.vault.use_keyring) {
                println!("key:         unusable — {e:#}");
            }
        }
        _ => println!(
            "key:         unusable — the vault key is missing; run `parda ca uninstall`, then `parda ca create --force`"
        ),
    }
    println!(
        "trusted:     {}",
        if trusted {
            "yes"
        } else {
            "no — run `parda ca install`"
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use parda_daemon::{Paths, write_private};

    use super::uninstall_blocker;

    fn home(config: &str) -> (tempfile::TempDir, Paths) {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path().to_path_buf());
        write_private(&p.config_file(), config).unwrap();
        (d, p)
    }

    #[test]
    fn uninstall_is_refused_while_intercept_is_in_use() {
        let (_d, p) = home("[intercept]\nenabled = false\n");
        assert_eq!(uninstall_blocker(&p), None);

        let (_d, p) = home("[intercept]\nenabled = true\n");
        let why = uninstall_blocker(&p).expect("enabled");
        assert!(why.contains("parda intercept off"), "{why}");

        // The system still points at parda (saved state), even if the
        // config says off.
        let (_d, p) = home("[intercept]\nenabled = false\n");
        write_private(
            &p.data_dir.join("intercept-state.json"),
            r#"{"platform":"MacOs","pac_url":"http://127.0.0.1:8788/parda.pac","saved":[]}"#,
        )
        .unwrap();
        let why = uninstall_blocker(&p).expect("state file");
        assert!(
            why.contains("fail") && why.contains("parda intercept off"),
            "{why}"
        );
    }
}
