//! `parda ca create | path | install | uninstall | status` — the local root
//! certificate used by `parda intercept`.

use parda_daemon::ca_store::{ca_cert_path, ca_exists, create_ca};
use parda_daemon::cert_trust;
use parda_daemon::load_config;
use parda_daemon::sysproxy::{Platform, SystemRunner};

use super::paths;

pub fn create(force: bool) -> anyhow::Result<()> {
    let p = paths()?;
    let config = load_config(&p)?;
    create_ca(&p, config.vault.use_keyring, force)?;
    println!("created {}", ca_cert_path(&p).display());
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

pub fn uninstall() -> anyhow::Result<()> {
    let p = paths()?;
    cert_trust::uninstall(&mut SystemRunner, Platform::current(), &ca_cert_path(&p))?;
    println!("removed parda's certificate from your trust store");
    Ok(())
}

pub fn status() -> anyhow::Result<()> {
    let p = paths()?;
    let pem = ca_cert_path(&p);
    if !ca_exists(&p) {
        println!("certificate: not created (`parda ca create` or `parda ca install`)");
        return Ok(());
    }
    let trusted = cert_trust::is_trusted(&mut SystemRunner, Platform::current(), &pem);
    println!("certificate: created ({})", pem.display());
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
