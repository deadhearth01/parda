//! `parda service install | uninstall | status`.

use parda_daemon::service;

pub fn install() -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let p = super::paths()?;
    p.ensure()?;
    println!("{}", service::install(&exe, &p)?);
    println!("parda now starts at login; check with `parda status`");
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    println!("{}", service::uninstall()?);
    Ok(())
}

pub fn status() -> anyhow::Result<()> {
    println!("service: {}", service::status()?);
    Ok(())
}
