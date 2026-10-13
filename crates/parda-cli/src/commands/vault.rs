//! `parda vault stats | wipe | reset`.

use dialoguer::Confirm;
use parda_daemon::load_config;
use parda_ipc::Request;
use parda_vault::{Store, open_vault};

use super::{daemon_client, paths};

fn local_store() -> anyhow::Result<Store> {
    let p = paths()?;
    p.ensure()?;
    let config = load_config(&p)?;
    // Same key lookup as the daemon, including the fallback to the other key store.
    Ok(open_vault(&p.data_dir, config.vault.use_keyring)?.0)
}

pub fn stats() -> anyhow::Result<()> {
    let p = paths()?;
    let rows: Vec<(String, String, u64)> = match daemon_client(&p)? {
        Some(mut c) => c.call(Request::VaultStats)?["stats"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|r| {
                (
                    r["scope"].as_str().unwrap_or("").to_string(),
                    r["kind"].as_str().unwrap_or("").to_string(),
                    r["count"].as_u64().unwrap_or(0),
                )
            })
            .collect(),
        None => local_store()?.stats()?,
    };
    if rows.is_empty() {
        println!("the vault is empty");
        return Ok(());
    }
    println!("{:<16} {:<18} {:>8}", "scope", "kind", "mappings");
    for (scope, kind, n) in rows {
        println!("{scope:<16} {kind:<18} {n:>8}");
    }
    Ok(())
}

fn confirm(prompt: &str, yes: bool) -> anyhow::Result<bool> {
    if yes {
        return Ok(true);
    }
    Ok(Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()?)
}

pub fn wipe(scope: Option<String>, yes: bool) -> anyhow::Result<()> {
    let what = scope
        .as_deref()
        .map(|s| format!("scope `{s}`"))
        .unwrap_or_else(|| "ALL scopes".into());
    if !confirm(
        &format!(
            "Delete every mapping in {what}? Answers that still contain those surrogates can no longer be restored"
        ),
        yes,
    )? {
        println!("cancelled");
        return Ok(());
    }
    let p = paths()?;
    let removed = match daemon_client(&p)? {
        Some(mut c) => c.call(Request::VaultWipe { scope })?["removed"]
            .as_u64()
            .unwrap_or(0) as usize,
        None => local_store()?.wipe(scope.as_deref())?,
    };
    println!("removed {removed} mapping(s)");
    Ok(())
}

pub fn reset(yes: bool) -> anyhow::Result<()> {
    let p = paths()?;
    if daemon_client(&p)?.is_some() {
        anyhow::bail!("stop the daemon first (`parda service uninstall` or stop `parda daemon`)");
    }
    if !confirm(
        "Delete the vault AND its key? All mappings are lost; a new key is created on next use",
        yes,
    )? {
        println!("cancelled");
        return Ok(());
    }
    let config = load_config(&p)?;
    for suffix in ["", "-wal", "-shm"] {
        let f = p.data_dir.join(format!("vault.db{suffix}"));
        if f.exists() {
            std::fs::remove_file(&f)?;
        }
    }
    parda_vault::delete_key(&p.data_dir, config.vault.use_keyring)?;
    println!("vault and key deleted");
    Ok(())
}
