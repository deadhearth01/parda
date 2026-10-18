//! `parda on` / `parda off`: the master protection switch.

use parda_core::Config;
use parda_daemon::{load_config, write_private};
use parda_ipc::Request;

use super::{daemon_client, paths};

pub fn set(enabled: bool) -> anyhow::Result<()> {
    let p = paths()?;
    p.ensure()?;
    match daemon_client(&p)? {
        // The daemon writes config.toml and applies the switch at once.
        Some(mut c) => {
            let v = c.call(Request::ConfigGet)?;
            let mut config = Config::from_toml_str(v["toml"].as_str().unwrap_or_default())?;
            config.protection.enabled = enabled;
            c.call(Request::ConfigSet {
                toml: config.to_toml_string()?,
            })?;
        }
        None => {
            let mut config = load_config(&p)?;
            config.protection.enabled = enabled;
            write_private(&p.config_file(), &config.to_toml_string()?)?;
        }
    }
    if enabled {
        println!("protection ON — personal data is replaced before it leaves this machine");
    } else {
        println!(
            "protection OFF — text is sent as typed (answers are still restored); `parda on` to resume"
        );
    }
    Ok(())
}
