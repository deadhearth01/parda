//! `parda setup`: config, model, service and agent settings in one go.

use dialoguer::{Confirm, Select};
use parda_daemon::{load_config, write_private};
use parda_ml::{ModelManager, default_model_id};

use super::{env, model, paths};

pub fn run(yes: bool, model_arg: Option<String>, no_service: bool) -> anyhow::Result<()> {
    let p = paths()?;
    p.ensure()?;
    println!("parda setup — config in {}", p.config_dir.display());

    let mut config = load_config(&p)?;
    // A model chosen earlier (`parda model use`) stays unless it is gone.
    let mm = ModelManager::new(&p.models_dir());
    let current = match config.detect.model.as_str() {
        "default" | "" => None,
        "none" => Some("none".to_string()),
        id if mm.is_installed(id) => Some(id.to_string()),
        _ => None,
    };
    let model_id = match model_arg {
        Some(m) => m,
        None if yes => current.unwrap_or_else(|| default_model_id().to_string()),
        None => {
            let mut choices = Vec::new();
            if let Some(c) = &current {
                choices.push(format!("{c} (keep current)"));
            }
            choices.push(format!(
                "{} (recommended: names, addresses — ~50 MB)",
                default_model_id()
            ));
            choices
                .push("none (rules and your own name list only; nothing to download)".to_string());
            let picked = Select::new()
                .with_prompt("Name detection model")
                .items(&choices)
                .default(0)
                .interact()?;
            let offset = usize::from(current.is_some());
            match (picked, &current) {
                (0, Some(c)) => c.clone(),
                (i, _) if i == offset => default_model_id().to_string(),
                _ => "none".to_string(),
            }
        }
    };
    config.detect.model = if model_id == default_model_id() {
        "default".into()
    } else {
        model_id.clone()
    };
    write_private(&p.config_file(), &config.to_toml_string()?)?;
    println!("✓ wrote {}", p.config_file().display());

    if model_id != "none" {
        if mm.is_installed(&model_id) {
            println!("✓ model {model_id} already installed");
        } else if parda_ml::find_model(&model_id).is_some() {
            model::pull(&model_id)?;
        } else {
            println!(
                "! model {model_id} is not in the catalog; import it with `parda model import`"
            );
        }
    }

    if !p.rules_file().exists() {
        write_private(
            &p.rules_file(),
            "# Add people to always mask with `parda rules add-person \"Name\"`\n",
        )?;
    }

    if !no_service {
        let install = yes
            || Confirm::new()
                .with_prompt("Start parda automatically at login?")
                .default(true)
                .interact()?;
        if install {
            match super::service::install() {
                Ok(()) => {}
                Err(e) => println!("! service not installed: {e:#} — run `parda daemon` yourself"),
            }
        }
    }

    let url = env::proxy_url()?;
    println!("\nRoute your agents through parda:\n");
    println!("{}\n", env::snippet("claude", &url));
    println!("{}\n", env::snippet("codex", &url));
    println!(
        "Chat apps: copy text, then press the paste-safe hotkey ({}) instead of paste.",
        if config.clipboard.hotkey == "default" {
            if cfg!(target_os = "macos") {
                "Cmd+Alt+V"
            } else {
                "Ctrl+Alt+V"
            }
        } else {
            config.clipboard.hotkey.as_str()
        }
    );
    if cfg!(target_os = "macos") {
        println!(
            "macOS: allow parda under System Settings → Privacy & Security → Accessibility so it can paste."
        );
    }
    println!("\nCheck everything with `parda doctor`; watch it work with `parda tui`.");
    Ok(())
}
