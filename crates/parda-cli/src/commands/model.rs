//! `parda model list | pull | use | import`.

use std::path::Path;

use indicatif::{ProgressBar, ProgressStyle};
use parda_daemon::{load_config, write_private};
use parda_ml::{ModelManager, catalog, default_model_id};

use super::paths;

pub fn list() -> anyhow::Result<()> {
    let p = paths()?;
    let mm = ModelManager::new(&p.models_dir());
    let configured = load_config(&p)?.detect.model;
    let active = if configured == "default" {
        default_model_id().to_string()
    } else {
        configured.clone()
    };
    println!(
        "{:<20} {:>8}  {:<11} {:<9} description",
        "id", "size", "license", "status"
    );
    for m in catalog() {
        let status = match (mm.is_installed(m.id), m.id == active) {
            (true, true) => "active",
            (true, false) => "installed",
            (false, true) => "MISSING",
            (false, false) => "-",
        };
        println!(
            "{:<20} {:>6} MB  {:<11} {:<9} {}",
            m.id,
            m.total_size() / 1_000_000,
            m.license,
            status,
            m.description
        );
    }
    for id in mm.installed() {
        if !catalog().iter().any(|m| m.id == id) {
            let status = if id == active { "active" } else { "installed" };
            println!(
                "{:<20} {:>8}  {:<11} {:<9} locally imported",
                id, "-", "-", status
            );
        }
    }
    if configured == "none" {
        println!(
            "\nML tier disabled (detect.model = \"none\"): names are found only via rules.toml"
        );
    }
    Ok(())
}

pub fn pull(id: &str) -> anyhow::Result<()> {
    let p = paths()?;
    p.ensure()?;
    let mm = ModelManager::new(&p.models_dir());
    let spec = parda_ml::find_model(id)
        .ok_or_else(|| anyhow::anyhow!("unknown model `{id}`; see `parda model list`"))?;
    let bar = ProgressBar::new(spec.total_size());
    bar.set_style(
        ProgressStyle::with_template("{msg:<24} [{bar:30}] {bytes}/{total_bytes} {bytes_per_sec}")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=> "),
    );
    let mut done_before = std::collections::HashMap::new();
    let mut offset = 0u64;
    for f in spec.files {
        done_before.insert(f.path, offset);
        offset += f.size;
    }
    mm.pull(id, &|file, done, _total| {
        bar.set_message(file.to_string());
        bar.set_position(done_before.get(file).copied().unwrap_or(0) + done);
    })?;
    bar.finish_with_message("verified");
    println!("installed {id} into {}", mm.model_dir(id).display());
    Ok(())
}

const FP32_TIMEOUT_MS: u64 = 1000;

pub fn use_model(id: &str) -> anyhow::Result<()> {
    let p = paths()?;
    p.ensure()?;
    if id != "none" && id != "default" {
        let mm = ModelManager::new(&p.models_dir());
        if !mm.is_installed(id) {
            anyhow::bail!("model `{id}` is not installed; run `parda model pull {id}` first");
        }
    }
    let mut config = load_config(&p)?;
    config.detect.model = id.to_string();
    // The fine-tuned model runs in full precision (~4x slower than the INT8
    // default); give it room so strict mode does not refuse long new text.
    if id == "parda-pii-edge" && config.detect.ml_timeout_ms < FP32_TIMEOUT_MS {
        config.detect.ml_timeout_ms = FP32_TIMEOUT_MS;
        println!(
            "detect.ml_timeout_ms = {FP32_TIMEOUT_MS} (full-precision model needs a larger time budget)"
        );
    }
    write_private(&p.config_file(), &config.to_toml_string()?)?;
    println!("detect.model = \"{id}\" — restart the daemon to load it");
    Ok(())
}

pub fn import(dir: &Path, id: &str) -> anyhow::Result<()> {
    let p = paths()?;
    p.ensure()?;
    ModelManager::new(&p.models_dir()).import(id, dir)?;
    println!("imported `{id}`; activate it with `parda model use {id}`");
    Ok(())
}
