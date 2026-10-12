//! Installing models: verified HTTPS downloads and local imports.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use sha2::{Digest, Sha256};

use crate::catalog::find_model;

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_file(path: &Path) -> anyhow::Result<(String, u64)> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n = 0u64;
    loop {
        let read = f.read(&mut buf)?;
        if read == 0 {
            break;
        }
        h.update(&buf[..read]);
        n += read as u64;
    }
    Ok((hex(&h.finalize()), n))
}

/// Download `url` to `dest`, verifying size and SHA-256. Writes to a `.part`
/// file and renames only after verification, so a failed or tampered download
/// never leaves a file at `dest`.
pub fn download_verified(
    url: &str,
    dest: &Path,
    sha256: &str,
    size: u64,
    progress: &dyn Fn(u64, u64),
) -> anyhow::Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let part = dest.with_extension("part");
    let result = (|| -> anyhow::Result<()> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(concat!("parda/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(60 * 30))
            .build()?;
        let mut resp = client.get(url).send()?.error_for_status()?;
        let mut out = File::create(&part)?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut done = 0u64;
        loop {
            let n = resp.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            h.update(&buf[..n]);
            done += n as u64;
            progress(done, size);
        }
        out.flush()?;
        let got = hex(&h.finalize());
        if got != sha256 {
            bail!("sha256 mismatch for {url}: expected {sha256}, got {got}");
        }
        if done != size {
            bail!("size mismatch for {url}: expected {size} bytes, got {done}");
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            fs::rename(&part, dest)?;
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&part);
            Err(e)
        }
    }
}

/// Installs models under `<root>/<id>/`.
#[derive(Debug, Clone)]
pub struct ModelManager {
    root: PathBuf,
}

impl ModelManager {
    pub fn new(root: &Path) -> Self {
        ModelManager {
            root: root.to_path_buf(),
        }
    }

    pub fn model_dir(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    /// A model counts as installed when its directory holds the ONNX model,
    /// the tokenizer and the GLiNER config.
    pub fn is_installed(&self, id: &str) -> bool {
        let dir = self.model_dir(id);
        ["model_quint8.onnx", "tokenizer.json", "gliner_config.json"]
            .iter()
            .all(|f| dir.join(f).is_file())
    }

    /// Installed model ids (directories that pass [`Self::is_installed`]).
    pub fn installed(&self) -> Vec<String> {
        let Ok(rd) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut ids: Vec<String> = rd
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|id| self.is_installed(id))
            .collect();
        ids.sort();
        ids
    }

    /// Download a catalog model, verifying every file.
    pub fn pull(&self, id: &str, progress: &dyn Fn(&str, u64, u64)) -> anyhow::Result<()> {
        let spec = find_model(id).with_context(|| format!("unknown model `{id}`"))?;
        let dir = self.model_dir(id);
        for f in spec.files {
            let dest = dir.join(f.path);
            if dest.is_file()
                && sha256_file(&dest)
                    .map(|(h, _)| h == f.sha256)
                    .unwrap_or(false)
            {
                continue;
            }
            download_verified(f.url, &dest, f.sha256, f.size, &|d, t| {
                progress(f.path, d, t)
            })?;
        }
        Ok(())
    }

    /// Install a locally exported model directory (e.g. a fine-tuned model
    /// produced by `training/export_onnx.py`). Every file listed in the
    /// directory's `manifest.json` is checked against its SHA-256 and size.
    pub fn import(&self, id: &str, src: &Path) -> anyhow::Result<()> {
        let manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(src.join("manifest.json")).context("reading manifest.json")?,
        )?;
        let files = manifest["files"]
            .as_object()
            .context("manifest.json has no `files` object")?;
        for (name, meta) in files {
            if name.contains('/') || name.contains("..") {
                bail!("unsafe file name in manifest: {name}");
            }
            let (got, size) = sha256_file(&src.join(name))?;
            let want = meta["sha256"].as_str().unwrap_or_default();
            if got != want {
                bail!("sha256 mismatch for {name}: expected {want}, got {got}");
            }
            if meta["size"].as_u64() != Some(size) {
                bail!("size mismatch for {name}");
            }
        }
        let dir = self.model_dir(id);
        fs::create_dir_all(&dir)?;
        for name in files.keys() {
            fs::copy(src.join(name), dir.join(name))?;
        }
        fs::copy(src.join("manifest.json"), dir.join("manifest.json"))?;
        if !self.is_installed(id) {
            bail!(
                "imported directory lacks model_quint8.onnx, tokenizer.json or gliner_config.json"
            );
        }
        Ok(())
    }
}
