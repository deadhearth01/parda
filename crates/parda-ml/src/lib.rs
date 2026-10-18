//! Machine-learning tier for parda: a catalog of permissively licensed PII
//! models, verified downloads/imports, and a GLiNER-based [`MlDetector`].

pub mod catalog;
pub mod ep;
pub mod gliner;
pub mod manager;

use std::path::Path;
use std::sync::Arc;

pub use catalog::{ModelFile, ModelSpec, catalog, default_model_id, find_model, ml_labels};
pub use ep::ExecutionProvider;
pub use gliner::GlinerDetector;
pub use manager::{MODEL_FILES, ModelManager, download_verified, model_file, sha256_hex};
use parda_core::MlDetector;

/// Load the detector for catalog model `id` from `models_root/<id>`.
pub fn load_detector(
    models_root: &Path,
    id: &str,
    ep: ExecutionProvider,
    threshold: f32,
) -> anyhow::Result<Arc<dyn MlDetector>> {
    let mm = ModelManager::new(models_root);
    if !mm.is_installed(id) {
        anyhow::bail!("model `{id}` is not installed; run `parda model pull {id}`");
    }
    let det = GlinerDetector::load(&mm.model_dir(id), threshold, ep)?.named(id);
    Ok(Arc::new(det))
}
