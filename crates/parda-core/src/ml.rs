//! The interface between the engine and a machine-learning detector.

use crate::detection::Detection;

/// A model that finds entities the rule tiers cannot (names, addresses…).
/// Implementations live in `parda-ml`; the engine also works without one.
pub trait MlDetector: Send + Sync {
    /// Short identifier shown in status output, e.g. `gliner-pii-edge`.
    fn name(&self) -> &str;

    /// Detect entities in each text. Offsets are byte offsets into the
    /// corresponding input; the result has one entry per input.
    fn detect_batch(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<Detection>>>;
}
