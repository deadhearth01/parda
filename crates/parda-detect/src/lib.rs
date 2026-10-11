//! Deterministic PII detectors.
use parda_core::Detection;

pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    fn detect(&self, text: &str) -> Vec<Detection>;
}

pub mod rules;
pub use rules::RuleDetector;
