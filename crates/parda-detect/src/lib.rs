//! Deterministic PII detectors.
use parda_core::Detection;

pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    fn detect(&self, text: &str) -> Vec<Detection>;
}

pub mod rules;
pub use rules::RuleDetector;

pub mod allow;
pub mod dictionary;
pub use allow::AllowList;
pub use dictionary::{DictionaryDetector, PersonBlock, RulesFile, Term, expand_person};
