//! The parda engine: finds personal data with the dictionary, rule and ML
//! tiers, swaps it for vault-backed surrogates, and restores real values in
//! text coming back — including text that arrives in arbitrary stream chunks.
//!
//! ```text
//! redact(text, scope):
//!   fragments ─► cache? ─► T0 dictionary + T1 rules (sync) ∥ T2 ML (budgeted)
//!             ─► merge ─► allow-list ─► surrogate-echo guard ─► actions
//!             ─► vault surrogates ─► replaced text
//! restore(text, scope): Aho-Corasick over the scope's surrogates ─► real values
//! ```

mod cache;
mod engine;
mod fragment;
mod index;
mod ml;
mod resolve;
mod restore;
mod stream;

pub use engine::{
    Engine, EngineError, EngineOptions, EngineStats, Redaction, Replacement, source_label,
};
pub use fragment::{DEFAULT_MAX_FRAGMENT_BYTES, ML_WINDOW_OVERLAP, ml_windows, split_fragments};
pub use stream::StreamRestorer;
