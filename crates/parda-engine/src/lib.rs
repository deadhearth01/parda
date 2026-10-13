//! The parda engine: finds personal data with the dictionary, rule and ML
//! tiers, swaps it for vault-backed surrogates, and restores real values in
//! text coming back — including text that arrives in arbitrary stream chunks.
//!
//! ```text
//! redact(texts, scope):
//!   per text: cache? ─► T0 dictionary + T1 rules over the whole text
//!                       ∥ T2 ML over overlapping windows (budgeted, cached)
//!             ─► allow-list ─► policy (block anywhere refuses; warn reported;
//!                only redact findings go on) ─► + surrogate-echo guard
//!             ─► resolve (format matches absorb; URLs keep their contents)
//!             ─► vault stand-ins (never a word already in the input)
//!             ─► self-check: restore(output) == input, else repair or refuse
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
