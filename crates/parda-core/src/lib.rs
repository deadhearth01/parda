//! Core types shared by every parda crate: entity kinds, detections, the
//! overlap-merge policy, configuration, validators and the ML detector trait.

pub mod config;
pub mod detection;
pub mod error;
pub mod kind;
pub mod merge;
pub mod ml;
pub mod validators;

pub use config::{
    Action, ClipboardConfig, Config, DEFAULT_INTERCEPT_HOSTS, DetectConfig,
    INTERCEPT_SCOPE_PER_HOST, InterceptConfig, InterceptScope, Mode, PrivacyConfig,
    ProtectionConfig, ProxyConfig, ReplaceConfig, Style, UnscannedMedia, VaultConfig,
};
pub use detection::{Detection, Source, Span};
pub use error::{Error, Result};
pub use kind::EntityKind;
pub use merge::{SpanSet, merge, preference};
pub use ml::MlDetector;
