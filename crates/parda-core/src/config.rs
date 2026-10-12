//! User configuration (`config.toml`). Every field has a default so an empty
//! file is a valid configuration.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::kind::EntityKind;

/// What happens when an entity of a given kind is found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Replace with a surrogate or token and restore on the way back.
    Redact,
    /// Refuse to send the text at all.
    Block,
    /// Send unchanged but record an event.
    Warn,
    /// Send unchanged, no event.
    Ignore,
}

/// Behaviour when the ML tier fails or exceeds its time budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Refuse the request (privacy over availability).
    Strict,
    /// Continue with the dictionary and rule tiers only.
    Fast,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Style {
    /// Realistic same-kind fake values.
    Surrogate,
    /// Typed placeholder tokens such as `⟦PERSON_1⟧`.
    Token,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnscannedMedia {
    Allow,
    Block,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub detect: DetectConfig,
    pub replace: ReplaceConfig,
    pub vault: VaultConfig,
    pub clipboard: ClipboardConfig,
    pub privacy: PrivacyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    pub enabled: bool,
    pub listen: String,
    pub anthropic_upstream: String,
    pub openai_upstream: String,
    pub unscanned_media: UnscannedMedia,
    pub allowed_origins: Vec<String>,
    pub allow_non_loopback: bool,
    /// Largest request body accepted, in bytes.
    pub max_body_bytes: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            enabled: true,
            listen: "127.0.0.1:8787".into(),
            anthropic_upstream: "https://api.anthropic.com".into(),
            openai_upstream: "https://api.openai.com".into(),
            unscanned_media: UnscannedMedia::Allow,
            allowed_origins: Vec::new(),
            allow_non_loopback: false,
            max_body_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectConfig {
    pub mode: Mode,
    pub packs: Vec<String>,
    pub dates: bool,
    /// Model catalog id, `"default"`, or `"none"` to disable the ML tier.
    pub model: String,
    pub ml_threshold: f32,
    pub ml_timeout_ms: u64,
    /// `auto`, `cpu`, `coreml`, `directml` or `cuda`.
    pub execution_provider: String,
    pub actions: BTreeMap<EntityKind, Action>,
}

impl Default for DetectConfig {
    fn default() -> Self {
        DetectConfig {
            mode: Mode::Strict,
            packs: ["global", "india", "us_uk", "secrets"]
                .map(String::from)
                .to_vec(),
            dates: false,
            model: "default".into(),
            ml_threshold: 0.4,
            ml_timeout_ms: 250,
            execution_provider: "auto".into(),
            actions: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReplaceConfig {
    pub style: Style,
}

impl Default for ReplaceConfig {
    fn default() -> Self {
        ReplaceConfig {
            style: Style::Surrogate,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VaultConfig {
    pub ttl_days: u32,
    /// Store the vault key in the OS keyring when available.
    pub use_keyring: bool,
}

impl Default for VaultConfig {
    fn default() -> Self {
        VaultConfig {
            ttl_days: 30,
            use_keyring: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClipboardConfig {
    pub enabled: bool,
    pub poll_ms: u64,
    /// `"default"` picks Cmd+Alt+V on macOS and Ctrl+Alt+V elsewhere.
    pub hotkey: String,
    pub restore_on_copy: bool,
    pub scope: String,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        ClipboardConfig {
            enabled: true,
            poll_ms: 300,
            hotkey: "default".into(),
            restore_on_copy: true,
            scope: "global".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivacyConfig {
    /// Include raw values in logs and events. Off by default.
    pub log_values: bool,
}

impl Config {
    pub fn from_toml_str(s: &str) -> Result<Config> {
        toml::from_str(s).map_err(|e| Error::Config(e.to_string()))
    }

    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))
    }

    pub fn action_for(&self, kind: &EntityKind) -> Action {
        self.detect
            .actions
            .get(kind)
            .copied()
            .unwrap_or(Action::Redact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EntityKind;

    #[test]
    fn empty_toml_gives_defaults() {
        let c = Config::from_toml_str("").unwrap();
        assert_eq!(c.proxy.listen, "127.0.0.1:8787");
        assert_eq!(c.proxy.anthropic_upstream, "https://api.anthropic.com");
        assert_eq!(c.proxy.openai_upstream, "https://api.openai.com");
        assert_eq!(c.proxy.unscanned_media, UnscannedMedia::Allow);
        assert_eq!(c.detect.mode, Mode::Strict);
        assert_eq!(c.detect.ml_timeout_ms, 250);
        assert_eq!(c.detect.model, "default");
        assert!(!c.detect.dates);
        assert_eq!(c.detect.packs, vec!["global", "india", "us_uk", "secrets"]);
        assert_eq!(c.replace.style, Style::Surrogate);
        assert_eq!(c.vault.ttl_days, 30);
        assert!(c.clipboard.enabled);
        assert!(c.clipboard.restore_on_copy);
        assert_eq!(c.clipboard.poll_ms, 300);
        assert_eq!(c.clipboard.scope, "global");
        assert!(!c.privacy.log_values);
    }

    #[test]
    fn per_kind_action_override() {
        let c = Config::from_toml_str("[detect.actions]\nSecret = \"block\"\n").unwrap();
        assert_eq!(c.action_for(&EntityKind::Secret), Action::Block);
        assert_eq!(c.action_for(&EntityKind::Email), Action::Redact);
    }

    #[test]
    fn roundtrip_toml() {
        let mut c = Config::default();
        c.detect.mode = Mode::Fast;
        c.replace.style = Style::Token;
        let s = c.to_toml_string().unwrap();
        let back = Config::from_toml_str(&s).unwrap();
        assert_eq!(back.detect.mode, Mode::Fast);
        assert_eq!(back.replace.style, Style::Token);
    }

    #[test]
    fn unknown_field_is_error() {
        assert!(Config::from_toml_str("[proxy]\nlisten_typo = \"x\"\n").is_err());
    }
}
