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
    /// Typed tags such as `[NAME_1]`.
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
    pub protection: ProtectionConfig,
    pub proxy: ProxyConfig,
    pub detect: DetectConfig,
    pub replace: ReplaceConfig,
    pub vault: VaultConfig,
    pub clipboard: ClipboardConfig,
    pub intercept: InterceptConfig,
    pub privacy: PrivacyConfig,
}

/// The master switch. When off, nothing is redacted on any surface (text is
/// sent as typed) while surrogates sent earlier still restore in answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProtectionConfig {
    pub enabled: bool,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        ProtectionConfig { enabled: true }
    }
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
    /// Opt-in: request paths forwarded unchanged (unfiltered, with a warning
    /// event) instead of being refused as unknown endpoints. An entry is an
    /// exact path (`/v1/files`) or, when it ends in `*`, a prefix (`/api/*`).
    /// Endpoints parda knows how to redact are never passed through.
    pub passthrough_paths: Vec<String>,
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
            passthrough_paths: Vec::new(),
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
    /// Per kind. Built-in names ignore case and `_` / `-` / spaces
    /// (`secret`, `IP_ADDRESS`); any other key is a custom kind from
    /// `rules.toml`, exactly as written. See
    /// [`Config::suspicious_action_keys`] for likely typos.
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
            style: Style::Token,
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

/// `intercept.scope` value giving each site its own vault scope.
pub const INTERCEPT_SCOPE_PER_HOST: &str = "per-host";

/// What `intercept.scope` means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptScope {
    /// `"per-host"`: each host its own scope, `intercept:<host>`.
    PerHost,
    /// `"global"` (the scope the clipboard and the agent proxy use by
    /// default) or `"fixed:<name>"`: one scope, this one, for every site.
    Fixed(String),
}

impl InterceptScope {
    /// Read an `intercept.scope` value: `"per-host"`, `"global"` or
    /// `"fixed:<name>"`, where a name is 1 to 64 of `A-Z a-z 0-9 _ . : -`
    /// (as `x-parda-scope` names are). Anything else is an error naming
    /// the valid values, so a typo never silently shares one scope.
    pub fn parse(value: &str) -> std::result::Result<InterceptScope, String> {
        let name_ok = |n: &str| {
            !n.is_empty()
                && n.len() <= 64
                && n.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c))
        };
        match value {
            INTERCEPT_SCOPE_PER_HOST => Ok(InterceptScope::PerHost),
            "global" => Ok(InterceptScope::Fixed("global".into())),
            v => match v.strip_prefix("fixed:") {
                Some(name) if name_ok(name) => Ok(InterceptScope::Fixed(name.into())),
                _ => Err(format!(
                    "invalid intercept.scope {value:?}: use \"per-host\" (the default, one \
                     vault scope per site), \"global\" or \"fixed:<name>\" (one scope for every \
                     site; a name is 1-64 of A-Z a-z 0-9 _ . : -)"
                )),
            },
        }
    }
}

/// Deserialize `intercept.scope`, refusing a value [`InterceptScope::parse`]
/// does not accept.
fn intercept_scope<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<String, D::Error> {
    let value = String::deserialize(d)?;
    InterceptScope::parse(&value).map_err(serde::de::Error::custom)?;
    Ok(value)
}

/// The AI sites intercepted by default.
pub const DEFAULT_INTERCEPT_HOSTS: [&str; 11] = [
    "chatgpt.com",
    "chat.openai.com",
    "claude.ai",
    "gemini.google.com",
    "copilot.microsoft.com",
    "perplexity.ai",
    "chat.deepseek.com",
    "chat.mistral.ai",
    "grok.com",
    "meta.ai",
    "poe.com",
];

/// System-wide HTTPS interception of AI sites (`parda intercept`). Tags
/// follow the global `replace.style`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InterceptConfig {
    pub enabled: bool,
    pub listen: String,
    /// Hosts decrypted and filtered (subdomains included); every other host
    /// is tunnelled untouched.
    pub hosts: Vec<String>,
    /// Vault scope for intercepted traffic. `per-host` (the default) gives
    /// each host its own scope, `intercept:<host>`, so a site's answers can
    /// only restore tags issued for text sent to that same host. `global`
    /// shares one scope across every site, the clipboard and the agent
    /// proxy; `fixed:<name>` one scope `<name>` across every site. Any
    /// other value is refused when the config loads ([`InterceptScope`]).
    #[serde(deserialize_with = "intercept_scope")]
    pub scope: String,
    /// Request parts parda cannot read (file uploads, binary bodies):
    /// forwarded with a warning (`allow`) or refused (`block`).
    pub unscanned: UnscannedMedia,
    /// Extra JSON / form keys that hold identifiers, on top of the built-in
    /// identifier keys: identifier-shaped values under them skip only the
    /// name model; the dictionary and rule tiers still apply (an e-mail
    /// under such a key is still redacted).
    pub skip_keys: Vec<String>,
}

impl Default for InterceptConfig {
    fn default() -> Self {
        InterceptConfig {
            enabled: false,
            listen: "127.0.0.1:8788".into(),
            hosts: DEFAULT_INTERCEPT_HOSTS.map(String::from).to_vec(),
            scope: INTERCEPT_SCOPE_PER_HOST.into(),
            unscanned: UnscannedMedia::Allow,
            skip_keys: Vec::new(),
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

    /// Custom-kind keys in `[detect.actions]` that look like a misspelt
    /// built-in kind (`Aadhar`, `Pasport`, `secrets`): within edit distance 2
    /// of a built-in name, ignoring case and separators, and less than half
    /// that name's length away (so short custom kinds like `Tag` are not
    /// flagged against `Pan`). Such a key is still a valid custom kind; this
    /// is for a warning at startup.
    pub fn suspicious_action_keys(&self) -> Vec<String> {
        let builtins: Vec<String> = EntityKind::all()
            .map(|k| crate::kind::fold(&k.to_string()))
            .collect();
        self.detect
            .actions
            .keys()
            .filter_map(|k| match k {
                EntityKind::Custom(name) => Some(name),
                _ => None,
            })
            .filter(|name| {
                let folded = crate::kind::fold(name);
                builtins.iter().any(|b| {
                    let d = edit_distance(&folded, b);
                    (1..=2).contains(&d) && 2 * d < b.chars().count()
                })
            })
            .cloned()
            .collect()
    }

    pub fn action_for(&self, kind: &EntityKind) -> Action {
        self.detect
            .actions
            .get(kind)
            .copied()
            .unwrap_or(Action::Redact)
    }
}

/// Levenshtein distance in characters.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = Vec::with_capacity(b.len() + 1);
        cur.push(i + 1);
        for (j, cb) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(ca != *cb);
            cur.push(sub.min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
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
        assert_eq!(c.replace.style, Style::Token);
        assert_eq!(c.vault.ttl_days, 30);
        assert!(c.clipboard.enabled);
        assert!(c.clipboard.restore_on_copy);
        assert_eq!(c.clipboard.poll_ms, 300);
        assert_eq!(c.clipboard.scope, "global");
        assert!(!c.privacy.log_values);
        assert!(c.protection.enabled);
    }

    #[test]
    fn passthrough_paths_default_to_none_and_parse() {
        let c = Config::from_toml_str("").unwrap();
        assert!(c.proxy.passthrough_paths.is_empty());
        let c = Config::from_toml_str("[proxy]\npassthrough_paths = [\"/api/*\", \"/v1/files\"]\n")
            .unwrap();
        assert_eq!(c.proxy.passthrough_paths, ["/api/*", "/v1/files"]);
        let again = Config::from_toml_str(&c.to_toml_string().unwrap()).unwrap();
        assert_eq!(again.proxy.passthrough_paths, c.proxy.passthrough_paths);
    }

    #[test]
    fn protection_switch_roundtrips() {
        let c = Config::from_toml_str("[protection]\nenabled = false\n").unwrap();
        assert!(!c.protection.enabled);
        let back = Config::from_toml_str(&c.to_toml_string().unwrap()).unwrap();
        assert!(!back.protection.enabled);
    }

    #[test]
    fn per_kind_action_override() {
        let c = Config::from_toml_str("[detect.actions]\nSecret = \"block\"\n").unwrap();
        assert_eq!(c.action_for(&EntityKind::Secret), Action::Block);
        assert_eq!(c.action_for(&EntityKind::Email), Action::Redact);
    }

    #[test]
    fn action_keys_ignore_case() {
        let c =
            Config::from_toml_str("[detect.actions]\nsecret = \"block\"\nip_address = \"warn\"\n")
                .unwrap();
        assert_eq!(c.action_for(&EntityKind::Secret), Action::Block);
        assert_eq!(c.action_for(&EntityKind::IpAddress), Action::Warn);
    }

    #[test]
    fn custom_action_keys_are_kept_as_written() {
        let c = Config::from_toml_str(
            "[detect.actions]\nCodename = \"block\"\n\"employee id\" = \"ignore\"\nsecret = \"warn\"\n",
        )
        .unwrap();
        assert_eq!(
            c.action_for(&EntityKind::Custom("Codename".into())),
            Action::Block
        );
        assert_eq!(
            c.action_for(&EntityKind::Custom("employee id".into())),
            Action::Ignore
        );
        assert_eq!(c.action_for(&EntityKind::Secret), Action::Warn);
        let back = Config::from_toml_str(&c.to_toml_string().unwrap()).unwrap();
        assert_eq!(back.detect.actions, c.detect.actions);
    }

    #[test]
    fn near_misses_of_builtin_names_are_reported() {
        let c = Config::from_toml_str(
            "[detect.actions]\nAadhar = \"block\"\nPasport = \"block\"\nsecrets = \"block\"\n\
             Emial = \"warn\"\nCodename = \"block\"\nEmployeeId = \"block\"\nHandle = \"ignore\"\n\
             Tag = \"ignore\"\nSecret = \"block\"\n",
        )
        .unwrap();
        let mut got = c.suspicious_action_keys();
        got.sort();
        assert_eq!(got, ["Aadhar", "Emial", "Pasport", "secrets"]);
        assert!(Config::default().suspicious_action_keys().is_empty());
    }

    #[test]
    fn edit_distances() {
        assert_eq!(edit_distance("aadhar", "aadhaar"), 1);
        assert_eq!(edit_distance("emial", "email"), 2);
        assert_eq!(edit_distance("", "pan"), 3);
        assert_eq!(edit_distance("secret", "secret"), 0);
    }

    #[test]
    fn roundtrip_toml() {
        let mut c = Config::default();
        c.detect.mode = Mode::Fast;
        c.replace.style = Style::Surrogate;
        let s = c.to_toml_string().unwrap();
        let back = Config::from_toml_str(&s).unwrap();
        assert_eq!(back.detect.mode, Mode::Fast);
        assert_eq!(back.replace.style, Style::Surrogate);
    }

    #[test]
    fn intercept_section_defaults_and_parses() {
        let c = Config::from_toml_str("").unwrap();
        assert!(!c.intercept.enabled);
        assert_eq!(c.intercept.listen, "127.0.0.1:8788");
        assert_eq!(
            c.intercept.hosts,
            [
                "chatgpt.com",
                "chat.openai.com",
                "claude.ai",
                "gemini.google.com",
                "copilot.microsoft.com",
                "perplexity.ai",
                "chat.deepseek.com",
                "chat.mistral.ai",
                "grok.com",
                "meta.ai",
                "poe.com",
            ]
        );
        assert_eq!(c.intercept.scope, "per-host");
        assert_eq!(c.intercept.unscanned, UnscannedMedia::Allow);
        assert!(c.intercept.skip_keys.is_empty());

        let c = Config::from_toml_str(
            "[intercept]\nenabled = true\nhosts = [\"chat.test\"]\nunscanned = \"block\"\n\
             skip_keys = [\"trace\"]\nscope = \"fixed:web\"\n",
        )
        .unwrap();
        assert!(c.intercept.enabled);
        assert_eq!(c.intercept.hosts, ["chat.test"]);
        assert_eq!(c.intercept.unscanned, UnscannedMedia::Block);
        assert_eq!(c.intercept.skip_keys, ["trace"]);
        assert_eq!(c.intercept.scope, "fixed:web");
        let back = Config::from_toml_str(&c.to_toml_string().unwrap()).unwrap();
        assert_eq!(back.intercept.hosts, c.intercept.hosts);
        assert_eq!(back.intercept.unscanned, UnscannedMedia::Block);
        // There is no per-surface style: `replace.style` applies everywhere.
        assert!(Config::from_toml_str("[intercept]\nstyle = \"token\"\n").is_err());
    }

    /// Review F4: a misspelt `intercept.scope` ("per_host", "perhost")
    /// was taken as a fixed scope name, silently sharing one scope across
    /// every site.
    #[test]
    fn intercept_scope_accepts_only_known_forms() {
        let load = |v: &str| Config::from_toml_str(&format!("[intercept]\nscope = {v:?}\n"));
        for (v, want) in [
            ("per-host", InterceptScope::PerHost),
            ("global", InterceptScope::Fixed("global".into())),
            ("fixed:web", InterceptScope::Fixed("web".into())),
            ("fixed:a.b_c-1:2", InterceptScope::Fixed("a.b_c-1:2".into())),
        ] {
            let c = load(v).unwrap_or_else(|e| panic!("{v}: {e}"));
            assert_eq!(c.intercept.scope, v);
            assert_eq!(InterceptScope::parse(&c.intercept.scope), Ok(want), "{v}");
        }
        assert_eq!(
            InterceptScope::parse(&InterceptConfig::default().scope),
            Ok(InterceptScope::PerHost)
        );
        for v in [
            "",
            "per_host",
            "perhost",
            "Per-Host",
            "per-host ",
            "GLOBAL",
            "web",
            "fixed:",
            "fixed: web",
            "fixed:a b",
            "fixed:a/b",
            "fixed:\u{e9}",
            &format!("fixed:{}", "x".repeat(65)),
        ] {
            let err = load(v).expect_err(v).to_string();
            for named in ["\"per-host\"", "\"global\"", "\"fixed:<name>\""] {
                assert!(err.contains(named), "{v:?}: {err}");
            }
            assert!(InterceptScope::parse(v).is_err(), "{v:?}");
        }
        assert!(Config::from_toml_str("[intercept]\nscope = 1\n").is_err());
        // A config written back loads again.
        let c = load("fixed:web").unwrap();
        let back = Config::from_toml_str(&c.to_toml_string().unwrap()).unwrap();
        assert_eq!(back.intercept.scope, "fixed:web");
    }

    #[test]
    fn unknown_field_is_error() {
        assert!(Config::from_toml_str("[proxy]\nlisten_typo = \"x\"\n").is_err());
    }
}
