//! Every user-facing option of `config.toml` as a list row the Settings tab
//! can show and change (Enter/Space/click cycles forward, ←/right-click back).

use parda_core::{Action, Config, EntityKind, Mode, Style, UnscannedMedia};

pub const PACKS: [&str; 4] = ["global", "india", "us_uk", "secrets"];
const THRESHOLDS: [f32; 8] = [0.3, 0.35, 0.4, 0.45, 0.5, 0.55, 0.6, 0.7];
const TIMEOUTS_MS: [u64; 5] = [100, 250, 500, 1000, 2000];
const TTL_DAYS: [u32; 6] = [1, 7, 30, 90, 180, 365];
const ACTIONS: [Action; 4] = [Action::Redact, Action::Block, Action::Warn, Action::Ignore];

#[derive(Debug, Clone, PartialEq)]
pub enum Setting {
    Protection,
    Mode,
    Style,
    Proxy,
    UnscannedMedia,
    Clipboard,
    RestoreOnCopy,
    Model,
    Threshold,
    Timeout,
    Dates,
    Pack(&'static str),
    Ttl,
    LogValues,
    Action(EntityKind),
}

/// One rendered row.
#[derive(Debug, Clone)]
pub struct Row {
    pub group: &'static str,
    pub label: String,
    pub value: String,
    /// `Some(true)` on, `Some(false)` off, `None` for multi-valued settings.
    pub on: Option<bool>,
    pub help: &'static str,
    /// The daemon must restart before the change takes effect.
    pub restart: bool,
    /// Turning this on weakens privacy.
    pub risky: bool,
}

/// Every setting, in display order.
pub fn all() -> Vec<Setting> {
    let mut v = vec![
        Setting::Protection,
        Setting::Mode,
        Setting::Style,
        Setting::Proxy,
        Setting::UnscannedMedia,
        Setting::Clipboard,
        Setting::RestoreOnCopy,
        Setting::Model,
        Setting::Threshold,
        Setting::Timeout,
        Setting::Dates,
    ];
    v.extend(PACKS.iter().map(|p| Setting::Pack(p)));
    v.push(Setting::Ttl);
    v.push(Setting::LogValues);
    v.extend(EntityKind::all().map(Setting::Action));
    v
}

fn switch(on: bool) -> (String, Option<bool>) {
    (if on { "ON" } else { "OFF" }.to_string(), Some(on))
}

pub fn row(s: &Setting, c: &Config) -> Row {
    let mut r = Row {
        group: "",
        label: String::new(),
        value: String::new(),
        on: None,
        help: "",
        restart: false,
        risky: false,
    };
    match s {
        Setting::Protection => {
            r.group = "general";
            r.label = "protection".into();
            (r.value, r.on) = switch(c.protection.enabled);
            r.help = "Master switch. OFF sends text as typed on every surface (answers are still restored). Also: p anywhere.";
        }
        Setting::Mode => {
            r.group = "general";
            r.label = "when the model fails".into();
            r.value = match c.detect.mode {
                Mode::Strict => "strict — refuse".into(),
                Mode::Fast => "fast — rules only".into(),
            };
            r.help = "strict refuses a request if the name model errors or times out; fast sends it with format rules only.";
        }
        Setting::Style => {
            r.group = "general";
            r.label = "replacement style".into();
            r.value = match c.replace.style {
                Style::Surrogate => "realistic stand-ins".into(),
                Style::Token => "⟦TOKENS⟧".into(),
            };
            r.help = "Stand-ins read naturally (Ravi Kumar → Arjun Mehta); tokens make every replacement obvious.";
        }
        Setting::Proxy => {
            r.group = "agents";
            r.label = format!("agent proxy ({})", c.proxy.listen);
            (r.value, r.on) = switch(c.proxy.enabled);
            r.help = "Local API endpoint for Claude Code, Codex and SDKs (ANTHROPIC_BASE_URL / OPENAI_BASE_URL).";
            r.restart = true;
        }
        Setting::UnscannedMedia => {
            r.group = "agents";
            r.label = "images & PDFs in requests".into();
            r.value = match c.proxy.unscanned_media {
                UnscannedMedia::Allow => "allow (not scanned)".into(),
                UnscannedMedia::Block => "block".into(),
            };
            r.help = "v0.1 cannot read text inside images or documents: allow forwards them unscanned, block refuses the request.";
        }
        Setting::Clipboard => {
            r.group = "chat apps";
            r.label = format!("clipboard & paste-safe hotkey ({})", c.clipboard.hotkey);
            (r.value, r.on) = switch(c.clipboard.enabled);
            r.help = "Copy text, then press the hotkey instead of paste to paste a redacted version into any app.";
            r.restart = true;
        }
        Setting::RestoreOnCopy => {
            r.group = "chat apps";
            r.label = "restore real values when copying answers".into();
            (r.value, r.on) = switch(c.clipboard.restore_on_copy);
            r.help = "Copying an AI answer that contains stand-ins puts the real names back on the clipboard.";
        }
        Setting::Model => {
            r.group = "detection";
            r.label = "name model".into();
            r.value = match c.detect.model.as_str() {
                "none" => "none — rules & dictionary only".into(),
                m => m.to_string(),
            };
            r.on = Some(c.detect.model != "none");
            r.help = "The ML tier finds names and addresses rules cannot. `parda model list` shows installed models.";
            r.restart = true;
        }
        Setting::Threshold => {
            r.group = "detection";
            r.label = "model confidence threshold".into();
            r.value = format!("{:.2}", c.detect.ml_threshold);
            r.help = "Lower finds more names (and more false alarms); higher is stricter about what counts as a name. A higher value applies at once; a lower one after a daemon restart.";
            r.restart = true;
        }
        Setting::Timeout => {
            r.group = "detection";
            r.label = "model time budget".into();
            r.value = format!("{} ms", c.detect.ml_timeout_ms);
            r.help =
                "How long a request may wait for the name model before strict/fast mode decides.";
        }
        Setting::Dates => {
            r.group = "detection";
            r.label = "redact all dates".into();
            (r.value, r.on) = switch(c.detect.dates);
            r.help =
                "Off: only dates next to 'DOB' / 'date of birth' / 'जन्म' are treated as personal.";
        }
        Setting::Pack(p) => {
            r.group = "rule packs";
            r.label = match *p {
                "global" => "global (email, phone, cards, IBAN, IP …)".into(),
                "india" => "india (Aadhaar, PAN, GSTIN, UPI, IFSC …)".into(),
                "us_uk" => "us_uk (SSN, NINO)".into(),
                _ => "secrets (API keys, tokens, private keys)".into(),
            };
            (r.value, r.on) = switch(c.detect.packs.iter().any(|x| x == p));
            r.help = "Checksum-validated format rules. Turning a pack off lets those identifiers through.";
        }
        Setting::Ttl => {
            r.group = "vault";
            r.label = "forget mappings after".into();
            r.value = format!("{} days", c.vault.ttl_days);
            r.help = "Older real ⇄ stand-in pairs are deleted; answers mentioning them can no longer be restored.";
        }
        Setting::LogValues => {
            r.group = "privacy";
            r.label = "write real values to logs".into();
            (r.value, r.on) = switch(c.privacy.log_values);
            r.help = "Debugging only: logs and events then contain personal data in plain text. Asks before turning on.";
            r.risky = true;
        }
        Setting::Action(k) => {
            r.group = "per kind";
            r.label = k.to_string();
            let a = c.action_for(k);
            r.value = action_label(a).into();
            r.on = Some(a == Action::Redact);
            r.help = "redact replaces it · block refuses to send · warn sends it and logs a warning · ignore sends it silently.";
        }
    }
    r
}

fn action_label(a: Action) -> &'static str {
    match a {
        Action::Redact => "redact",
        Action::Block => "block",
        Action::Warn => "warn",
        Action::Ignore => "ignore",
    }
}

fn cycle<T: PartialEq + Copy>(list: &[T], current: T, forward: bool) -> T {
    let n = list.len();
    let i = list.iter().position(|x| *x == current);
    let next = match (i, forward) {
        (Some(i), true) => (i + 1) % n,
        (Some(i), false) => (i + n - 1) % n,
        (None, true) => 0,
        (None, false) => n - 1,
    };
    list[next]
}

fn cycle_f32(list: &[f32], current: f32, forward: bool) -> f32 {
    // Snap to the nearest listed value first so hand-edited values cycle too.
    let nearest = list
        .iter()
        .copied()
        .min_by(|a, b| (a - current).abs().total_cmp(&(b - current).abs()))
        .unwrap_or(current);
    if (nearest - current).abs() > 1e-6 {
        return nearest;
    }
    cycle(list, nearest, forward)
}

/// Whether changing this setting needs a confirmation first.
pub fn needs_confirm(s: &Setting, c: &Config) -> bool {
    matches!(s, Setting::LogValues) && !c.privacy.log_values
}

/// Change `s` to its next (or previous) value.
pub fn step(s: &Setting, c: &mut Config, forward: bool) {
    match s {
        Setting::Protection => c.protection.enabled = !c.protection.enabled,
        Setting::Mode => {
            c.detect.mode = match c.detect.mode {
                Mode::Strict => Mode::Fast,
                Mode::Fast => Mode::Strict,
            }
        }
        Setting::Style => {
            c.replace.style = match c.replace.style {
                Style::Surrogate => Style::Token,
                Style::Token => Style::Surrogate,
            }
        }
        Setting::Proxy => c.proxy.enabled = !c.proxy.enabled,
        Setting::UnscannedMedia => {
            c.proxy.unscanned_media = match c.proxy.unscanned_media {
                UnscannedMedia::Allow => UnscannedMedia::Block,
                UnscannedMedia::Block => UnscannedMedia::Allow,
            }
        }
        Setting::Clipboard => c.clipboard.enabled = !c.clipboard.enabled,
        Setting::RestoreOnCopy => c.clipboard.restore_on_copy = !c.clipboard.restore_on_copy,
        Setting::Model => {
            let mut options = vec!["default".to_string(), "none".to_string()];
            if !options.contains(&c.detect.model) {
                options.insert(0, c.detect.model.clone());
            }
            let i = options
                .iter()
                .position(|m| *m == c.detect.model)
                .unwrap_or(0);
            let n = options.len();
            let next = if forward {
                (i + 1) % n
            } else {
                (i + n - 1) % n
            };
            c.detect.model = options[next].clone();
        }
        Setting::Threshold => {
            c.detect.ml_threshold = cycle_f32(&THRESHOLDS, c.detect.ml_threshold, forward)
        }
        Setting::Timeout => {
            c.detect.ml_timeout_ms = cycle(&TIMEOUTS_MS, c.detect.ml_timeout_ms, forward)
        }
        Setting::Dates => c.detect.dates = !c.detect.dates,
        Setting::Pack(p) => {
            if let Some(i) = c.detect.packs.iter().position(|x| x == p) {
                c.detect.packs.remove(i);
            } else {
                c.detect.packs.push((*p).to_string());
                // Keep the canonical order so config.toml diffs stay small.
                c.detect
                    .packs
                    .sort_by_key(|x| PACKS.iter().position(|p| p == x).unwrap_or(usize::MAX));
            }
        }
        Setting::Ttl => c.vault.ttl_days = cycle(&TTL_DAYS, c.vault.ttl_days, forward),
        Setting::LogValues => c.privacy.log_values = !c.privacy.log_values,
        Setting::Action(k) => {
            let next = cycle(&ACTIONS, c.action_for(k), forward);
            if next == Action::Redact {
                c.detect.actions.remove(k);
            } else {
                c.detect.actions.insert(k.clone(), next);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_setting_renders_and_cycles_back_to_start() {
        let base = Config::default();
        for s in all() {
            let before = base.to_toml_string().unwrap();
            let mut c = base.clone();
            let r = row(&s, &c);
            assert!(
                !r.label.is_empty() && !r.value.is_empty() && !r.help.is_empty(),
                "{s:?}"
            );
            // Forward then backward returns to the start.
            step(&s, &mut c, true);
            assert_ne!(c.to_toml_string().unwrap(), before, "{s:?} did not change");
            step(&s, &mut c, false);
            assert_eq!(
                c.to_toml_string().unwrap(),
                before,
                "{s:?} did not cycle back"
            );
        }
    }

    #[test]
    fn packs_toggle_in_canonical_order() {
        let mut c = Config::default();
        step(&Setting::Pack("india"), &mut c, true);
        assert_eq!(c.detect.packs, ["global", "us_uk", "secrets"]);
        step(&Setting::Pack("india"), &mut c, true);
        assert_eq!(c.detect.packs, ["global", "india", "us_uk", "secrets"]);
    }

    #[test]
    fn per_kind_action_cycles_and_default_is_not_stored() {
        let mut c = Config::default();
        let s = Setting::Action(EntityKind::Secret);
        step(&s, &mut c, true);
        assert_eq!(c.action_for(&EntityKind::Secret), Action::Block);
        for _ in 0..3 {
            step(&s, &mut c, true);
        }
        assert_eq!(c.action_for(&EntityKind::Secret), Action::Redact);
        assert!(c.detect.actions.is_empty());
    }

    #[test]
    fn model_threshold_is_marked_restart_required() {
        // The model is loaded with the threshold; a lower value only takes
        // effect after the daemon reloads it.
        let r = row(&Setting::Threshold, &Config::default());
        assert!(r.restart);
        assert!(r.help.contains("restart"), "{}", r.help);
    }

    #[test]
    fn log_values_on_needs_confirmation_but_off_does_not() {
        let mut c = Config::default();
        assert!(needs_confirm(&Setting::LogValues, &c));
        c.privacy.log_values = true;
        assert!(!needs_confirm(&Setting::LogValues, &c));
        assert!(!needs_confirm(&Setting::Protection, &c));
    }
}
