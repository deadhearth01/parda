//! Every user-facing option of `config.toml` as a list row the Settings tab
//! can show and change: switches toggle, choices cycle (Enter/Space/click
//! forward, ←/right-click back), numbers and text open an inline editor
//! whose input is validated here before it goes to the daemon.

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
    ProxyListen,
    UnscannedMedia,
    Intercept,
    InterceptListen,
    InterceptUnscanned,
    Clipboard,
    Hotkey,
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
        Setting::ProxyListen,
        Setting::UnscannedMedia,
        Setting::Intercept,
        Setting::InterceptListen,
        Setting::InterceptUnscanned,
        Setting::Clipboard,
        Setting::Hotkey,
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
                Style::Token => "tags like [NAME_1]".into(),
            };
            r.help = "Tags show exactly what was hidden (Ravi Kumar → [NAME_1]); realistic stand-ins (→ Arjun Mehta) read more naturally to the AI.";
        }
        Setting::Proxy => {
            r.group = "agents";
            r.label = format!("agent proxy ({})", c.proxy.listen);
            (r.value, r.on) = switch(c.proxy.enabled);
            r.help = "Local API endpoint for Claude Code, Codex and SDKs (ANTHROPIC_BASE_URL / OPENAI_BASE_URL).";
            r.restart = true;
        }
        Setting::ProxyListen => {
            r.group = "agents";
            r.label = "agent proxy address".into();
            r.value = c.proxy.listen.clone();
            r.help = "Where the agent proxy listens (a loopback address such as 127.0.0.1:8787). Enter edits it.";
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
        Setting::Intercept => {
            r.group = "AI sites";
            r.label = format!(
                "filter AI sites in browsers & apps ({})",
                c.intercept.listen
            );
            (r.value, r.on) = switch(c.intercept.enabled);
            r.help = "Filters ChatGPT, Claude, Gemini … in browsers and desktop apps; applies at once. Set up: `parda ca create`, `parda ca install`, `parda intercept on`. Undo all: `parda intercept off`.";
        }
        Setting::InterceptListen => {
            r.group = "AI sites";
            r.label = "intercept listener address".into();
            r.value = c.intercept.listen.clone();
            r.help = "Where the AI-site listener runs (loopback only). It moves at once; run `parda intercept on` again so the system proxy follows.";
        }
        Setting::InterceptUnscanned => {
            r.group = "AI sites";
            r.label = "files & images sent to AI sites".into();
            r.value = match c.intercept.unscanned {
                UnscannedMedia::Allow => "allow (not scanned)".into(),
                UnscannedMedia::Block => "block".into(),
            };
            r.help = "parda cannot read text inside uploaded files or images: allow sends them unscanned (with a warning), block refuses the upload.";
        }
        Setting::Clipboard => {
            r.group = "chat apps";
            r.label = format!("clipboard & paste-safe hotkey ({})", c.clipboard.hotkey);
            (r.value, r.on) = switch(c.clipboard.enabled);
            r.help = "Copy text, then press the hotkey instead of paste to paste a redacted version into any app.";
            r.restart = true;
        }
        Setting::Hotkey => {
            r.group = "chat apps";
            r.label = "paste-safe hotkey".into();
            r.value = c.clipboard.hotkey.clone();
            r.help = "`default` is Cmd+Alt+V on macOS and Ctrl+Alt+V elsewhere; or type one such as ctrl+shift+v.";
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
            r.help = "The ML tier finds names and addresses rules cannot. ←/→ switch default/none, Enter types an id (`parda model list`).";
            r.restart = true;
        }
        Setting::Threshold => {
            r.group = "detection";
            r.label = "model confidence threshold".into();
            r.value = format!("{:.2}", c.detect.ml_threshold);
            r.help = "Lower finds more names (and more false alarms); higher is stricter. 0.30–0.95, applies at once. Enter types a value, ←/→ step.";
        }
        Setting::Timeout => {
            r.group = "detection";
            r.label = "model time budget".into();
            r.value = format!("{} ms", c.detect.ml_timeout_ms);
            r.help = "How long a request may wait for the name model before strict/fast mode decides (10–60000 ms). Enter types a value.";
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
            r.help = "Older real ⇄ stand-in pairs are deleted; answers mentioning them can no longer be restored (1–3650 days). Enter types a value.";
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

/// How a setting is changed in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edit {
    /// ON/OFF: Enter, Space or a click flips it.
    Toggle,
    /// One of a few choices: Enter/Space/→ next, ← previous.
    Cycle,
    /// A number typed into the inline editor (←/→ step through presets).
    Number,
    /// Free text typed into the inline editor.
    Text,
}

pub fn edit_kind(s: &Setting) -> Edit {
    match s {
        Setting::Protection
        | Setting::Proxy
        | Setting::Intercept
        | Setting::Clipboard
        | Setting::RestoreOnCopy
        | Setting::Dates
        | Setting::Pack(_)
        | Setting::LogValues => Edit::Toggle,
        Setting::Mode
        | Setting::Style
        | Setting::UnscannedMedia
        | Setting::InterceptUnscanned
        | Setting::Action(_) => Edit::Cycle,
        Setting::Threshold | Setting::Timeout | Setting::Ttl => Edit::Number,
        Setting::Model | Setting::ProxyListen | Setting::InterceptListen | Setting::Hotkey => {
            Edit::Text
        }
    }
}

/// Whether ←/→ ([`step`]) changes this setting (text-only ones need the editor).
pub fn cycles(s: &Setting) -> bool {
    !matches!(
        s,
        Setting::ProxyListen | Setting::InterceptListen | Setting::Hotkey
    )
}

/// The current value as the inline editor starts with it.
pub fn raw_value(s: &Setting, c: &Config) -> String {
    match s {
        Setting::Threshold => format!("{:.2}", c.detect.ml_threshold),
        Setting::Timeout => c.detect.ml_timeout_ms.to_string(),
        Setting::Ttl => c.vault.ttl_days.to_string(),
        Setting::Model => c.detect.model.clone(),
        Setting::ProxyListen => c.proxy.listen.clone(),
        Setting::InterceptListen => c.intercept.listen.clone(),
        Setting::Hotkey => c.clipboard.hotkey.clone(),
        other => row(other, c).value,
    }
}

fn int_in<T: std::str::FromStr + PartialOrd + std::fmt::Display>(
    v: &str,
    lo: T,
    hi: T,
    unit: &str,
) -> Result<T, String> {
    match v.parse::<T>() {
        Ok(n) if n >= lo && n <= hi => Ok(n),
        _ => Err(format!("enter a whole number from {lo} to {hi}{unit}")),
    }
}

fn loopback(v: &str) -> Result<String, String> {
    match v.parse::<std::net::SocketAddr>() {
        Ok(a) if a.ip().is_loopback() => Ok(a.to_string()),
        Ok(_) => Err("use a loopback address (127.0.0.1:PORT or [::1]:PORT)".into()),
        Err(_) => Err("enter an address like 127.0.0.1:8787".into()),
    }
}

/// Validate `input` for `s` and store it in `c`; on error `c` is unchanged
/// and the message says what is accepted.
pub fn apply_text(s: &Setting, c: &mut Config, input: &str) -> Result<(), String> {
    let v = input.trim();
    match s {
        Setting::Threshold => match v.parse::<f32>() {
            Ok(t) if (0.3..=0.95).contains(&t) => c.detect.ml_threshold = t,
            _ => return Err("enter a number from 0.30 to 0.95".into()),
        },
        Setting::Timeout => c.detect.ml_timeout_ms = int_in(v, 10u64, 60_000, " ms")?,
        Setting::Ttl => c.vault.ttl_days = int_in(v, 1u32, 3650, " days")?,
        Setting::Model => {
            let ok = !v.is_empty()
                && v.chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || "._-".contains(ch));
            if !ok {
                return Err("a model id has letters, digits, '.', '_' or '-' only".into());
            }
            c.detect.model = v.to_string();
        }
        Setting::ProxyListen => c.proxy.listen = loopback(v)?,
        Setting::InterceptListen => c.intercept.listen = loopback(v)?,
        Setting::Hotkey => {
            if v.is_empty() || v.chars().any(char::is_whitespace) || v.len() > 40 {
                return Err("enter `default` or keys joined by '+', e.g. ctrl+shift+v".into());
            }
            c.clipboard.hotkey = v.to_string();
        }
        _ => return Err("this setting is switched, not typed".into()),
    }
    Ok(())
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
        Setting::ProxyListen | Setting::InterceptListen | Setting::Hotkey => {}
        Setting::UnscannedMedia => {
            c.proxy.unscanned_media = match c.proxy.unscanned_media {
                UnscannedMedia::Allow => UnscannedMedia::Block,
                UnscannedMedia::Block => UnscannedMedia::Allow,
            }
        }
        Setting::Intercept => c.intercept.enabled = !c.intercept.enabled,
        Setting::InterceptUnscanned => {
            c.intercept.unscanned = match c.intercept.unscanned {
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
        for s in all()
            .into_iter()
            .filter(|s| edit_kind(s) != Edit::Text || cycles(s))
        {
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
    fn model_threshold_applies_live() {
        // The daemon decodes at a 0.3 floor and the engine filters by the
        // configured threshold, so every offered value applies at once.
        let r = row(&Setting::Threshold, &Config::default());
        assert!(!r.restart);
        assert!(THRESHOLDS.iter().all(|t| *t >= 0.3));
    }

    #[test]
    fn intercept_rows_apply_live_and_toggle_the_config() {
        let mut c = Config::default();
        let r = row(&Setting::Intercept, &c);
        assert_eq!(r.on, Some(false));
        assert!(r.label.contains("127.0.0.1:8788"), "{}", r.label);
        assert!(!r.restart, "the daemon starts and stops the listener live");
        assert!(r.help.contains("parda intercept on"), "{}", r.help);
        step(&Setting::Intercept, &mut c, true);
        assert!(c.intercept.enabled);
        assert_eq!(row(&Setting::Intercept, &c).on, Some(true));

        let r = row(&Setting::InterceptUnscanned, &c);
        assert!(!r.restart);
        assert!(r.value.starts_with("allow"), "{}", r.value);
        step(&Setting::InterceptUnscanned, &mut c, true);
        assert_eq!(c.intercept.unscanned, UnscannedMedia::Block);
        // The agent proxy's own rule is a separate setting.
        assert_eq!(c.proxy.unscanned_media, UnscannedMedia::Allow);
    }

    #[test]
    fn log_values_on_needs_confirmation_but_off_does_not() {
        let mut c = Config::default();
        assert!(needs_confirm(&Setting::LogValues, &c));
        c.privacy.log_values = true;
        assert!(!needs_confirm(&Setting::LogValues, &c));
        assert!(!needs_confirm(&Setting::Protection, &c));
    }

    #[test]
    fn edit_kinds_cover_bools_enums_numbers_and_text() {
        assert_eq!(edit_kind(&Setting::Protection), Edit::Toggle);
        assert_eq!(edit_kind(&Setting::Mode), Edit::Cycle);
        assert_eq!(edit_kind(&Setting::Action(EntityKind::Email)), Edit::Cycle);
        assert_eq!(edit_kind(&Setting::Threshold), Edit::Number);
        assert_eq!(edit_kind(&Setting::Timeout), Edit::Number);
        assert_eq!(edit_kind(&Setting::Ttl), Edit::Number);
        assert_eq!(edit_kind(&Setting::Model), Edit::Text);
        assert_eq!(edit_kind(&Setting::ProxyListen), Edit::Text);
        assert_eq!(edit_kind(&Setting::InterceptListen), Edit::Text);
        assert_eq!(edit_kind(&Setting::Hotkey), Edit::Text);
        // Every editable setting starts the editor with its current value.
        let c = Config::default();
        for s in all() {
            if matches!(edit_kind(&s), Edit::Number | Edit::Text) {
                let v = raw_value(&s, &c);
                assert!(!v.is_empty(), "{s:?}");
                let mut c2 = c.clone();
                assert_eq!(
                    apply_text(&s, &mut c2, &v),
                    Ok(()),
                    "{s:?} rejects its own value"
                );
                assert_eq!(c2.to_toml_string().unwrap(), c.to_toml_string().unwrap());
            }
        }
    }

    #[test]
    fn inline_values_are_validated() {
        let mut c = Config::default();
        assert_eq!(apply_text(&Setting::Threshold, &mut c, " 0.42 "), Ok(()));
        assert!((c.detect.ml_threshold - 0.42).abs() < 1e-6);
        for bad in ["abc", "0.1", "1.5", "", "NaN"] {
            assert!(
                apply_text(&Setting::Threshold, &mut c, bad).is_err(),
                "{bad:?}"
            );
        }
        assert!(
            (c.detect.ml_threshold - 0.42).abs() < 1e-6,
            "a bad value changes nothing"
        );
        assert_eq!(apply_text(&Setting::Timeout, &mut c, "750"), Ok(()));
        assert_eq!(c.detect.ml_timeout_ms, 750);
        assert!(apply_text(&Setting::Timeout, &mut c, "0").is_err());
        assert!(apply_text(&Setting::Timeout, &mut c, "-5").is_err());
        assert_eq!(apply_text(&Setting::Ttl, &mut c, "14"), Ok(()));
        assert_eq!(c.vault.ttl_days, 14);
        assert!(apply_text(&Setting::Ttl, &mut c, "99999").is_err());
        assert_eq!(
            apply_text(&Setting::ProxyListen, &mut c, "127.0.0.1:9000"),
            Ok(())
        );
        assert_eq!(c.proxy.listen, "127.0.0.1:9000");
        let e = apply_text(&Setting::ProxyListen, &mut c, "0.0.0.0:9000").unwrap_err();
        assert!(e.contains("loopback"), "{e}");
        assert!(apply_text(&Setting::InterceptListen, &mut c, "localhost").is_err());
        assert_eq!(
            apply_text(&Setting::InterceptListen, &mut c, "[::1]:8790"),
            Ok(())
        );
        assert_eq!(c.intercept.listen, "[::1]:8790");
        assert!(apply_text(&Setting::Model, &mut c, "two words").is_err());
        assert_eq!(apply_text(&Setting::Model, &mut c, "none"), Ok(()));
        assert_eq!(c.detect.model, "none");
        assert!(apply_text(&Setting::Hotkey, &mut c, "  ").is_err());
        assert_eq!(apply_text(&Setting::Hotkey, &mut c, "ctrl+alt+v"), Ok(()));
        assert_eq!(c.clipboard.hotkey, "ctrl+alt+v");
        // Bools and enums are not typed in.
        assert!(apply_text(&Setting::Protection, &mut c, "on").is_err());
    }

    #[test]
    fn address_rows_say_they_need_a_restart_where_the_daemon_does() {
        let c = Config::default();
        assert!(row(&Setting::ProxyListen, &c).restart);
        assert!(!row(&Setting::InterceptListen, &c).restart);
        assert!(row(&Setting::Hotkey, &c).restart);
        assert_eq!(row(&Setting::ProxyListen, &c).value, "127.0.0.1:8787");
    }
}
