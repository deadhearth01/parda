//! Compiled recognizers. Findings may overlap; the engine applies core's merge policy.
mod global;
mod india;
mod keyed;
mod secrets;
mod us_uk;

use crate::Detector;
use parda_core::{Detection, EntityKind, Source, Span};
use regex::Regex;

struct Rule {
    kind: EntityKind,
    regex: Regex,
    validator: Option<fn(&str) -> bool>,
    context: &'static [&'static str],
    base: f32,
}
impl Rule {
    fn new(
        kind: EntityKind,
        pattern: &str,
        validator: Option<fn(&str) -> bool>,
        context: &'static [&'static str],
        base: f32,
    ) -> Self {
        Self {
            kind,
            regex: Regex::new(pattern).expect("built-in rule regex"),
            validator,
            context,
            base,
        }
    }
}

pub struct RuleDetector {
    rules: Vec<Rule>,
    dates: bool,
}
impl RuleDetector {
    pub fn new(packs: &[String], dates: bool) -> Self {
        let mut rules = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for pack in packs {
            if !seen.insert(pack.as_str()) {
                continue;
            }
            match pack.as_str() {
                "global" => {
                    rules.extend(global::rules());
                    rules.extend(keyed::global());
                }
                "india" => {
                    rules.extend(india::rules());
                    rules.extend(keyed::india());
                }
                "us_uk" => {
                    rules.extend(us_uk::rules());
                    rules.extend(keyed::us_uk());
                }
                "secrets" => rules.extend(secrets::rules()),
                _ => tracing::warn!(pack, "unknown rule pack; ignoring"),
            }
        }
        Self { rules, dates }
    }
}

/// An alphanumeric/underscore next to a rule match means it is part of a token.
fn bounded(text: &str, start: usize, end: usize) -> bool {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    !text[..start].chars().next_back().is_some_and(word)
        && !text[end..].chars().next().is_some_and(word)
}

/// Byte-limited context, rounded inward to preserve UTF-8 boundaries.
fn has_context(text: &str, start: usize, window: usize, words: &[&str]) -> bool {
    let mut from = start.saturating_sub(window);
    while !text.is_char_boundary(from) {
        from += 1;
    }
    let before = &text[from..start];
    // ASCII folding preserves byte offsets, including for Devanagari context.
    let folded = before.to_ascii_lowercase();
    words.iter().any(|word| {
        folded
            .match_indices(word)
            .any(|(i, _)| bounded(text, from + i, from + i + word.len()))
    })
}

impl Detector for RuleDetector {
    fn name(&self) -> &str {
        "rules"
    }
    fn detect(&self, text: &str) -> Vec<Detection> {
        let mut found = Vec::new();
        for rule in &self.rules {
            for captures in rule.regex.captures_iter(text) {
                let m = captures
                    .name("value")
                    .unwrap_or_else(|| captures.get(0).expect("whole match"));
                let (start, mut end) = (m.start(), m.end());
                if rule.kind == EntityKind::Url {
                    end = start
                        + m.as_str()
                            .trim_end_matches(['.', ',', ';', '!', '?', ')', ']', '}'])
                            .len();
                }
                if rule.kind == EntityKind::Iban {
                    // An uppercase word after a spaced IBAN can be consumed by
                    // the candidate regex. Find the longest valid bounded prefix.
                    let candidate_end = (start..=end).rev().find(|&e| {
                        text.is_char_boundary(e)
                            && bounded(text, start, e)
                            && parda_core::validators::iban(&text[start..e])
                    });
                    let Some(e) = candidate_end else {
                        continue;
                    };
                    end = e;
                }
                if rule.kind == EntityKind::Secret
                    && rule.validator.is_some()
                    && !has_context(text, start, 40, rule.context)
                {
                    continue;
                }
                if !bounded(text, start, end) {
                    continue;
                }
                if rule.kind == EntityKind::DateOfBirth
                    && !self.dates
                    && !has_context(text, start, 20, global::DOB_CONTEXT)
                {
                    continue;
                }
                if rule.kind == EntityKind::IpAddress {
                    if has_context(text, start, 40, &["version"]) {
                        continue;
                    }
                    // Don't accept a valid substring of a malformed address.
                    if text[..start].ends_with(['.', ':'])
                        || text[end..].starts_with(':')
                        || (text[end..].starts_with('.')
                            && text[end + 1..]
                                .chars()
                                .next()
                                .is_some_and(|c| c.is_ascii_digit()))
                    {
                        continue;
                    }
                }
                if rule.kind == EntityKind::Upi
                    && text[end..].starts_with('.')
                    && text[end + 1..]
                        .chars()
                        .next()
                        .is_some_and(char::is_alphanumeric)
                {
                    continue;
                }
                let normalized;
                let value = if matches!(
                    rule.kind,
                    EntityKind::Aadhaar | EntityKind::CreditCard | EntityKind::Phone
                ) {
                    normalized = text[start..end].replace([' ', '-'], "");
                    normalized.as_str()
                } else {
                    &text[start..end]
                };
                if rule.validator.is_some_and(|validate| !validate(value)) {
                    continue;
                }
                let boost = if has_context(text, start, 40, rule.context) {
                    0.2
                } else {
                    0.0
                };
                found.push(Detection {
                    span: Span { start, end },
                    kind: rule.kind.clone(),
                    score: (rule.base + boost).min(1.0),
                    source: Source::Rule {
                        validated: rule.validator.is_some(),
                    },
                });
            }
        }
        found.sort_by(|a, b| {
            (a.span, &a.kind)
                .cmp(&(b.span, &b.kind))
                .then(b.source.rank().cmp(&a.source.rank()))
                .then(b.score.total_cmp(&a.score))
        });
        found.dedup_by(|a, b| a.span == b.span && a.kind == b.kind);
        found
    }
}
