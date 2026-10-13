//! Finding surrogates in text and mapping them back to real values.
//!
//! One Aho-Corasick automaton per scope over the lower-cased surrogates
//! (leftmost-longest, ASCII case-insensitive). A match counts only at word
//! boundaries; when the longest match at a position fails that test, shorter
//! surrogates starting at the same position are tried. The replacement keeps
//! the case the model used (`ARJUN` → `RAVI`).

use aho_corasick::{AhoCorasick, Input, MatchKind};
use parda_core::EntityKind;
use parda_vault::surrogate::apply_case;

/// A vault mapping as held in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub surrogate: String,
    pub real: String,
    pub kind: EntityKind,
}

/// Kinds whose values are written in any case (names, e-mail addresses…):
/// a surrogate echoed in another case still restores, re-cased.
pub(crate) fn case_insensitive(kind: &EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::Person
            | EntityKind::Email
            | EntityKind::Upi
            | EntityKind::Organization
            | EntityKind::Address
            | EntityKind::Custom(_)
    )
}

/// A surrogate occurrence: byte span and pattern id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Found {
    pub start: usize,
    pub end: usize,
    pub pattern: usize,
}

pub(crate) struct RestoreTable {
    ac: Option<AhoCorasick>,
    /// Per pattern: every mapping whose surrogate lower-cases to it.
    targets: Vec<Vec<Entry>>,
    /// Per pattern: does it start / end with a letter or digit?
    alnum_edges: Vec<(bool, bool)>,
    /// Lower-cased patterns, sorted, for prefix queries.
    sorted: Vec<String>,
    max_len: usize,
}

impl RestoreTable {
    pub(crate) fn build<'a>(entries: impl IntoIterator<Item = &'a Entry>) -> Self {
        let mut by_pattern: std::collections::BTreeMap<String, Vec<Entry>> = Default::default();
        for e in entries {
            if e.surrogate.is_empty() {
                continue;
            }
            by_pattern
                .entry(e.surrogate.to_ascii_lowercase())
                .or_default()
                .push(e.clone());
        }
        let patterns: Vec<String> = by_pattern.keys().cloned().collect();
        let targets: Vec<Vec<Entry>> = by_pattern.into_values().collect();
        let alnum_edges = patterns
            .iter()
            .map(|p| {
                (
                    p.chars().next().is_some_and(char::is_alphanumeric),
                    p.chars().next_back().is_some_and(char::is_alphanumeric),
                )
            })
            .collect();
        let max_len = patterns.iter().map(String::len).max().unwrap_or(0);
        let ac = if patterns.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .ascii_case_insensitive(true)
                .build(&patterns)
                .map_err(|e| tracing::error!(error = %e, "cannot build restore automaton"))
                .ok()
        };
        // BTreeMap keys are already sorted.
        RestoreTable {
            ac,
            targets,
            alnum_edges,
            sorted: patterns,
            max_len,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ac.is_none()
    }

    /// Is `s` (ignoring ASCII case) one of the surrogates?
    pub(crate) fn contains(&self, s: &str) -> bool {
        self.sorted.binary_search(&s.to_ascii_lowercase()).is_ok()
    }

    fn bounded(
        &self,
        text: &str,
        start: usize,
        end: usize,
        pattern: usize,
        prev: Option<char>,
    ) -> bool {
        let (first_alnum, last_alnum) = self.alnum_edges[pattern];
        let before = if start == 0 {
            prev
        } else {
            text[..start].chars().next_back()
        };
        let after = text[end..].chars().next();
        !(first_alnum && before.is_some_and(char::is_alphanumeric))
            && !(last_alnum && after.is_some_and(char::is_alphanumeric))
    }

    /// Word-bounded surrogate occurrences, leftmost-longest, non-overlapping.
    /// `prev` is the character just before `text` (for streams). The end of
    /// `text` counts as a boundary.
    pub(crate) fn find(&self, text: &str, prev: Option<char>) -> Vec<Found> {
        let Some(ac) = &self.ac else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < text.len() {
            let Some(m) = ac.find(Input::new(text).span(pos..text.len())) else {
                break;
            };
            let start = m.start();
            let (mut end, mut pattern) = (m.end(), m.pattern().as_usize());
            loop {
                if text.is_char_boundary(end) && self.bounded(text, start, end, pattern, prev) {
                    out.push(Found {
                        start,
                        end,
                        pattern,
                    });
                    pos = end;
                    break;
                }
                // Try a shorter surrogate starting at the same place.
                let limit = text[..end]
                    .char_indices()
                    .next_back()
                    .map_or(start, |(i, _)| i);
                let shorter = if limit > start {
                    ac.find(Input::new(text).span(start..limit))
                        .filter(|s| s.start() == start)
                } else {
                    None
                };
                match shorter {
                    Some(s) => {
                        end = s.end();
                        pattern = s.pattern().as_usize();
                    }
                    None => {
                        pos = start + text[start..].chars().next().map_or(1, char::len_utf8);
                        break;
                    }
                }
            }
        }
        out
    }

    /// The real value for an occurrence `matched` of `pattern`.
    pub(crate) fn replacement(&self, pattern: usize, matched: &str) -> String {
        let entries = &self.targets[pattern];
        if let Some(e) = entries.iter().find(|e| e.surrogate == matched) {
            return e.real.clone();
        }
        match entries.iter().find(|e| case_insensitive(&e.kind)) {
            Some(e) => apply_case(matched, &e.real),
            None => entries[0].real.clone(),
        }
    }

    /// The kind behind `pattern` (first mapping).
    pub(crate) fn kind(&self, pattern: usize) -> &EntityKind {
        &self.targets[pattern][0].kind
    }

    /// Replace `found` occurrences (sorted, non-overlapping, all inside
    /// `text`) with their real values.
    pub(crate) fn apply_found<'a>(
        &self,
        text: &str,
        found: impl IntoIterator<Item = &'a Found>,
    ) -> String {
        let mut out = String::with_capacity(text.len());
        let mut pos = 0;
        for f in found {
            out.push_str(&text[pos..f.start]);
            out.push_str(&self.replacement(f.pattern, &text[f.start..f.end]));
            pos = f.end;
        }
        out.push_str(&text[pos..]);
        out
    }

    /// Restore every surrogate in `text`.
    pub(crate) fn apply(&self, text: &str, prev: Option<char>) -> String {
        let found = self.find(text, prev);
        self.apply_found(text, &found)
    }

    /// Start of the longest suffix of `text` that is (ignoring ASCII case) a
    /// prefix of some surrogate, or `text.len()` if there is none. A stream
    /// must hold that suffix back until more text decides it.
    pub(crate) fn hold_start(&self, text: &str) -> usize {
        if self.sorted.is_empty() || text.is_empty() {
            return text.len();
        }
        let lower = text.to_ascii_lowercase();
        let mut from = text.len().saturating_sub(self.max_len);
        while !text.is_char_boundary(from) {
            from += 1;
        }
        for (i, _) in text[from..].char_indices() {
            let s = from + i;
            if self.is_prefix(&lower[s..]) {
                return s;
            }
        }
        text.len()
    }

    fn is_prefix(&self, s: &str) -> bool {
        let idx = self.sorted.partition_point(|p| p.as_str() < s);
        self.sorted.get(idx).is_some_and(|p| p.starts_with(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(pairs: &[(&str, &str)]) -> RestoreTable {
        let entries: Vec<Entry> = pairs
            .iter()
            .map(|(s, r)| Entry {
                surrogate: s.to_string(),
                real: r.to_string(),
                kind: EntityKind::Person,
            })
            .collect();
        RestoreTable::build(&entries)
    }

    #[test]
    fn restores_with_case_and_boundaries() {
        let t = table(&[
            ("Arjun Mehta", "Ravi Kumar"),
            ("Arjun", "Ravi"),
            ("Mehta", "Kumar"),
        ]);
        assert_eq!(t.apply("Hi Arjun Mehta!", None), "Hi Ravi Kumar!");
        assert_eq!(t.apply("ARJUN MEHTA", None), "RAVI KUMAR");
        assert_eq!(t.apply("Arjun's plan, arjun", None), "Ravi's plan, ravi");
        assert_eq!(t.apply("Arjunx Mehtas", None), "Arjunx Mehtas");
        // The longest match fails the boundary test; the shorter one is used.
        assert_eq!(t.apply("Arjun Mehtas", None), "Ravi Mehtas");
        assert_eq!(t.apply("नमस्ते Arjun 🙏", None), "नमस्ते Ravi 🙏");
    }

    #[test]
    fn exact_entry_preferred_over_case_variant() {
        let t = table(&[("Arjun Mehta", "Ravi Kumar"), ("ARJUN MEHTA", "RAVI KUMAR")]);
        assert_eq!(
            t.apply("ARJUN MEHTA / Arjun Mehta", None),
            "RAVI KUMAR / Ravi Kumar"
        );
    }

    #[test]
    fn hold_start_finds_partial_prefixes() {
        let t = table(&[("Arjun Mehta", "Ravi Kumar")]);
        assert_eq!(t.hold_start("Hello Arj"), 6);
        assert_eq!(t.hold_start("Hello Arjun Me"), 6);
        assert_eq!(t.hold_start("Hello there"), 11);
        assert_eq!(t.hold_start("x arjun mehta"), 2);
        assert_eq!(t.hold_start(""), 0);
    }

    #[test]
    fn non_alnum_edges_skip_boundary_checks() {
        let t = table(&[("[NAME_1]", "Ravi")]);
        assert_eq!(t.apply("hi[NAME_1]'s", None), "hiRavi's");
    }
}
