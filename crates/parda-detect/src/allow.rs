//! The allow-list: terms the user never wants redacted (own product names,
//! public figures, …). It filters detections from every tier.

use std::collections::HashSet;

use aho_corasick::AhoCorasick;
use parda_core::Detection;

use crate::dictionary::{with_case_variants, word_bounded};

/// Case-insensitive exact-term filter.
pub struct AllowList {
    /// Lower-cased allow terms, for whole-detection comparison.
    exact: HashSet<String>,
    /// Finds occurrences of the terms inside a text.
    matcher: Option<AhoCorasick>,
}

impl AllowList {
    /// Blank entries are ignored.
    pub fn new(terms: &[String]) -> Self {
        let mut exact = HashSet::new();
        let mut patterns = Vec::new();
        for term in terms {
            let term = term.trim();
            if term.is_empty() || !exact.insert(term.to_lowercase()) {
                continue;
            }
            patterns.extend(with_case_variants(term));
        }
        let matcher = (!patterns.is_empty()).then(|| {
            // Standard match kind: containment needs every occurrence,
            // including overlapping ones, not just the leftmost-longest.
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&patterns)
                .expect("allow-list automaton must build")
        });
        Self { exact, matcher }
    }

    /// Drop every detection whose text equals an allow term, or lies entirely
    /// inside a word-bounded occurrence of one, ignoring case. Order is kept.
    pub fn filter(&self, text: &str, dets: Vec<Detection>) -> Vec<Detection> {
        let Some(matcher) = &self.matcher else {
            return dets;
        };

        // Occurrences sorted by start, with the furthest end seen so far, so
        // "is [s, e) inside some occurrence" is one binary search.
        let mut occurrences: Vec<(usize, usize)> = matcher
            .find_overlapping_iter(text)
            .map(|m| (m.start(), m.end()))
            .filter(|&(s, e)| word_bounded(text, s, e))
            .collect();
        occurrences.sort_unstable();
        let mut reach = Vec::with_capacity(occurrences.len());
        let mut furthest = 0;
        for &(_, end) in &occurrences {
            furthest = furthest.max(end);
            reach.push(furthest);
        }

        dets.into_iter()
            .filter(|d| {
                let (start, end) = (d.span.start, d.span.end);
                if text
                    .get(start..end)
                    .is_some_and(|t| self.exact.contains(&t.to_lowercase()))
                {
                    return false;
                }
                let upto = occurrences.partition_point(|&(s, _)| s <= start);
                !(upto > 0 && reach[upto - 1] >= end)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parda_core::{EntityKind, Source, Span};

    fn det(start: usize, end: usize, kind: EntityKind) -> Detection {
        Detection {
            span: Span { start, end },
            kind,
            score: 0.9,
            source: Source::Ml,
        }
    }

    #[test]
    fn allow_list_removes() {
        let a = AllowList::new(&["Acme Corp".into()]);
        let t = "Acme Corp hired Ravi";
        let dets = vec![Detection {
            span: Span { start: 0, end: 9 },
            kind: EntityKind::Organization,
            score: 0.9,
            source: Source::Ml,
        }];
        assert!(a.filter(t, dets).is_empty());
    }

    #[test]
    fn exact_match_is_case_insensitive() {
        let a = AllowList::new(&["acme corp".into()]);
        let t = "ACME CORP hired Ravi";
        let dets = vec![
            det(0, 9, EntityKind::Organization),
            det(16, 20, EntityKind::Person),
        ];
        let kept = a.filter(t, dets);
        assert_eq!(kept.len(), 1);
        assert_eq!(&t[kept[0].span.start..kept[0].span.end], "Ravi");
    }

    #[test]
    fn detection_inside_an_allowed_occurrence_is_dropped() {
        let a = AllowList::new(&["Acme Corp".into()]);
        let t = "Acme Corp hired Ravi";
        // "Acme" is a sub-span of the allowed "Acme Corp" occurrence.
        let kept = a.filter(
            t,
            vec![
                det(0, 4, EntityKind::Organization),
                det(16, 20, EntityKind::Person),
            ],
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].kind, EntityKind::Person);
    }

    #[test]
    fn occurrence_must_be_word_bounded_to_cover_a_detection() {
        let a = AllowList::new(&["Acme Corp".into()]);
        let t = "Acme Corporation hired Ravi";
        // "Acme Corp" occurs only as a prefix of "Corporation"; "Corp" stays detected.
        let kept = a.filter(t, vec![det(5, 9, EntityKind::Organization)]);
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn detection_partly_outside_the_occurrence_is_kept() {
        let a = AllowList::new(&["Acme Corp".into()]);
        let t = "Acme Corp Holdings";
        let kept = a.filter(t, vec![det(0, 18, EntityKind::Organization)]);
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn overlapping_occurrences_are_all_considered() {
        let a = AllowList::new(&["Acme Corp".into(), "Corp Park".into()]);
        let t = "Acme Corp Park";
        // Covered by the second occurrence only.
        let kept = a.filter(t, vec![det(5, 14, EntityKind::Address)]);
        assert!(kept.is_empty());
    }

    #[test]
    fn empty_or_blank_allow_list_changes_nothing() {
        let t = "Acme Corp hired Ravi";
        let dets = vec![det(0, 9, EntityKind::Organization)];
        assert_eq!(AllowList::new(&[]).filter(t, dets.clone()), dets);
        assert_eq!(
            AllowList::new(&["".into(), "   ".into()]).filter(t, dets.clone()),
            dets
        );
    }

    #[test]
    fn non_ascii_text_is_handled_on_char_boundaries() {
        let a = AllowList::new(&["रवि कुमार".into()]);
        let t = "नमस्ते 👋 रवि कुमार आया";
        let start = t.find("रवि").unwrap();
        let end = start + "रवि कुमार".len();
        let kept = a.filter(
            t,
            vec![
                det(start, end, EntityKind::Person),
                det(0, "नमस्ते".len(), EntityKind::Person),
            ],
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].span.start, 0);
    }

    #[test]
    fn out_of_range_or_misaligned_spans_do_not_panic() {
        let a = AllowList::new(&["Acme".into()]);
        let t = "é Acme";
        let kept = a.filter(
            t,
            vec![
                det(1, 2, EntityKind::Person),
                det(0, 99, EntityKind::Person),
            ],
        );
        assert_eq!(kept.len(), 2);
    }
}
