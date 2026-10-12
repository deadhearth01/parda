//! Overlap resolution between detections coming from different tiers.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::detection::{Detection, Span};

/// The preference order of [`merge`]: higher [`Source::rank`](crate::Source::rank),
/// then longer span, then higher score, then earlier start.
pub fn preference(a: &Detection, b: &Detection) -> Ordering {
    b.source
        .rank()
        .cmp(&a.source.rank())
        .then(b.span.len().cmp(&a.span.len()))
        .then(b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal))
        .then(a.span.start.cmp(&b.span.start))
}

/// A set of non-overlapping, non-empty spans with logarithmic overlap tests.
#[derive(Debug, Clone, Default)]
pub struct SpanSet {
    /// start → end; entries never overlap.
    by_start: BTreeMap<usize, usize>,
}

impl SpanSet {
    pub fn new() -> Self {
        SpanSet::default()
    }

    /// Does `span` overlap any member? Members never overlap each other, so
    /// only the member starting last before `span.end` can.
    pub fn overlaps(&self, span: Span) -> bool {
        self.by_start
            .range(..span.end)
            .next_back()
            .is_some_and(|(_, &end)| end > span.start)
    }

    /// Add `span`, which must not overlap a member and must not be empty.
    pub fn insert(&mut self, span: Span) {
        debug_assert!(!span.is_empty() && !self.overlaps(span));
        self.by_start.insert(span.start, span.end);
    }

    /// The parts of `span` no member covers, in order.
    pub fn gaps(&self, span: Span) -> Vec<Span> {
        let before = self
            .by_start
            .range(..span.start)
            .next_back()
            .filter(|(_, end)| **end > span.start);
        let inside = self.by_start.range(span.start..span.end);
        let mut gaps = Vec::new();
        let mut pos = span.start;
        for (&start, &end) in before.into_iter().chain(inside) {
            if start > pos {
                gaps.push(Span::new(pos, start));
            }
            pos = pos.max(end);
        }
        if pos < span.end {
            gaps.push(Span::new(pos, span.end));
        }
        gaps
    }
}

/// Resolve overlapping detections into a non-overlapping list sorted by
/// start offset. Preference order: see [`preference`]. `O(n log n)`.
pub fn merge(mut dets: Vec<Detection>) -> Vec<Detection> {
    dets.retain(|d| !d.span.is_empty());
    dets.sort_by(preference);
    let mut taken = SpanSet::new();
    let mut kept: Vec<Detection> = Vec::with_capacity(dets.len());
    for d in dets {
        if !taken.overlaps(d.span) {
            taken.insert(d.span);
            kept.push(d);
        }
    }
    kept.sort_by_key(|d| (d.span.start, d.span.end));
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntityKind, Source, Span};

    fn det(start: usize, end: usize, kind: EntityKind, score: f32, source: Source) -> Detection {
        Detection {
            span: Span { start, end },
            kind,
            score,
            source,
        }
    }

    #[test]
    fn dictionary_beats_ml_on_overlap() {
        let a = det(0, 10, EntityKind::Person, 0.6, Source::Ml);
        let b = det(0, 5, EntityKind::Person, 1.0, Source::Dictionary);
        assert_eq!(merge(vec![a, b.clone()]), vec![b]);
    }

    #[test]
    fn longer_span_wins_same_rank() {
        let a = det(0, 4, EntityKind::Person, 0.9, Source::Ml);
        let b = det(0, 9, EntityKind::Person, 0.7, Source::Ml);
        assert_eq!(merge(vec![a, b.clone()]), vec![b]);
    }

    #[test]
    fn non_overlapping_sorted() {
        let a = det(
            10,
            12,
            EntityKind::Email,
            1.0,
            Source::Rule { validated: true },
        );
        let b = det(
            0,
            3,
            EntityKind::Phone,
            1.0,
            Source::Rule { validated: true },
        );
        assert_eq!(merge(vec![a.clone(), b.clone()]), vec![b, a]);
    }

    #[test]
    fn validated_rule_beats_ml_but_unvalidated_rule_loses() {
        let ml = det(0, 12, EntityKind::Person, 0.9, Source::Ml);
        let weak = det(
            2,
            6,
            EntityKind::Phone,
            0.5,
            Source::Rule { validated: false },
        );
        let strong = det(
            2,
            6,
            EntityKind::Aadhaar,
            0.9,
            Source::Rule { validated: true },
        );
        assert_eq!(merge(vec![ml.clone(), weak]), vec![ml.clone()]);
        assert_eq!(merge(vec![ml, strong.clone()]), vec![strong]);
    }

    #[test]
    fn span_set_overlaps_and_gaps() {
        let mut s = SpanSet::new();
        s.insert(Span::new(2, 4));
        s.insert(Span::new(6, 9));
        assert!(s.overlaps(Span::new(3, 5)));
        assert!(s.overlaps(Span::new(0, 3)));
        assert!(s.overlaps(Span::new(8, 20)));
        assert!(!s.overlaps(Span::new(4, 6)));
        assert!(!s.overlaps(Span::new(0, 2)));
        assert_eq!(
            s.gaps(Span::new(0, 12)),
            vec![Span::new(0, 2), Span::new(4, 6), Span::new(9, 12)]
        );
        assert_eq!(s.gaps(Span::new(3, 7)), vec![Span::new(4, 6)]);
        assert!(s.gaps(Span::new(6, 9)).is_empty());
    }

    #[test]
    fn merge_is_fast_on_many_detections() {
        let dets: Vec<_> = (0..50_000)
            .map(|i| det(i * 10, i * 10 + 8, EntityKind::Email, 0.8, Source::Ml))
            .collect();
        let t = std::time::Instant::now();
        assert_eq!(merge(dets).len(), 50_000);
        assert!(t.elapsed().as_secs() < 2, "{:?}", t.elapsed());
    }

    #[test]
    fn adjacent_spans_both_kept() {
        let a = det(0, 4, EntityKind::Person, 0.9, Source::Ml);
        let b = det(
            4,
            8,
            EntityKind::Email,
            1.0,
            Source::Rule { validated: true },
        );
        assert_eq!(merge(vec![a.clone(), b.clone()]).len(), 2);
    }
}
