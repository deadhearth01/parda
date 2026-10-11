//! Overlap resolution between detections coming from different tiers.

use std::cmp::Ordering;

use crate::detection::Detection;

/// Resolve overlapping detections into a non-overlapping list sorted by
/// start offset. Preference order: higher [`Source::rank`](crate::Source::rank),
/// then longer span, then higher score, then earlier start.
pub fn merge(mut dets: Vec<Detection>) -> Vec<Detection> {
    dets.retain(|d| !d.span.is_empty());
    dets.sort_by(|a, b| {
        b.source
            .rank()
            .cmp(&a.source.rank())
            .then(b.span.len().cmp(&a.span.len()))
            .then(b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal))
            .then(a.span.start.cmp(&b.span.start))
    });
    let mut kept: Vec<Detection> = Vec::with_capacity(dets.len());
    for d in dets {
        if kept.iter().all(|k| !k.span.overlaps(&d.span)) {
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
