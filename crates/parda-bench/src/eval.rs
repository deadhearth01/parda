//! Precision / recall per kind, zero-leak and round-trip rates.

use std::collections::BTreeMap;

use parda_core::{Detection, Span};
use serde::Serialize;

use crate::golden::Case;

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct KindScore {
    pub gold: u32,
    pub found: u32,
    pub predicted: u32,
    pub correct: u32,
    pub recall: f64,
    pub precision: f64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Report {
    pub model: String,
    pub cases: u32,
    pub per_kind: BTreeMap<String, KindScore>,
    /// Person recall per region (`IN`, `GL`).
    pub person_recall_by_region: BTreeMap<String, f64>,
    /// Cases whose redacted text contains none of their gold values.
    pub zero_leak_rate: f64,
    /// Cases with `restore(redact(x)) == x`.
    pub round_trip_rate: f64,
    pub mean_ms: f64,
}

/// A prediction matches a gold span of the same kind when it covers it or
/// their overlap is at least half of the union.
pub fn matches(pred: &Span, gold: &Span) -> bool {
    let inter = pred
        .end
        .min(gold.end)
        .saturating_sub(pred.start.max(gold.start));
    let union = pred.end.max(gold.end) - pred.start.min(gold.start);
    (pred.start <= gold.start && pred.end >= gold.end) || (union > 0 && inter * 2 >= union)
}

/// One evaluated case.
pub struct Outcome<'a> {
    pub case: &'a Case,
    pub detections: Vec<Detection>,
    pub redacted: String,
    pub restored: String,
    pub ms: f64,
}

pub fn score(model: &str, outcomes: &[Outcome<'_>]) -> Report {
    let mut per_kind: BTreeMap<String, KindScore> = BTreeMap::new();
    let mut region_person: BTreeMap<String, (u32, u32)> = BTreeMap::new();
    let (mut no_leak, mut round_trip) = (0u32, 0u32);
    let mut ms = 0.0;
    let gold_kinds: std::collections::BTreeSet<String> = outcomes
        .iter()
        .flat_map(|o| o.case.entities.iter().map(|g| g.kind.clone()))
        .collect();

    for o in outcomes {
        ms += o.ms;
        for g in &o.case.entities {
            let gs = Span::new(g.start, g.end);
            let hit = o
                .detections
                .iter()
                .any(|d| d.kind.to_string() == g.kind && matches(&d.span, &gs));
            let k = per_kind.entry(g.kind.clone()).or_default();
            k.gold += 1;
            k.found += u32::from(hit);
            if g.kind == "Person" {
                let r = region_person
                    .entry(o.case.region().to_string())
                    .or_default();
                r.0 += 1;
                r.1 += u32::from(hit);
            }
        }
        for d in &o.detections {
            let kind = d.kind.to_string();
            if !gold_kinds.contains(&kind) {
                continue; // only score kinds the corpus annotates
            }
            let ok = o
                .case
                .entities
                .iter()
                .any(|g| g.kind == kind && matches(&d.span, &Span::new(g.start, g.end)));
            let k = per_kind.entry(kind).or_default();
            k.predicted += 1;
            k.correct += u32::from(ok);
        }
        let leaked = o
            .case
            .entities
            .iter()
            .any(|g| o.redacted.contains(&o.case.text[g.start..g.end]));
        no_leak += u32::from(!leaked);
        round_trip += u32::from(o.restored == o.case.text);
    }
    for k in per_kind.values_mut() {
        k.recall = ratio(k.found, k.gold);
        k.precision = ratio(k.correct, k.predicted);
    }
    let n = outcomes.len() as u32;
    Report {
        model: model.to_string(),
        cases: n,
        per_kind,
        person_recall_by_region: region_person
            .into_iter()
            .map(|(r, (g, f))| (r, ratio(f, g)))
            .collect(),
        zero_leak_rate: ratio(no_leak, n),
        round_trip_rate: ratio(round_trip, n),
        mean_ms: if n == 0 { 0.0 } else { ms / f64::from(n) },
    }
}

fn ratio(a: u32, b: u32) -> f64 {
    if b == 0 {
        1.0
    } else {
        f64::from(a) / f64::from(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::golden::Gold;
    use parda_core::{EntityKind, Source};

    fn det(s: usize, e: usize, kind: EntityKind) -> Detection {
        Detection {
            span: Span::new(s, e),
            kind,
            score: 0.9,
            source: Source::Ml,
        }
    }

    #[test]
    fn toy_metrics() {
        let case = Case {
            region: Some("IN".into()),
            text: "Ravi Kumar met Anna in Pune".into(),
            entities: vec![
                Gold {
                    start: 0,
                    end: 10,
                    kind: "Person".into(),
                },
                Gold {
                    start: 15,
                    end: 19,
                    kind: "Person".into(),
                },
            ],
        };
        let outcomes = vec![Outcome {
            case: &case,
            // One exact, one partial-but-overlapping wrong span, one false positive.
            detections: vec![
                det(0, 10, EntityKind::Person),
                det(23, 27, EntityKind::Person),
            ],
            redacted: "Arjun Mehta met Anna in Pune".into(),
            restored: case.text.clone(),
            ms: 2.0,
        }];
        let r = score("toy", &outcomes);
        let p = &r.per_kind["Person"];
        assert_eq!((p.gold, p.found, p.predicted, p.correct), (2, 1, 2, 1));
        assert_eq!(p.recall, 0.5);
        assert_eq!(p.precision, 0.5);
        assert_eq!(r.person_recall_by_region["IN"], 0.5);
        assert_eq!(r.zero_leak_rate, 0.0); // "Anna" leaked
        assert_eq!(r.round_trip_rate, 1.0);
        assert!(matches(&Span::new(0, 12), &Span::new(0, 10)));
        assert!(matches(&Span::new(0, 8), &Span::new(0, 10)));
        assert!(!matches(&Span::new(0, 3), &Span::new(0, 10)));
    }
}
