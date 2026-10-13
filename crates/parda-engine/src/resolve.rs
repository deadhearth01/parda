//! Resolving overlaps between detection tiers without losing coverage.
//!
//! * Anything strictly inside a format match (an e-mail, UPI id, phone, key
//!   …) is part of it: "ravi" inside "ravi.k@gmail.com", or a phone number
//!   inside "9876543210@ybl", must not split it. The format match records
//!   what it absorbed so its stand-in can be checked not to repeat it.
//! * A URL absorbs nothing: whatever is found inside it is resolved on its
//!   own and redacted *inside* the URL's stand-in ([`Item::children`]).
//! * A model guess does not decide the kind of a format match: the model
//!   calling a Voter ID a passport number, or an API key an e-mail, loses to
//!   the rule. Only a model address or name that strictly contains a rule
//!   match (an address around a PIN code) competes in the merge.
//! * Coverage is the union of every tier: whatever part of a losing
//!   detection no winner covers (the rest of an address around a validated
//!   phone number, the name part of an odd e-mail) is still redacted, as its
//!   own segment of the loser's kind. Tier conflicts can change kinds, never
//!   shrink what is hidden.
//!
//! Everything here is `O(n log n)` in the number of detections, so a whole
//! multi-megabyte text resolves in one pass.

use std::collections::HashMap;

use parda_core::{Detection, EntityKind, Source, Span, SpanSet, preference};

/// One top-level replacement.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Item {
    pub det: Detection,
    /// URL only: values found inside it, resolved on their own and redacted
    /// in place inside the URL's stand-in. Sorted, non-overlapping.
    pub children: Vec<Item>,
    /// Spans of detections strictly inside this format match that it
    /// replaces as a whole (a name inside an e-mail address).
    pub absorbed: Vec<Span>,
}

impl Item {
    fn plain(det: Detection) -> Item {
        Item {
            det,
            children: Vec::new(),
            absorbed: Vec::new(),
        }
    }
}

/// Kinds whose rule match is a fixed format that swallows what is inside.
fn structured(kind: &EntityKind) -> bool {
    !matches!(
        kind,
        EntityKind::Person | EntityKind::Address | EntityKind::Organization | EntityKind::Custom(_)
    )
}

pub(crate) fn strictly_inside(inner: &Span, outer: &Span) -> bool {
    outer.start <= inner.start && inner.end <= outer.end && outer.len() > inner.len()
}

struct RuleSpan {
    span: Span,
    idx: usize,
    structured: bool,
    url: bool,
}

/// Rule-tier spans sorted by start, for "what overlaps or contains this
/// span" queries in logarithmic time.
struct RuleSpans {
    spans: Vec<RuleSpan>,
    max_len: usize,
}

impl RuleSpans {
    fn new(dets: &[Detection]) -> Self {
        let mut spans: Vec<RuleSpan> = dets
            .iter()
            .enumerate()
            .filter(|(_, d)| matches!(d.source, Source::Rule { .. }))
            .map(|(idx, d)| RuleSpan {
                span: d.span,
                idx,
                structured: structured(&d.kind),
                url: d.kind == EntityKind::Url,
            })
            .collect();
        spans.sort_by_key(|r| r.span.start);
        let max_len = spans.iter().map(|r| r.span.len()).max().unwrap_or(0);
        RuleSpans { spans, max_len }
    }

    /// Every rule span that could overlap or contain `s`.
    fn near(&self, s: Span) -> impl Iterator<Item = &RuleSpan> {
        let lo = s.start.saturating_sub(self.max_len);
        let from = self.spans.partition_point(|r| r.span.start < lo);
        self.spans[from..]
            .iter()
            .take_while(move |r| r.span.start < s.end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Fate {
    Compete,
    /// A model guess that overlaps a rule match: only fills gaps.
    Deferred,
    /// Strictly inside this URL (outermost one).
    InUrl(usize),
    /// Strictly inside this format match (outermost one, not in a URL).
    Absorbed(usize),
}

/// Resolve `dets` (all inside `text`) into sorted, non-overlapping items.
pub(crate) fn resolve(text: &str, dets: Vec<Detection>) -> Vec<Item> {
    let rules = RuleSpans::new(&dets);
    let fates: Vec<Fate> = dets
        .iter()
        .enumerate()
        .map(|(i, d)| fate(&rules, i, d))
        .collect();

    let by_preference = |mut v: Vec<usize>| {
        v.sort_by(|&a, &b| preference(&dets[a], &dets[b]));
        v
    };
    let competing = by_preference(
        (0..dets.len())
            .filter(|&i| fates[i] == Fate::Compete && !dets[i].span.is_empty())
            .collect(),
    );
    let mut covered = SpanSet::new();
    let mut won = vec![false; dets.len()];
    for &i in &competing {
        if !covered.overlaps(dets[i].span) {
            covered.insert(dets[i].span);
            won[i] = true;
        }
    }

    let mut in_url: HashMap<usize, Vec<Detection>> = HashMap::new();
    let mut absorbed: HashMap<usize, Vec<Span>> = HashMap::new();
    for (j, f) in fates.iter().enumerate() {
        match *f {
            Fate::InUrl(u) if won[u] => in_url.entry(u).or_default().push(dets[j].clone()),
            Fate::Absorbed(c) => absorbed.entry(c).or_default().push(dets[j].span),
            _ => {}
        }
    }
    let mut out: Vec<Item> = Vec::new();
    for (i, d) in dets.iter().enumerate() {
        if !won[i] {
            continue;
        }
        let mut item = Item::plain(d.clone());
        if let Some(inside) = in_url.remove(&i) {
            item.children = resolve(text, inside);
        }
        item.absorbed = absorbed.remove(&i).unwrap_or_default();
        out.push(item);
    }

    // Gap filling, most trusted first: the contents of a URL that lost the
    // merge, then the losers, then deferred model guesses.
    let lost_url_contents = by_preference(
        (0..dets.len())
            .filter(|&j| matches!(fates[j], Fate::InUrl(u) if !won[u]))
            .collect(),
    );
    let losers = competing.iter().copied().filter(|&i| !won[i]);
    let deferred = by_preference(
        (0..dets.len())
            .filter(|&i| fates[i] == Fate::Deferred)
            .collect(),
    );
    for i in lost_url_contents.into_iter().chain(losers).chain(deferred) {
        for gap in covered.gaps(dets[i].span) {
            if let Some(seg) = trim_to_alnum(text, gap) {
                covered.insert(seg);
                out.push(Item::plain(Detection {
                    span: seg,
                    ..dets[i].clone()
                }));
            }
        }
    }
    out.sort_by_key(|it| (it.det.span.start, it.det.span.end));
    out
}

fn fate(rules: &RuleSpans, i: usize, d: &Detection) -> Fate {
    let mut url: Option<&RuleSpan> = None;
    let mut format: Option<&RuleSpan> = None;
    for r in rules.near(d.span) {
        if r.idx == i || !r.structured || !strictly_inside(&d.span, &r.span) {
            continue;
        }
        let slot = if r.url { &mut url } else { &mut format };
        if slot.is_none_or(|o| r.span.len() > o.span.len()) {
            *slot = Some(r);
        }
    }
    if let Some(u) = url {
        return Fate::InUrl(u.idx);
    }
    if let Some(f) = format {
        return Fate::Absorbed(f.idx);
    }
    if d.source == Source::Ml {
        let container = matches!(d.kind, EntityKind::Address | EntityKind::Person);
        if rules
            .near(d.span)
            .any(|r| r.span.overlaps(&d.span) && !(container && strictly_inside(&r.span, &d.span)))
        {
            return Fate::Deferred;
        }
    }
    Fate::Compete
}

/// `gap` trimmed to its first and last letter or digit; `None` if it has
/// none (or is not on character boundaries).
fn trim_to_alnum(text: &str, gap: Span) -> Option<Span> {
    let seg = text.get(gap.start..gap.end)?;
    let start = gap.start + seg.find(|c: char| c.is_alphanumeric())?;
    let end = gap.start
        + seg
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_alphanumeric())
            .map(|(i, c)| i + c.len_utf8())?;
    (start < end).then(|| Span::new(start, end))
}

/// The top-level detections of `items`.
pub(crate) fn flatten(items: Vec<Item>) -> Vec<Detection> {
    items.into_iter().map(|it| it.det).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Text for span-only tests: every byte a letter.
    static TXT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| "x".repeat(80));

    fn d(s: usize, e: usize, kind: EntityKind, source: Source) -> Detection {
        Detection {
            span: Span::new(s, e),
            kind,
            score: 0.9,
            source,
        }
    }

    fn dets(text: &str, items: &[Item]) -> Vec<(EntityKind, String)> {
        items
            .iter()
            .map(|x| {
                (
                    x.det.kind.clone(),
                    text[x.det.span.start..x.det.span.end].to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn coverage_is_kept_when_a_rule_wins() {
        // An address around a validated phone: phone wins, the rest of the
        // address is still redacted on both sides.
        let t = "Flat 4, MG Road 9876543210 Pune 411001";
        let p = t.find("9876543210").unwrap();
        let out = resolve(
            t,
            vec![
                d(0, t.len(), EntityKind::Address, Source::Ml),
                d(
                    p,
                    p + 10,
                    EntityKind::Phone,
                    Source::Rule { validated: true },
                ),
            ],
        );
        assert_eq!(
            dets(t, &out),
            vec![
                (EntityKind::Address, "Flat 4, MG Road".into()),
                (EntityKind::Phone, "9876543210".into()),
                (EntityKind::Address, "Pune 411001".into()),
            ]
        );
        // An odd e-mail the e-mail rule misses, with phone digits inside.
        let t = "mail rahul.9876543210@corp-mail now";
        let s0 = t.find("rahul").unwrap();
        let e0 = t.find(" now").unwrap();
        let p = t.find("9876543210").unwrap();
        let out = resolve(
            t,
            vec![
                d(s0, e0, EntityKind::Email, Source::Ml),
                d(
                    p,
                    p + 10,
                    EntityKind::Phone,
                    Source::Rule { validated: true },
                ),
            ],
        );
        let texts: Vec<_> = dets(t, &out).into_iter().map(|(_, s)| s).collect();
        assert_eq!(texts, vec!["rahul", "9876543210", "corp-mail"]);
    }

    #[test]
    fn absorb_drops_name_inside_email() {
        let out = resolve(
            &TXT,
            vec![
                d(0, 4, EntityKind::Person, Source::Dictionary),
                d(0, 16, EntityKind::Email, Source::Rule { validated: false }),
            ],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].det.kind, EntityKind::Email);
        assert_eq!(out[0].absorbed, vec![Span::new(0, 4)]);
    }

    #[test]
    fn longer_format_match_wins_over_validated_inner_match() {
        // "9876543210@ybl": a validated phone inside an (unvalidated) UPI id.
        let out = resolve(
            &TXT,
            vec![
                d(0, 10, EntityKind::Phone, Source::Rule { validated: true }),
                d(0, 14, EntityKind::Upi, Source::Rule { validated: false }),
            ],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].det.kind, EntityKind::Upi);
    }

    #[test]
    fn model_does_not_relabel_a_format_match() {
        let out = resolve(
            &TXT,
            vec![
                d(7, 17, EntityKind::Passport, Source::Ml),
                d(
                    7,
                    17,
                    EntityKind::VoterId,
                    Source::Rule { validated: false },
                ),
            ],
        );
        assert_eq!(out[0].det.kind, EntityKind::VoterId);
        // A model e-mail span that wraps an API key (plus a full stop) loses.
        let t = "Value: xoxb-123456789012-123456789012-abcdefghijklmnop.";
        let out = resolve(
            t,
            vec![
                d(7, 55, EntityKind::Email, Source::Ml),
                d(7, 54, EntityKind::Secret, Source::Rule { validated: false }),
            ],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].det.kind, EntityKind::Secret);
        // …but a model address that covers a PIN code still wins.
        let out = resolve(
            &TXT,
            vec![
                d(0, 40, EntityKind::Address, Source::Ml),
                d(
                    34,
                    40,
                    EntityKind::Custom("Pin".into()),
                    Source::Rule { validated: false },
                ),
            ],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].det.kind, EntityKind::Address);
    }

    #[test]
    fn url_keeps_what_is_inside_it_as_children() {
        let t = "see https://crm.acme.in/u/ravikumar/x?email=ravi.k@gmail.com&token=1 ok";
        let u0 = t.find("https").unwrap();
        let u1 = t.find(" ok").unwrap();
        let n = t.find("ravikumar").unwrap();
        let e = t.find("ravi.k@").unwrap();
        let out = resolve(
            t,
            vec![
                d(u0, u1, EntityKind::Url, Source::Rule { validated: true }),
                d(n, n + 9, EntityKind::Person, Source::Dictionary),
                d(
                    e,
                    e + 16,
                    EntityKind::Email,
                    Source::Rule { validated: false },
                ),
                d(e, e + 4, EntityKind::Person, Source::Dictionary),
            ],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].det.kind, EntityKind::Url);
        assert_eq!(
            dets(t, &out[0].children),
            vec![
                (EntityKind::Person, "ravikumar".into()),
                (EntityKind::Email, "ravi.k@gmail.com".into()),
            ]
        );
        // The name inside the e-mail is absorbed by the e-mail, not the URL.
        assert_eq!(out[0].children[1].absorbed, vec![Span::new(e, e + 4)]);
        assert!(out[0].absorbed.is_empty());
    }

    #[test]
    fn whole_text_resolution_is_fast() {
        let unit = "Contact ravi.k@gmail.com about order 12345.\n";
        let t = unit.repeat(25_000);
        let mut v = Vec::new();
        for i in 0..25_000 {
            let s = i * unit.len() + 8;
            v.push(d(
                s,
                s + 16,
                EntityKind::Email,
                Source::Rule { validated: false },
            ));
            v.push(d(s, s + 4, EntityKind::Person, Source::Dictionary));
        }
        let started = std::time::Instant::now();
        let out = resolve(&t, v);
        assert_eq!(out.len(), 25_000);
        assert!(started.elapsed().as_secs() < 3, "{:?}", started.elapsed());
    }
}
