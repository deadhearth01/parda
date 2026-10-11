use parda_core::{EntityKind, Source};
use parda_detect::{Detector, RuleDetector};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Entity {
    start: usize,
    end: usize,
    kind: String,
}
#[derive(Deserialize)]
struct Case {
    text: String,
    #[serde(default)]
    entities: Vec<Entity>,
    #[serde(default)]
    kinds: Vec<String>,
}
fn detector(dates: bool) -> RuleDetector {
    RuleDetector::new(
        &["global", "india", "us_uk", "secrets"].map(String::from),
        dates,
    )
}
fn load(data: &str) -> Vec<Case> {
    data.lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}
#[test]
fn golden_rules_full_recall() {
    let det = detector(false);
    let cases = load(include_str!("../../../bench/golden/rules.jsonl"));
    assert!(cases.len() >= 60);
    for (line_no, case) in cases.iter().enumerate() {
        let found = det.detect(&case.text);
        for want in &case.entities {
            assert!(case.text.is_char_boundary(want.start) && case.text.is_char_boundary(want.end));
            assert!(
                found.iter().any(|d| d.kind.to_string() == want.kind
                    && d.span.start <= want.start
                    && d.span.end >= want.end),
                "line {}: missing {:?} in {:?}; got {:?}",
                line_no + 1,
                want,
                case.text,
                found
            );
        }
        for d in found {
            assert!(case.text.get(d.span.start..d.span.end).is_some());
        }
    }
}
#[test]
fn golden_negatives_clean() {
    let det = detector(false);
    let cases = load(include_str!("../../../bench/golden/negatives.jsonl"));
    assert!(cases.len() >= 30);
    for (i, case) in cases.iter().enumerate() {
        let found = det.detect(&case.text);
        assert!(
            !found
                .iter()
                .any(|d| case.kinds.contains(&d.kind.to_string())),
            "line {}: {:?}: {:?}",
            i + 1,
            case.text,
            found
        );
    }
}
#[test]
fn dates_context_and_byte_window() {
    for word in [
        "dob",
        "d.o.b",
        "date of birth",
        "born on",
        "birth date",
        "janm",
        "जन्म",
    ] {
        let t = format!("मेरा {word}: 23/04/1990");
        assert!(
            detector(false)
                .detect(&t)
                .iter()
                .any(|d| d.kind == EntityKind::DateOfBirth),
            "{t}"
        );
    }
    assert!(
        detector(true)
            .detect("23/04/1990")
            .iter()
            .any(|d| d.kind == EntityKind::DateOfBirth)
    );
    for t in [
        "dob: ..................... 23/04/1990",
        "dob 31/02/1990",
        "dob 29/02/1900",
        "dob 23/04/1990abc",
        "antidob 23/04/1990",
    ] {
        assert!(
            !detector(false)
                .detect(t)
                .iter()
                .any(|d| d.kind == EntityKind::DateOfBirth),
            "{t}"
        );
    }
    let t = "dob: अअअअअअअ 23/04/1990";
    assert!(
        !detector(false)
            .detect(t)
            .iter()
            .any(|d| d.kind == EntityKind::DateOfBirth)
    );
    assert!(
        detector(false)
            .detect("dob 29/02/2000")
            .iter()
            .any(|d| d.kind == EntityKind::DateOfBirth)
    );
}
#[test]
fn context_boost_validation_and_pack_selection() {
    let det = detector(false);
    let plain = det
        .detect("ABCPE1234F")
        .into_iter()
        .find(|d| d.kind == EntityKind::Pan)
        .unwrap();
    let boosted = det
        .detect("PAN: ABCPE1234F")
        .into_iter()
        .find(|d| d.kind == EntityKind::Pan)
        .unwrap();
    assert_eq!(plain.source, Source::Rule { validated: true });
    assert!((boosted.score - (plain.score + 0.2).min(1.0)).abs() < 0.0001);
    assert_eq!(det.name(), "rules");
    assert!(
        RuleDetector::new(&["unknown".into()], false)
            .detect("ravi@example.com")
            .is_empty()
    );
    assert!(
        RuleDetector::new(&["india".into()], false)
            .detect("ravi@example.com")
            .iter()
            .all(|d| d.kind != EntityKind::Email)
    );
    let dup = RuleDetector::new(&["global".into(), "global".into()], false);
    assert_eq!(dup.detect("ravi@example.com").len(), 1);
}
#[test]
fn utf8_boundaries_and_exact_spans() {
    let det = detector(false);
    for (value, kind) in [
        ("+1 (415) 555-0132", EntityKind::Phone),
        ("+44 20 7946 0958", EntityKind::Phone),
        ("::1", EntityKind::IpAddress),
        ("ravi@example.com", EntityKind::Email),
    ] {
        let text = format!("अअअअअअअअअअअअअअअअअअअअ {value} है");
        assert!(
            det.detect(&text)
                .iter()
                .any(|d| d.kind == kind && d.text(&text) == value),
            "{value}"
        );
    }
}

#[test]
fn addresses_secrets_and_embedded_identifiers() {
    let det = detector(false);
    for (text, value, kind) in [
        (
            "IBAN GB82 WEST 1234 5698 7654 32 FOR RAVI",
            "GB82 WEST 1234 5698 7654 32",
            EntityKind::Iban,
        ),
        (
            "Visit https://example.com/?token=abc123.",
            "https://example.com/?token=abc123",
            EntityKind::Url,
        ),
        (
            "key: ......................... aB3dE6gH9jK2mN5pQ8sT1vW4xY7z",
            "aB3dE6gH9jK2mN5pQ8sT1vW4xY7z",
            EntityKind::Secret,
        ),
        ("\"password\": \"hunter2\"", "hunter2", EntityKind::Secret),
        (
            "-----BEGIN PRIVATE KEY-----\nYWJjZGVm\n-----END PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\nYWJjZGVm\n-----END PRIVATE KEY-----",
            EntityKind::Secret,
        ),
    ] {
        assert!(
            det.detect(text)
                .iter()
                .any(|d| d.kind == kind && d.text(text) == value),
            "{text}: {:?}",
            det.detect(text)
        );
    }
    for (text, kind) in [
        ("dob 23/04-1990", EntityKind::DateOfBirth),
        (
            "key: अअअअअअअअअअअअअअअ aB3dE6gH9jK2mN5pQ8sT1vW4xY7z",
            EntityKind::Secret,
        ),
        ("९9876543210९", EntityKind::Phone),
        ("https://example.com/?token=", EntityKind::Url),
    ] {
        assert!(!det.detect(text).iter().any(|d| d.kind == kind), "{text}");
    }
}
