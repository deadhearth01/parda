//! Numbers introduced by an ID keyword are masked as that ID even when they
//! fail the checksum (typos, partial numbers, test data): the user said what
//! it is.
use parda_core::{Detection, EntityKind};
use parda_detect::{Detector, RuleDetector};

fn rules() -> RuleDetector {
    RuleDetector::new(
        &["global", "india", "us_uk", "secrets"].map(String::from),
        false,
    )
}

fn found(text: &str) -> Vec<(EntityKind, String)> {
    let mut v: Vec<Detection> = rules().detect(text);
    v.sort_by_key(|d| d.span.start);
    v.into_iter()
        .map(|d| (d.kind.clone(), text[d.span.start..d.span.end].to_string()))
        .collect()
}

fn has(text: &str, kind: EntityKind, value: &str) {
    let f = found(text);
    assert!(
        f.iter().any(|(k, v)| *k == kind && v == value),
        "{kind:?} {value:?} not found in {text:?}: {f:?}"
    );
}

#[test]
fn invalid_or_partial_ids_after_keywords() {
    has(
        "hey my aadhar number is 123456789",
        EntityKind::Aadhaar,
        "123456789",
    );
    has(
        "Aadhaar no: 1234 5678 9012",
        EntityKind::Aadhaar,
        "1234 5678 9012",
    );
    has(
        "mera aadhaar card 4321-8765-1111 hai",
        EntityKind::Aadhaar,
        "4321-8765-1111",
    );
    has("आधार 9876 5432 1098", EntityKind::Aadhaar, "9876 5432 1098");
    has("PAN number is ABCDE1234", EntityKind::Pan, "ABCDE1234");
    has("my pan: abcde1234x", EntityKind::Pan, "abcde1234x");
    has("passport no. K1234567", EntityKind::Passport, "K1234567");
    has(
        "account number 00123456789",
        EntityKind::BankAccount,
        "00123456789",
    );
    has(
        "a/c no 5012 3456 789",
        EntityKind::BankAccount,
        "5012 3456 789",
    );
    has("SSN 123-45-678", EntityKind::UsSsn, "123-45-678");
    has("voter id ABC123456", EntityKind::VoterId, "ABC123456");
}

#[test]
fn keywords_without_an_id_value_are_left_alone() {
    for t in [
        "Explain the difference between a PAN card and an Aadhaar card.",
        "The aadhaar centre is open 24 hours.",
        "PAN number is pending, will send tomorrow",
        "passport photos: 2 copies",
        "account number format has 11 digits",
        "My account number? I'll check later.",
    ] {
        let f = found(t);
        assert!(f.is_empty(), "{t:?}: {f:?}");
    }
}
