use super::Rule;
use parda_core::EntityKind as K;

pub(super) fn rules() -> Vec<Rule> {
    vec![
        Rule::new(
            K::UsSsn,
            r"[0-9]{3}-[0-9]{2}-[0-9]{4}|[0-9]{3} [0-9]{2} [0-9]{4}",
            Some(ssn),
            &["ssn", "social security"],
            0.8,
        ),
        Rule::new(
            K::UkNino,
            r"(?i)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?[0-9]{2} ?[0-9]{2} ?[0-9]{2} ?[A-D]",
            Some(nino),
            &["nino", "national insurance"],
            0.8,
        ),
    ]
}
fn ssn(s: &str) -> bool {
    let digits = s.replace([' ', '-'], "");
    let area: u16 = digits[..3].parse().unwrap_or(0);
    area > 0 && area != 666 && area < 900 && &digits[3..5] != "00" && &digits[5..] != "0000"
}
fn nino(s: &str) -> bool {
    !["BG", "GB", "KN", "NK", "NT", "TN", "ZZ"].contains(&&s[..2].to_ascii_uppercase()[..])
}
