//! IDs introduced by their name ("my Aadhaar number is …", "PAN: …",
//! "passport no. …"). The user has said what the value is, so it is masked
//! as that kind even when it fails the checksum — typos, partial numbers and
//! test data are still personal data.

use super::Rule;
use parda_core::EntityKind as K;

/// Words allowed between the keyword and the value.
const FILLER: &str = r"(?:\s*(?:card|number|num|no\.?|#|id|is|was|hai|h|ka|ki|:|=|-|–))*\s*";

fn keyed(kind: K, keywords: &str, value: &str, validator: fn(&str) -> bool) -> Rule {
    // The regex crate has no look-behind; the leading boundary comes from \b
    // and the trailing one from the detector's own `bounded` check.
    let pattern = format!(r"(?i)\b(?:{keywords}){FILLER}(?P<value>{value})");
    Rule::new(kind, &pattern, Some(validator), &[], 0.9)
}

fn digits(s: &str) -> usize {
    s.chars().filter(char::is_ascii_digit).count()
}

fn letters(s: &str) -> usize {
    s.chars().filter(char::is_ascii_alphabetic).count()
}

fn only(s: &str, allowed: impl Fn(char) -> bool) -> bool {
    s.chars().all(allowed)
}

fn numeric_id(s: &str) -> bool {
    (4..=16).contains(&digits(s)) && only(s, |c| c.is_ascii_digit() || c == ' ' || c == '-')
}

fn account_number(s: &str) -> bool {
    (6..=18).contains(&digits(s)) && only(s, |c| c.is_ascii_digit() || c == ' ' || c == '-')
}

fn alnum_id(s: &str) -> bool {
    (5..=15).contains(&s.len())
        && digits(s) >= 2
        && letters(s) >= 1
        && only(s, |c| c.is_ascii_alphanumeric())
}

fn pan_like(s: &str) -> bool {
    alnum_id(s) && letters(s) >= 3
}

const NUMBER: &str = r"[0-9](?:[ -]?[0-9]){3,17}";
const ALNUM: &str = r"[A-Za-z0-9]{5,15}";

pub(super) fn india() -> Vec<Rule> {
    vec![
        keyed(
            K::Aadhaar,
            r"aadhaar|aadhar|adhaar|adhar|aadhar|uidai|uid|आधार",
            NUMBER,
            numeric_id,
        ),
        keyed(K::Pan, r"pan|permanent\s+account\s+number", ALNUM, pan_like),
        keyed(K::VoterId, r"voter(?:\s*id)?|epic", ALNUM, alnum_id),
        keyed(
            K::DrivingLicence,
            r"driving\s+licen[cs]e|dl",
            r"[A-Za-z0-9 -]{6,20}[0-9]",
            alnum_id_spaced,
        ),
    ]
}

pub(super) fn global() -> Vec<Rule> {
    vec![
        keyed(K::Passport, r"passport", ALNUM, alnum_id_or_digits),
        keyed(
            K::BankAccount,
            r"(?:bank\s+)?account|acct|a/c",
            NUMBER,
            account_number,
        ),
    ]
}

pub(super) fn us_uk() -> Vec<Rule> {
    vec![keyed(
        K::UsSsn,
        r"ssn|social\s+security(?:\s+number)?",
        r"[0-9](?:[ -]?[0-9]){3,10}",
        numeric_id,
    )]
}

fn alnum_id_spaced(s: &str) -> bool {
    let compact: String = s.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    alnum_id(&compact) && only(s, |c| c.is_ascii_alphanumeric() || c == ' ' || c == '-')
}

fn alnum_id_or_digits(s: &str) -> bool {
    alnum_id(s) || (6..=12).contains(&digits(s)) && only(s, |c| c.is_ascii_digit())
}
