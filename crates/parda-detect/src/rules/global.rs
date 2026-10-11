use super::Rule;
use parda_core::{EntityKind as K, validators};
use std::net::IpAddr;

pub(super) const DOB_CONTEXT: &[&str] = &[
    "dob",
    "d.o.b",
    "date of birth",
    "born on",
    "birth date",
    "janm",
    "जन्म",
];

pub(super) fn rules() -> Vec<Rule> {
    vec![
        Rule::new(
            K::Email,
            r"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+",
            None,
            &["email", "mail"],
            0.8,
        ),
        Rule::new(
            K::Phone,
            r"(?:\+1[ -]?)?\([0-9]{3}\)[ .-]?[0-9]{3}[ .-]?[0-9]{4}|\+[1-9](?:[ -]?[0-9]){7,14}|0[0-9]{2,4}[ -]?[0-9]{6,8}|[6-9][0-9]{4}[ -]?[0-9]{5}|(?:\+1[ -]?)?[0-9]{3}[ .-]?[0-9]{3}[ .-]?[0-9]{4}",
            Some(phone),
            &["phone", "mobile", "tel", "call"],
            0.7,
        ),
        Rule::new(
            K::IpAddress,
            r"[0-9A-Fa-f]*:[0-9A-Fa-f:.]*[0-9A-Fa-f:]|[0-9]{1,3}(?:\.[0-9]{1,3}){3}",
            Some(ip),
            &["ip", "host", "address"],
            0.8,
        ),
        Rule::new(
            K::MacAddress,
            r"(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|(?:[0-9a-f]{2}-){5}[0-9a-f]{2}",
            None,
            &["mac"],
            0.8,
        ),
        Rule::new(
            K::Iban,
            r"[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]){11,30}",
            Some(validators::iban),
            &["iban", "account"],
            0.8,
        ),
        Rule::new(
            K::CreditCard,
            r"[0-9](?:[ -]?[0-9]){12,18}",
            Some(card),
            &["card", "visa", "mastercard"],
            0.8,
        ),
        Rule::new(
            K::Url,
            r#"(?i)https?://[^\s<>"']+"#,
            Some(sensitive_url),
            &["url", "link"],
            0.7,
        ),
        Rule::new(
            K::DateOfBirth,
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}|[0-9]{1,2}-[0-9]{1,2}-[0-9]{4}",
            Some(date),
            DOB_CONTEXT,
            0.6,
        ),
    ]
}
fn phone(s: &str) -> bool {
    (8..=15).contains(&s.bytes().filter(u8::is_ascii_digit).count())
}
fn card(s: &str) -> bool {
    (13..=19).contains(&s.len()) && !s.starts_with('0') && validators::luhn(s)
}
fn ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}
fn sensitive_url(s: &str) -> bool {
    let Some((_, rest)) = s.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return true;
    }
    let Some((_, query)) = rest.split_once('?') else {
        return false;
    };
    query
        .split('#')
        .next()
        .unwrap_or("")
        .split('&')
        .any(|pair| {
            let Some((key, value)) = pair.split_once('=') else {
                return false;
            };
            !value.is_empty()
                && matches!(
                    key.to_ascii_lowercase().as_str(),
                    "token"
                        | "access_token"
                        | "refresh_token"
                        | "api_key"
                        | "apikey"
                        | "key"
                        | "secret"
                        | "password"
                        | "auth"
                        | "authorization"
                        | "email"
                        | "phone"
                        | "name"
                        | "address"
                        | "ssn"
                )
        })
}
fn date(s: &str) -> bool {
    let parts: Vec<_> = s.split(['-', '/']).collect();
    if parts.len() != 3 {
        return false;
    }
    let nums: Option<Vec<u32>> = parts.iter().map(|p| p.parse().ok()).collect();
    let Some(nums) = nums else {
        return false;
    };
    let (year, month, day) = if parts[0].len() == 4 {
        (nums[0], nums[1], nums[2])
    } else {
        (nums[2], nums[1], nums[0])
    };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return false,
    };
    (1..=9999).contains(&year) && (1..=max_day).contains(&day)
}
