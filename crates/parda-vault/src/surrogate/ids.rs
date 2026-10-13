//! Format-preserving surrogates for identifiers: same shape, same separators,
//! valid checksums where the real format has one, and the non-identifying
//! parts (public mail domain, UPI handle, state code, key prefix) kept.

use std::net::Ipv4Addr;

use parda_core::validators::{gstin_check_char, luhn, verhoeff_check_digit};
use rand::Rng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha20Rng;

use super::case::apply_case;
use super::names::{first_name, last_name, origin_of, word};

/// Mail providers whose domain identifies nobody, so it is kept.
const PUBLIC_MAIL_DOMAINS: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.co.in",
    "yahoo.co.uk",
    "yahoo.in",
    "ymail.com",
    "outlook.com",
    "outlook.in",
    "hotmail.com",
    "hotmail.co.uk",
    "live.com",
    "msn.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "pm.me",
    "rediffmail.com",
    "zoho.com",
    "zohomail.in",
    "gmx.com",
    "gmx.de",
    "mail.com",
    "yandex.com",
    "yandex.ru",
    "qq.com",
    "163.com",
    "naver.com",
    "fastmail.com",
    "hey.com",
    "tutanota.com",
    "web.de",
    "orange.fr",
];

/// Sites whose host name identifies nobody, so it is kept in URLs.
const PUBLIC_HOSTS: &[&str] = &[
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "google.com",
    "docs.google.com",
    "drive.google.com",
    "dropbox.com",
    "youtube.com",
    "notion.so",
    "slack.com",
    "zoom.us",
    "linkedin.com",
    "x.com",
    "twitter.com",
    "facebook.com",
    "instagram.com",
    "wa.me",
    "amazonaws.com",
    "s3.amazonaws.com",
    "onedrive.live.com",
    "sharepoint.com",
];

/// Calling codes, longest first when matching.
const CALLING_CODES: &[&str] = &[
    "880", "971", "966", "974", "965", "968", "973", "977", "975", "960", "234", "254", "255",
    "256", "233", "212", "213", "216", "353", "351", "358", "372", "380", "20", "27", "30", "31",
    "32", "33", "34", "36", "39", "40", "41", "43", "44", "45", "46", "47", "48", "49", "51", "52",
    "53", "54", "55", "56", "57", "58", "60", "61", "62", "63", "64", "65", "66", "81", "82", "84",
    "86", "90", "91", "92", "93", "94", "95", "98", "1", "7",
];

/// Known secret prefixes, kept so the surrogate still looks like the same
/// kind of key (and tools that sniff prefixes still behave).
const SECRET_PREFIXES: &[&str] = &[
    "sk-ant-api03-",
    "sk-ant-admin01-",
    "sk-ant-",
    "sk-proj-",
    "sk-svcacct-",
    "sk_live_",
    "sk_test_",
    "pk_live_",
    "pk_test_",
    "rk_live_",
    "rk_test_",
    "whsec_",
    "github_pat_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xapp-",
    "AKIA",
    "ASIA",
    "AIza",
    "SG.",
    "hf_",
    "npm_",
    "pypi-",
    "sk-",
];

const MONTHS: &[&str] = &[
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
];

fn digit(rng: &mut ChaCha20Rng) -> char {
    char::from(b'0' + rng.gen_range(0..10u8))
}

fn digit_in(rng: &mut ChaCha20Rng, lo: u8, hi: u8) -> char {
    char::from(b'0' + rng.gen_range(lo..=hi))
}

fn upper(rng: &mut ChaCha20Rng) -> char {
    char::from(b'A' + rng.gen_range(0..26u8))
}

fn lower(rng: &mut ChaCha20Rng) -> char {
    char::from(b'a' + rng.gen_range(0..26u8))
}

fn hex_like(c: char, rng: &mut ChaCha20Rng) -> char {
    let v = rng.gen_range(0..16u8);
    let h = char::from_digit(u32::from(v), 16).unwrap_or('0');
    if c.is_ascii_uppercase() {
        h.to_ascii_uppercase()
    } else {
        h
    }
}

/// Same character classes in the same places: digit→digit, A→A, a→a;
/// everything else (separators, punctuation, non-ASCII) is kept.
pub(crate) fn shape(s: &str, rng: &mut ChaCha20Rng) -> String {
    s.chars()
        .map(|c| match c {
            '0'..='9' => digit(rng),
            'A'..='Z' => upper(rng),
            'a'..='z' => lower(rng),
            other => other,
        })
        .collect()
}

/// Write `digits` into the digit positions of `template`, keeping every
/// other character. Falls back to `digits` when the counts differ.
fn fill_digits(template: &str, digits: &str) -> String {
    if template.chars().filter(char::is_ascii_digit).count() != digits.len() {
        return digits.to_string();
    }
    let mut it = digits.chars();
    template
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                it.next().unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

/// Write `alnum` into the ASCII-alphanumeric positions of `template`.
fn fill_alnum(template: &str, alnum: &str) -> String {
    if template.chars().filter(char::is_ascii_alphanumeric).count() != alnum.chars().count() {
        return alnum.to_string();
    }
    let mut it = alnum.chars();
    template
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                it.next().unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

fn digits_of(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

pub(crate) fn email(real: &str, rng: &mut ChaCha20Rng) -> String {
    let Some((local, domain)) = real.rsplit_once('@') else {
        return shape(real, rng);
    };
    let domain_lc = domain.to_ascii_lowercase();
    let new_domain = if PUBLIC_MAIL_DOMAINS.contains(&domain_lc.as_str()) {
        domain.to_string()
    } else {
        fake_domain(rng)
    };
    format!("{}@{new_domain}", local_part(local, rng))
}

fn fake_domain(rng: &mut ChaCha20Rng) -> String {
    format!("{}{}.example", word(rng), word(rng))
}

/// A name-like replacement for an e-mail or UPI local part, keeping its
/// separators, digit runs and case.
fn local_part(local: &str, rng: &mut ChaCha20Rng) -> String {
    // Split into runs of letters, digits and everything else.
    let mut runs: Vec<(u8, String)> = Vec::new();
    for c in local.chars() {
        let class = if c.is_alphabetic() {
            0
        } else if c.is_ascii_digit() {
            1
        } else {
            2
        };
        match runs.last_mut() {
            Some((k, s)) if *k == class && class != 2 => s.push(c),
            _ => runs.push((class, c.to_string())),
        }
    }
    let alpha_runs = runs.iter().filter(|(k, _)| *k == 0).count();
    let origin = origin_of(
        runs.iter()
            .filter(|(k, _)| *k == 0)
            .map(|(_, s)| s.as_str()),
    );
    let mut seen_alpha = 0;
    let mut out = String::with_capacity(local.len() + 8);
    for (k, s) in &runs {
        match k {
            0 => {
                let n = s.chars().count();
                let w = if n == 1 {
                    lower(rng).to_string()
                } else if seen_alpha == 0 && alpha_runs == 1 && n >= 8 {
                    format!("{}{}", first_name(rng, origin), last_name(rng, origin))
                } else if seen_alpha == 0 {
                    first_name(rng, origin)
                } else {
                    last_name(rng, origin)
                };
                seen_alpha += 1;
                out.push_str(&apply_case(s, &w));
            }
            1 => out.extend(s.chars().map(|_| digit(rng))),
            _ => out.push_str(s),
        }
    }
    out
}

pub(crate) fn phone(real: &str, rng: &mut ChaCha20Rng) -> String {
    let total_digits = digits_of(real).len();
    let (cc, cc_end) = calling_code(real);
    let mut out = String::with_capacity(real.len());
    out.push_str(&real[..cc_end]);
    let national = &real[cc_end..];
    let national_digits = digits_of(national).len();
    let indian_mobile = cc == Some("91")
        || (cc.is_none()
            && national_digits == 10
            && digits_of(national).starts_with(['6', '7', '8', '9']))
        || (cc.is_none() && total_digits == 11 && digits_of(national).starts_with('0') && {
            let d = digits_of(national);
            d[1..].starts_with(['6', '7', '8', '9'])
        });
    let nanp = cc == Some("1") || (cc.is_none() && national_digits == 10 && !indian_mobile);
    let mut significant = 0usize; // significant (non-trunk) digits written so far
    let mut first_digit = true;
    for c in national.chars() {
        if !c.is_ascii_digit() {
            out.push(c);
            continue;
        }
        if first_digit && c == '0' {
            // Trunk prefix.
            out.push('0');
            first_digit = false;
            continue;
        }
        first_digit = false;
        let d = match significant {
            0 if indian_mobile => digit_in(rng, 6, 9),
            0 | 3 if nanp => digit_in(rng, 2, 9),
            0 => digit_in(rng, 1, 9),
            _ => digit(rng),
        };
        out.push(d);
        significant += 1;
    }
    out
}

/// The calling code after a leading `+` (and the byte where it ends).
fn calling_code(s: &str) -> (Option<&'static str>, usize) {
    let Some(rest) = s.strip_prefix('+') else {
        return (None, 0);
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    // "+91 98…" (code then separator) or "+9198…" (run-on): longest known code.
    if let Some(code) = CALLING_CODES
        .iter()
        .filter(|c| digits.starts_with(**c))
        .max_by_key(|c| c.len())
    {
        return (Some(code), 1 + code.len());
    }
    (None, 1)
}

pub(crate) fn aadhaar(real: &str, rng: &mut ChaCha20Rng) -> String {
    let mut base = String::with_capacity(12);
    base.push(digit_in(rng, 2, 9));
    for _ in 0..10 {
        base.push(digit(rng));
    }
    base.push(char::from(b'0' + verhoeff_check_digit(&base)));
    if digits_of(real).len() == 12 {
        fill_digits(real, &base)
    } else {
        // Partial or mistyped number ("my aadhaar is 123456789"): keep its shape.
        shape(real, rng)
    }
}

pub(crate) fn card(real: &str, rng: &mut ChaCha20Rng) -> String {
    let d = digits_of(real);
    if d.len() < 12 {
        return shape(real, rng);
    }
    let mut payload = String::with_capacity(d.len());
    payload.push(d.chars().next().unwrap_or('4'));
    while payload.len() < d.len() - 1 {
        payload.push(digit(rng));
    }
    let check = (0..10u8)
        .map(|c| char::from(b'0' + c))
        .find(|c| luhn(&format!("{payload}{c}")))
        .unwrap_or('0');
    payload.push(check);
    fill_digits(real, &payload)
}

fn pan_with_holder(holder: char, rng: &mut ChaCha20Rng) -> String {
    let mut s = String::with_capacity(10);
    for _ in 0..3 {
        s.push(upper(rng));
    }
    s.push(holder);
    s.push(upper(rng));
    s.push(digit_in(rng, 1, 9));
    for _ in 0..3 {
        s.push(digit(rng));
    }
    s.push(upper(rng));
    s
}

fn holder_of(real_pan: &str) -> char {
    real_pan
        .chars()
        .nth(3)
        .map(|c| c.to_ascii_uppercase())
        .filter(|c| "ABCFGHLJPT".contains(*c))
        .unwrap_or('P')
}

pub(crate) fn pan(real: &str, rng: &mut ChaCha20Rng) -> String {
    if real.len() != 10 {
        return shape(real, rng); // partial or mistyped PAN: keep its shape
    }
    let s = pan_with_holder(holder_of(real), rng);
    if real.chars().any(|c| c.is_ascii_lowercase()) {
        s.to_lowercase()
    } else {
        s
    }
}

pub(crate) fn gstin(real: &str, rng: &mut ChaCha20Rng) -> String {
    let up = real.to_ascii_uppercase();
    let state = up
        .get(..2)
        .filter(|s| s.parse::<u8>().is_ok_and(|n| (1..=38).contains(&n)))
        .unwrap_or("27");
    let holder = up.get(2..12).map_or('P', holder_of);
    let mut first14 = String::with_capacity(15);
    first14.push_str(state);
    first14.push_str(&pan_with_holder(holder, rng));
    first14.push(digit_in(rng, 1, 9));
    first14.push('Z');
    let check = gstin_check_char(&first14);
    first14.push(check);
    first14
}

pub(crate) fn upi(real: &str, rng: &mut ChaCha20Rng) -> String {
    let Some((local, handle)) = real.rsplit_once('@') else {
        return shape(real, rng);
    };
    let local_new = if !local.is_empty() && local.chars().all(|c| c.is_ascii_digit()) {
        if local.len() == 10 {
            let mut s = String::from(digit_in(rng, 6, 9));
            for _ in 0..9 {
                s.push(digit(rng));
            }
            s
        } else {
            local.chars().map(|_| digit(rng)).collect()
        }
    } else {
        local_part(local, rng)
    };
    format!("{local_new}@{handle}")
}

pub(crate) fn ip(real: &str, rng: &mut ChaCha20Rng) -> String {
    if let Ok(v4) = real.parse::<Ipv4Addr>() {
        return ipv4(v4, rng).to_string();
    }
    if real.contains(':') {
        // IPv6: keep the first group (address type) and the `::` layout.
        let (head, tail) = real.split_once(':').unwrap_or((real, ""));
        let tail: String = tail
            .chars()
            .map(|c| {
                if c.is_ascii_hexdigit() {
                    hex_like(c, rng)
                } else {
                    c
                }
            })
            .collect();
        return format!("{head}:{tail}");
    }
    shape(real, rng)
}

fn ipv4(real: Ipv4Addr, rng: &mut ChaCha20Rng) -> Ipv4Addr {
    let [a, b, _, _] = real.octets();
    let c = rng.gen_range(0..=255u8);
    let d = rng.gen_range(1..=254u8);
    match (a, b) {
        (10, _) => Ipv4Addr::new(10, rng.gen_range(0..=255), c, d),
        (172, 16..=31) => Ipv4Addr::new(172, rng.gen_range(16..=31), c, d),
        (192, 168) => Ipv4Addr::new(192, 168, c, d),
        (169, 254) => Ipv4Addr::new(169, 254, c, d),
        (100, 64..=127) => Ipv4Addr::new(100, rng.gen_range(64..=127), c, d),
        (127, _) => Ipv4Addr::new(127, 0, c, d),
        _ => {
            const RESERVED: [u8; 6] = [10, 100, 127, 169, 172, 192];
            let mut first = rng.gen_range(11..=223u8);
            while RESERVED.contains(&first) {
                first = rng.gen_range(11..=223u8);
            }
            Ipv4Addr::new(first, rng.gen_range(0..=255), c, d)
        }
    }
}

pub(crate) fn mac(real: &str, rng: &mut ChaCha20Rng) -> String {
    let mut out: Vec<char> = real
        .chars()
        .map(|c| {
            if c.is_ascii_hexdigit() {
                hex_like(c, rng)
            } else {
                c
            }
        })
        .collect();
    // Unicast: clear the low bit of the first octet.
    if let Some(v) = out.get(1).and_then(|c| c.to_digit(16)) {
        let even = char::from_digit(v & !1, 16).unwrap_or('0');
        out[1] = if out[1].is_ascii_uppercase() {
            even.to_ascii_uppercase()
        } else {
            even
        };
    }
    out.into_iter().collect()
}

fn mod97(s: &str) -> u32 {
    s.chars().fold(0u32, |rem, c| match c {
        '0'..='9' => (rem * 10 + (c as u32 - '0' as u32)) % 97,
        'A'..='Z' => (rem * 100 + (c as u32 - 'A' as u32 + 10)) % 97,
        _ => rem,
    })
}

pub(crate) fn iban(real: &str, rng: &mut ChaCha20Rng) -> String {
    let compact: String = real
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if compact.len() < 15 || !compact.is_char_boundary(4) {
        return shape(real, rng);
    }
    let country = &compact[..2];
    let bban = shape(&compact[4..], rng);
    let check = 98 - mod97(&format!("{bban}{country}00"));
    let new = format!("{country}{check:02}{bban}");
    fill_alnum(real, &new)
}

pub(crate) fn bank_account(real: &str, rng: &mut ChaCha20Rng) -> String {
    let mut first = true;
    real.chars()
        .map(|c| {
            if c.is_ascii_digit() {
                let d = if first && c != '0' {
                    digit_in(rng, 1, 9)
                } else {
                    digit(rng)
                };
                first = false;
                d
            } else {
                match c {
                    'A'..='Z' => upper(rng),
                    'a'..='z' => lower(rng),
                    other => other,
                }
            }
        })
        .collect()
}

pub(crate) fn ifsc(real: &str, rng: &mut ChaCha20Rng) -> String {
    // Bank code (4 letters) + '0' + branch code: only the branch identifies.
    if real.len() == 11 && real.is_ascii() {
        format!("{}{}", &real[..5], shape(&real[5..], rng))
    } else {
        shape(real, rng)
    }
}

/// Keep a leading two-letter state/region code, shape the rest.
pub(crate) fn keep_state_prefix(real: &str, rng: &mut ChaCha20Rng) -> String {
    let n = real
        .char_indices()
        .take_while(|(i, c)| *i < 2 && c.is_ascii_alphabetic())
        .count();
    if n == 2 {
        format!("{}{}", &real[..2], shape(&real[2..], rng))
    } else {
        shape(real, rng)
    }
}

pub(crate) fn us_ssn(real: &str, rng: &mut ChaCha20Rng) -> String {
    let mut area = rng.gen_range(1..=899u16);
    while area == 666 {
        area = rng.gen_range(1..=899u16);
    }
    let group = rng.gen_range(1..=99u8);
    let serial = rng.gen_range(1..=9999u16);
    let digits = format!("{area:03}{group:02}{serial:04}");
    if digits_of(real).len() == 9 {
        fill_digits(real, &digits)
    } else {
        shape(real, rng) // partial SSN: keep its shape
    }
}

pub(crate) fn uk_nino(real: &str, rng: &mut ChaCha20Rng) -> String {
    const FIRST: &[u8] = b"ABCEGHJKLMNOPRSTWXYZ";
    const SECOND: &[u8] = b"ABCEGHJKLMNPRSTWXYZ";
    const BANNED: [&str; 7] = ["BG", "GB", "NK", "KN", "TN", "NT", "ZZ"];
    let prefix = loop {
        let p = format!(
            "{}{}",
            char::from(*FIRST.choose(rng).unwrap_or(&b'A')),
            char::from(*SECOND.choose(rng).unwrap_or(&b'B'))
        );
        if !BANNED.contains(&p.as_str()) {
            break p;
        }
    };
    let mut s = prefix;
    for _ in 0..6 {
        s.push(digit(rng));
    }
    s.push(char::from(b'A' + rng.gen_range(0..4u8)));
    if real.chars().filter(char::is_ascii_alphanumeric).count() == 9 {
        fill_alnum(real, &s)
    } else {
        s
    }
}

/// A different but still valid-looking date in the same layout: years move
/// by 1–5, numbers ≤ 12 stay ≤ 12 (they may be months), larger day numbers
/// stay within 13–28, month names become other month names.
pub(crate) fn date(real: &str, rng: &mut ChaCha20Rng) -> String {
    let mut out = String::with_capacity(real.len());
    let mut chars = real.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c.is_ascii_digit() {
            let mut end = i + 1;
            while let Some(&(j, d)) = chars.peek() {
                if d.is_ascii_digit() {
                    end = j + 1;
                    chars.next();
                } else {
                    break;
                }
            }
            let run = &real[i..end];
            let value: u32 = run.parse().unwrap_or(0);
            let width = run.len();
            let new = match width {
                4 => {
                    let shift = rng.gen_range(1..=5u32);
                    if rng.gen_bool(0.5) && value > shift {
                        value - shift
                    } else {
                        value + shift
                    }
                }
                1 | 2 if value <= 12 => rng.gen_range(1..=12u32),
                1 | 2 => rng.gen_range(13..=28u32),
                _ => {
                    out.push_str(&shape(run, rng));
                    continue;
                }
            };
            out.push_str(&format!("{new:0width$}"));
        } else if c.is_ascii_alphabetic() {
            let mut end = i + 1;
            while let Some(&(j, d)) = chars.peek() {
                if d.is_ascii_alphabetic() {
                    end = j + 1;
                    chars.next();
                } else {
                    break;
                }
            }
            let run = &real[i..end];
            let lower_run = run.to_ascii_lowercase();
            let is_month = MONTHS
                .iter()
                .any(|m| *m == lower_run || (lower_run.len() == 3 && m.starts_with(&lower_run)));
            if is_month {
                let m = MONTHS.choose(rng).copied().unwrap_or("march");
                let m = if run.len() == 3 { &m[..3] } else { m };
                out.push_str(&apply_case(run, m));
            } else {
                out.push_str(run);
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) fn secret(real: &str, rng: &mut ChaCha20Rng) -> String {
    if real.starts_with("-----BEGIN") {
        // PEM: keep the armour lines, replace the base64 body.
        return real
            .lines()
            .map(|l| {
                if l.starts_with("-----") {
                    l.to_string()
                } else {
                    shape(l, rng)
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    if real.starts_with("eyJ") && real.matches('.').count() == 2 {
        // JWT: three base64url segments; keep the `eyJ` that marks JSON.
        return real
            .split('.')
            .map(|seg| match seg.strip_prefix("eyJ") {
                Some(rest) => format!("eyJ{}", shape(rest, rng)),
                None => shape(seg, rng),
            })
            .collect::<Vec<_>>()
            .join(".");
    }
    let prefix = SECRET_PREFIXES
        .iter()
        .find(|p| real.starts_with(**p))
        .map_or(0, |p| p.len());
    format!("{}{}", &real[..prefix], shape(&real[prefix..], rng))
}

pub(crate) fn url(real: &str, rng: &mut ChaCha20Rng) -> String {
    let (scheme, rest) = match real.split_once("://") {
        Some((s, r)) => (format!("{s}://"), r),
        None => (String::new(), real),
    };
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(host_end);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h, format!(":{p}")),
        _ => (authority, String::new()),
    };
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host_lc = host.to_ascii_lowercase();
    let keep_host = PUBLIC_HOSTS
        .iter()
        .any(|p| host_lc == *p || host_lc.ends_with(&format!(".{p}")));
    let new_host = if keep_host {
        host.to_string()
    } else {
        fake_domain(rng)
    };
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    // Path segments that look like ids or tokens are replaced; words stay.
    let path: String = path
        .split('/')
        .map(|seg| {
            if seg.chars().any(|c| c.is_ascii_digit()) || seg.len() >= 16 {
                shape(seg, rng)
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    let mut out = format!("{scheme}{new_host}{port}{path}");
    if !query.is_empty() || tail.contains('?') {
        out.push('?');
        let (q, frag) = query.split_once('#').unwrap_or((query, ""));
        let q: Vec<String> = q
            .split('&')
            .map(|kv| match kv.split_once('=') {
                Some((k, v)) => format!("{k}={}", shape(v, rng)),
                None => kv.to_string(),
            })
            .collect();
        out.push_str(&q.join("&"));
        if query.contains('#') {
            out.push('#');
            out.push_str(&shape(frag, rng));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use parda_core::validators::{gstin as gstin_ok, iban as iban_ok, verhoeff};
    use rand::SeedableRng;

    fn rng(n: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([n; 32])
    }

    #[test]
    fn iban_checksum_valid_and_spacing_kept() {
        for n in 0..20 {
            let s = iban("GB82 WEST 1234 5698 7654 32", &mut rng(n));
            assert!(iban_ok(&s), "{s}");
            assert_eq!(s.len(), 27);
            assert!(s.starts_with("GB"));
            assert_eq!(s.matches(' ').count(), 5);
        }
    }

    #[test]
    fn gstin_and_aadhaar_valid_for_many_seeds() {
        for n in 0..50 {
            assert!(gstin_ok(&gstin("29ABCDE1234F1Z5", &mut rng(n))));
            let a = aadhaar("2345-6789-0124", &mut rng(n));
            assert_eq!(a.matches('-').count(), 2);
            assert!(verhoeff(&digits_of(&a)));
        }
    }

    #[test]
    fn phone_shapes() {
        let us = phone("+1 (415) 555-0132", &mut rng(3));
        assert!(us.starts_with("+1 ("), "{us}");
        assert_eq!(us.len(), "+1 (415) 555-0132".len());
        assert!(matches!(us.as_bytes()[4], b'2'..=b'9'));
        let trunk = phone("09876543210", &mut rng(4));
        assert!(
            trunk.starts_with('0') && matches!(trunk.as_bytes()[1], b'6'..=b'9'),
            "{trunk}"
        );
        let runon = phone("+919876543210", &mut rng(5));
        assert!(runon.starts_with("+91") && matches!(runon.as_bytes()[3], b'6'..=b'9'));
        let uk = phone("+44 20 7946 0958", &mut rng(6));
        assert!(uk.starts_with("+44 "));
    }

    #[test]
    fn upi_numeric_local_part() {
        let s = upi("9876543210@ybl", &mut rng(7));
        assert!(s.ends_with("@ybl"));
        assert_eq!(s.len(), "9876543210@ybl".len());
        assert!(matches!(s.as_bytes()[0], b'6'..=b'9'));
    }

    #[test]
    fn email_local_part_keeps_layout() {
        let s = email("first.last+tag@sub.domain.co.in", &mut rng(8));
        let (local, domain) = s.split_once('@').unwrap();
        assert!(domain.ends_with(".example"));
        assert!(local.contains('.') && local.contains('+'), "{s}");
        let s = email("RAVI99@gmail.com", &mut rng(9));
        assert!(s.ends_with("@gmail.com"));
        let local = s.split('@').next().unwrap();
        assert_eq!(local, local.to_uppercase());
        assert_eq!(local.chars().filter(char::is_ascii_digit).count(), 2);
    }

    #[test]
    fn ssn_nino_vehicle_dob() {
        let s = us_ssn("123-45-6789", &mut rng(10));
        assert_eq!(s.len(), 11);
        assert!(!s.starts_with("666") && !s.starts_with('9'));
        let n = uk_nino("AB 12 34 56 C", &mut rng(11));
        assert_eq!(n.len(), 13);
        assert!(matches!(n.as_bytes()[12], b'A'..=b'D'));
        let v = keep_state_prefix("MH 12 AB 1234", &mut rng(12));
        assert!(v.starts_with("MH ") && v.len() == 13);
        let d = date("1990-07-23", &mut rng(13));
        assert_eq!(d.len(), 10);
        let year: u32 = d[..4].parse().unwrap();
        assert!((1985..=1995).contains(&year) && year != 1990);
        let d = date("23 March 1990", &mut rng(14));
        assert!(!d.contains("1990"));
    }

    #[test]
    fn url_keeps_param_names_and_replaces_private_host() {
        let s = url(
            "https://internal.acme.in/reset/8f3a9c2d?token=abc123XYZ&user=ravi",
            &mut rng(15),
        );
        assert!(!s.contains("acme"));
        assert!(s.contains("/reset/") && s.contains("?token=") && s.contains("&user="));
        assert!(!s.contains("abc123XYZ"));
        let s = url(
            "https://github.com/acme/repo?access_token=zzz",
            &mut rng(16),
        );
        assert!(s.starts_with("https://github.com/acme/repo?access_token="));
    }

    #[test]
    fn mac_and_ipv6() {
        let m = mac("00:1A:2B:3C:4D:5E", &mut rng(17));
        assert_eq!(m.len(), 17);
        assert_eq!(m.matches(':').count(), 5);
        let second = m.chars().nth(1).unwrap().to_digit(16).unwrap();
        assert_eq!(second % 2, 0);
        let v6 = ip("2001:db8::8a2e:370:7334", &mut rng(18));
        assert!(v6.starts_with("2001:") && v6.contains("::"));
    }

    #[test]
    fn partial_ids_keep_their_shape() {
        use rand::SeedableRng;
        for (real, f) in [
            ("123456789", aadhaar as fn(&str, &mut ChaCha20Rng) -> String),
            ("ABCDE1234", pan),
            ("123-45-678", us_ssn),
        ] {
            let mut rng = ChaCha20Rng::from_seed([7; 32]);
            let s = f(real, &mut rng);
            assert_eq!(s.len(), real.len(), "{real} -> {s}");
            assert_ne!(s, real);
            let class = |c: char| (c.is_ascii_digit(), c.is_ascii_alphabetic());
            assert!(
                s.chars()
                    .zip(real.chars())
                    .all(|(a, b)| class(a) == class(b)),
                "{real} -> {s}"
            );
        }
    }
}
