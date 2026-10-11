//! Checksums and shape validators shared by detection and surrogate generation.

/// Validate a nonempty sequence of ASCII digits using Luhn.
pub fn luhn(digits: &str) -> bool {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let sum: u64 = digits
        .bytes()
        .rev()
        .enumerate()
        .map(|(i, b)| {
            let n = u64::from(b - b'0') * if i % 2 == 1 { 2 } else { 1 };
            if n > 9 { n - 9 } else { n }
        })
        .sum();
    sum.is_multiple_of(10)
}

const D: [[usize; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const P: [[usize; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];
const INV: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];
fn verhoeff_sum(digits: &str, shift: usize) -> Option<usize> {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(digits.bytes().rev().enumerate().fold(0, |c, (i, b)| {
        D[c][P[(i + shift) % 8][usize::from(b - b'0')]]
    }))
}
/// Validate ASCII digits including the final Verhoeff check digit.
pub fn verhoeff(digits: &str) -> bool {
    verhoeff_sum(digits, 0) == Some(0)
}
/// Generate a Verhoeff check digit. Invalid/empty input returns `u8::MAX`.
pub fn verhoeff_check_digit(digits: &str) -> u8 {
    verhoeff_sum(digits, 1).map_or(u8::MAX, |c| INV[c])
}

/// Validate IBAN shape and mod-97 checksum, ignoring ASCII spaces.
/// This does not establish that a bank account exists.
pub fn iban(s: &str) -> bool {
    let s: Vec<u8> = s
        .bytes()
        .filter(|b| *b != b' ')
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if !(15..=34).contains(&s.len())
        || !s[..2].iter().all(u8::is_ascii_uppercase)
        || !s[2..4].iter().all(u8::is_ascii_digit)
        || !s.iter().all(u8::is_ascii_alphanumeric)
    {
        return false;
    }
    let mut rem = 0u32;
    for &b in s[4..].iter().chain(&s[..4]) {
        rem = if b.is_ascii_digit() {
            (rem * 10 + u32::from(b - b'0')) % 97
        } else {
            (rem * 100 + u32::from(b - b'A' + 10)) % 97
        };
    }
    rem == 1
}

/// Validate the PAN shape, including its holder-type character.
pub fn pan(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[..5].iter().all(u8::is_ascii_uppercase)
        && b"ABCFGHLJPT".contains(&b[3])
        && b[5..9].iter().all(u8::is_ascii_digit)
        && b[9].is_ascii_uppercase()
}

/// Generate the base-36 GSTIN check character from 14 uppercase ASCII
/// alphanumerics. Invalid input returns the NUL character.
pub fn gstin_check_char(first14: &str) -> char {
    if first14.len() != 14
        || !first14
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
    {
        return '\0';
    }
    let sum: u32 = first14
        .bytes()
        .enumerate()
        .map(|(i, b)| {
            let value = u32::from(if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'A' + 10
            });
            let product = value * if i % 2 == 0 { 1 } else { 2 };
            product / 36 + product % 36
        })
        .sum();
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[((36 - sum % 36) % 36) as usize] as char
}
/// Validate GSTIN structure (state code, PAN, entity code, Z) and checksum.
pub fn gstin(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 15 || !b.iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    let state = s[..2].parse::<u8>().unwrap_or(0);
    (1..=38).contains(&state)
        && pan(&s[2..12])
        && b[12] != b'0'
        && (b[12].is_ascii_digit() || b[12].is_ascii_uppercase())
        && b[13] == b'Z'
        && gstin_check_char(&s[..14]) == b[14] as char
}

/// Shannon entropy in bits per Unicode scalar value. Empty input has zero entropy.
pub fn shannon_entropy(s: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    let mut total = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / total as f64;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_ok() {
        assert!(luhn("4111111111111111"));
        assert!(!luhn("4111111111111112"));
    }
    #[test]
    fn verhoeff_ok() {
        assert!(verhoeff("2363"));
        assert_eq!(verhoeff_check_digit("236"), 3);
    }
    #[test]
    fn aadhaar_sample_valid() {
        let base = "49911123456";
        let d = verhoeff_check_digit(base);
        assert!(verhoeff(&format!("{base}{d}")));
    }
    #[test]
    fn iban_ok() {
        assert!(iban("GB82 WEST 1234 5698 7654 32"));
        assert!(!iban("GB82 WEST 1234 5698 7654 33"));
    }
    #[test]
    fn gstin_ok() {
        let first = "27AAPFU0939F1Z";
        let c = gstin_check_char(first);
        assert!(gstin(&format!("{first}{c}")));
    }
    #[test]
    fn pan_shape() {
        assert!(pan("ABCPE1234F"));
        assert!(!pan("ABCDE1234F"));
    }
    #[test]
    fn entropy() {
        assert!(shannon_entropy("aaaaaaaa") < 1.0);
        assert!(shannon_entropy("k9F2xQ7pL0vB3mZ8") > 3.5);
    }
    #[test]
    fn invalid_inputs() {
        for s in ["", " ", "１２３", "123x", "123-4"] {
            assert!(!luhn(s));
            assert!(!verhoeff(s));
        }
        for s in ["", "GB00", "123456789012345", "GB82 WEST!1234 5698 7654 32"] {
            assert!(!iban(s));
        }
        for s in ["", "27AAPFU0939F1Z0", "00AAPFU0939F1ZV", "27ABCDE1234F1Z5"] {
            assert!(!gstin(s));
        }
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("अअआआ"), 1.0);
    }
    #[test]
    fn checksum_roundtrips() {
        for i in 0..1000 {
            let base = format!("49911123{i:03}");
            let complete = format!("{base}{}", verhoeff_check_digit(&base));
            assert!(verhoeff(&complete));
            let bad = format!("{base}{}", (verhoeff_check_digit(&base) + 1) % 10);
            assert!(!verhoeff(&bad));
        }
        assert_eq!(gstin_check_char("27AAPFU0939F1Z"), 'V');
        assert!(iban("DE89 3704 0044 0532 0130 00"));
    }
}
