//! Carrying the letter case of one string over to another, so a surrogate
//! looks like the value it replaces (`RAVI` → `ARJUN`, `ravi` → `arjun`) and a
//! restored value looks like the surrogate the model wrote.

/// The letter case of a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasePattern {
    /// Every letter upper case, and more than one letter (`RAVI KUMAR`).
    Upper,
    /// Every letter lower case (`ravi.kumar`).
    Lower,
    /// Anything else with letters (`Ravi Kumar`, `McCarthy`, `R`).
    Title,
    /// No cased letters at all (digits, Devanagari, …).
    None,
}

pub fn case_pattern(s: &str) -> CasePattern {
    let (mut upper, mut lower) = (0usize, 0usize);
    for c in s.chars() {
        if c.is_uppercase() {
            upper += 1;
        } else if c.is_lowercase() {
            lower += 1;
        }
    }
    match (upper, lower) {
        (0, 0) => CasePattern::None,
        (0, _) => CasePattern::Lower,
        // A lone capital ("R", "R.") reads as a title-cased initial.
        (1, 0) => CasePattern::Title,
        (_, 0) => CasePattern::Upper,
        _ => CasePattern::Title,
    }
}

/// Re-case `word` to follow `pattern`'s case: UPPER, lower, or Title.
///
/// Title case keeps a word's own mixed case (`McCarthy`), capitalises an
/// all-lower word and turns an all-upper word into `Title` form. Whitespace
/// separated parts are handled one by one.
pub fn apply_case(pattern: &str, word: &str) -> String {
    match case_pattern(pattern) {
        CasePattern::Upper => word.to_uppercase(),
        CasePattern::Lower => word.to_lowercase(),
        CasePattern::Title => title_case(word),
        CasePattern::None => word.to_string(),
    }
}

fn title_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut part = String::new();
    for c in s.chars() {
        if c.is_whitespace() {
            out.push_str(&title_part(&part));
            part.clear();
            out.push(c);
        } else {
            part.push(c);
        }
    }
    out.push_str(&title_part(&part));
    out
}

fn title_part(part: &str) -> String {
    match case_pattern(part) {
        CasePattern::Title | CasePattern::None => part.to_string(),
        CasePattern::Upper | CasePattern::Lower => {
            let mut out = String::with_capacity(part.len());
            // Capitalise the first letter, lower-case the rest.
            let mut seen_letter = false;
            for c in part.chars() {
                if !seen_letter && c.is_alphabetic() {
                    out.extend(c.to_uppercase());
                    seen_letter = true;
                } else if seen_letter {
                    out.extend(c.to_lowercase());
                } else {
                    out.push(c);
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        assert_eq!(case_pattern("RAVI KUMAR"), CasePattern::Upper);
        assert_eq!(case_pattern("ravi.kumar"), CasePattern::Lower);
        assert_eq!(case_pattern("Ravi"), CasePattern::Title);
        assert_eq!(case_pattern("McCarthy"), CasePattern::Title);
        assert_eq!(case_pattern("R."), CasePattern::Title);
        assert_eq!(case_pattern("रवि 123"), CasePattern::None);
    }

    #[test]
    fn apply() {
        assert_eq!(apply_case("RAVI", "Arjun"), "ARJUN");
        assert_eq!(apply_case("ravi", "Arjun"), "arjun");
        assert_eq!(apply_case("Ravi", "arjun"), "Arjun");
        assert_eq!(apply_case("Ravi", "McCarthy"), "McCarthy");
        assert_eq!(apply_case("Ravi Kumar", "RAVI KUMAR"), "Ravi Kumar");
        assert_eq!(apply_case("Arjun", "ravi kumar"), "Ravi Kumar");
        assert_eq!(apply_case("रवि", "Arjun"), "Arjun");
        assert_eq!(apply_case("ÉLODIE", "émile"), "ÉMILE");
    }
}
