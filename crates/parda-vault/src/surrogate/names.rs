//! Name and word lists (compiled in) and person-name surrogates.

use std::collections::HashSet;
use std::sync::OnceLock;

use rand::Rng;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha20Rng;

use super::case::apply_case;

const INDIAN_FIRST: &str = include_str!("../../data/indian_first.txt");
const INDIAN_LAST: &str = include_str!("../../data/indian_last.txt");
const WESTERN_FIRST: &str = include_str!("../../data/western_first.txt");
const WESTERN_LAST: &str = include_str!("../../data/western_last.txt");
const WORDS: &str = include_str!("../../data/words.txt");

/// Titles kept verbatim when a name is replaced.
const HONORIFICS: &[&str] = &[
    "dr", "mr", "mrs", "ms", "miss", "mx", "sir", "madam", "shri", "smt", "sri", "prof", "kumari",
];

pub(crate) struct Lists {
    pub indian_first: Vec<&'static str>,
    pub indian_last: Vec<&'static str>,
    pub western_first: Vec<&'static str>,
    pub western_last: Vec<&'static str>,
    pub words: Vec<&'static str>,
    indian: HashSet<String>,
    western: HashSet<String>,
}

fn parse(text: &'static str) -> Vec<&'static str> {
    let mut seen = HashSet::new();
    text.lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .flat_map(str::split_whitespace)
        .filter(|w| seen.insert(w.to_ascii_lowercase()))
        .collect()
}

pub(crate) fn lists() -> &'static Lists {
    static LISTS: OnceLock<Lists> = OnceLock::new();
    LISTS.get_or_init(|| {
        let lower = |v: &[&str]| v.iter().map(|w| w.to_lowercase()).collect::<Vec<_>>();
        let indian_first = parse(INDIAN_FIRST);
        let indian_last = parse(INDIAN_LAST);
        let western_first = parse(WESTERN_FIRST);
        let western_last = parse(WESTERN_LAST);
        let indian = lower(&indian_first)
            .into_iter()
            .chain(lower(&indian_last))
            .collect();
        let western = lower(&western_first)
            .into_iter()
            .chain(lower(&western_last))
            .collect();
        Lists {
            indian_first,
            indian_last,
            western_first,
            western_last,
            words: parse(WORDS),
            indian,
            western,
        }
    })
}

fn core(token: &str) -> String {
    token
        .trim_matches(|c: char| !c.is_alphanumeric())
        .to_lowercase()
}

/// Is `token` (ignoring case and surrounding punctuation) a known Indian
/// given or family name?
pub fn is_indian_name(token: &str) -> bool {
    lists().indian.contains(&core(token))
}

pub(crate) fn is_western_name(token: &str) -> bool {
    lists().western.contains(&core(token))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    Indian,
    Western,
}

/// Which list a name's replacement is drawn from. Unknown names default to
/// Indian (parda is India-first); a name with more Western than Indian
/// tokens gets a Western replacement.
pub(crate) fn origin_of<'a>(tokens: impl IntoIterator<Item = &'a str>) -> Origin {
    let (mut indian, mut western) = (0, 0);
    for t in tokens {
        indian += usize::from(is_indian_name(t));
        western += usize::from(is_western_name(t));
    }
    if western > indian {
        Origin::Western
    } else {
        Origin::Indian
    }
}

fn is_honorific(token: &str) -> bool {
    HONORIFICS.contains(&core(token).as_str())
}

/// A single letter, optionally followed by a dot: `R`, `R.`.
fn is_initial(token: &str) -> bool {
    token.chars().filter(|c| c.is_alphabetic()).count() == 1
}

fn pick<'a>(rng: &mut ChaCha20Rng, list: &[&'a str], avoid: &[String]) -> &'a str {
    for _ in 0..32 {
        let w = list.choose(rng).copied().unwrap_or("Arjun");
        if !avoid.iter().any(|a| a.eq_ignore_ascii_case(w)) {
            return w;
        }
    }
    list.iter()
        .copied()
        .find(|w| !avoid.iter().any(|a| a.eq_ignore_ascii_case(w)))
        .unwrap_or("Arjun")
}

/// Replace every word of a person's name, keeping the number of words, the
/// spacing, honorifics, initials-as-initials and the letter case.
pub(crate) fn person(real: &str, rng: &mut ChaCha20Rng) -> String {
    let tokens: Vec<&str> = real.split_whitespace().collect();
    let origin = origin_of(tokens.iter().copied());
    let l = lists();
    let (firsts, lasts) = match origin {
        Origin::Indian => (&l.indian_first, &l.indian_last),
        Origin::Western => (&l.western_first, &l.western_last),
    };
    let name_like: Vec<usize> = (0..tokens.len())
        .filter(|&i| !is_honorific(tokens[i]) && !is_initial(tokens[i]))
        .collect();
    // Words of the real name, so no surrogate word repeats a real one.
    let mut avoid: Vec<String> = tokens.iter().map(|t| core(t)).collect();

    let replace = |i: usize, tok: &str, rng: &mut ChaCha20Rng, avoid: &mut Vec<String>| {
        if is_honorific(tok) {
            return tok.to_string();
        }
        let start = tok.find(|c: char| c.is_alphanumeric()).unwrap_or(0);
        let end = tok
            .rfind(|c: char| c.is_alphanumeric())
            .map_or(tok.len(), |e| {
                e + tok[e..].chars().next().map_or(1, char::len_utf8)
            });
        let (pre, body, post) = (&tok[..start], &tok[start..end], &tok[end..]);
        let word = if is_initial(tok) {
            let c = char::from(b'A' + rng.gen_range(0..26u8));
            c.to_string()
        } else {
            let is_last = name_like.len() >= 2 && name_like.last() == Some(&i);
            let lone_family_name = name_like.len() == 1
                && lasts.iter().any(|w| w.eq_ignore_ascii_case(&core(tok)))
                && !firsts.iter().any(|w| w.eq_ignore_ascii_case(&core(tok)));
            let list = if is_last || lone_family_name {
                lasts
            } else {
                firsts
            };
            let w = pick(rng, list, avoid);
            avoid.push(w.to_lowercase());
            w.to_string()
        };
        format!("{pre}{}{post}", apply_case(body, &word))
    };

    if tokens.is_empty() {
        return pick(rng, firsts, &avoid).to_string();
    }
    // Rebuild in place so the original whitespace survives.
    let mut out = String::with_capacity(real.len() + 8);
    let mut i = 0;
    let mut rest = real;
    while !rest.is_empty() {
        let ws_end = rest
            .find(|c: char| !c.is_whitespace())
            .unwrap_or(rest.len());
        out.push_str(&rest[..ws_end]);
        rest = &rest[ws_end..];
        if rest.is_empty() {
            break;
        }
        let tok_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        out.push_str(&replace(i, &rest[..tok_end], rng, &mut avoid));
        rest = &rest[tok_end..];
        i += 1;
    }
    out
}

/// A lower-case first name, for e-mail and UPI local parts.
pub(crate) fn first_name(rng: &mut ChaCha20Rng, origin: Origin) -> String {
    let l = lists();
    let list = match origin {
        Origin::Indian => &l.indian_first,
        Origin::Western => &l.western_first,
    };
    list.choose(rng).copied().unwrap_or("arjun").to_lowercase()
}

/// A lower-case family name, for e-mail and UPI local parts.
pub(crate) fn last_name(rng: &mut ChaCha20Rng, origin: Origin) -> String {
    let l = lists();
    let list = match origin {
        Origin::Indian => &l.indian_last,
        Origin::Western => &l.western_last,
    };
    list.choose(rng).copied().unwrap_or("mehta").to_lowercase()
}

pub(crate) fn word(rng: &mut ChaCha20Rng) -> &'static str {
    lists().words.choose(rng).copied().unwrap_or("maple")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn list_sizes() {
        let l = lists();
        assert!(l.indian_first.len() >= 300, "{}", l.indian_first.len());
        assert!(l.indian_last.len() >= 300, "{}", l.indian_last.len());
        assert!(l.western_first.len() >= 300, "{}", l.western_first.len());
        assert!(l.western_last.len() >= 300, "{}", l.western_last.len());
        assert!(l.words.len() >= 500, "{}", l.words.len());
    }

    #[test]
    fn names_are_long_and_not_everyday_words() {
        // Surrogates are restored by word matching, so a surrogate that is
        // also an ordinary word would rewrite unrelated text.
        const EVERYDAY: &[&str] = &[
            "will", "mark", "grace", "hope", "joy", "rose", "may", "june", "april", "bill",
            "frank", "rich", "king", "young", "long", "white", "black", "brown", "green", "gold",
            "julia", "hugo", "rust", "ruby", "kelvin", "levy", "lynch", "bonnet", "kale", "mane",
            "pant", "gill", "harsh", "prem", "deep", "raja", "rani", "max",
        ];
        let l = lists();
        for list in [
            &l.indian_first,
            &l.indian_last,
            &l.western_first,
            &l.western_last,
        ] {
            for w in list.iter() {
                assert!(w.chars().count() >= 4, "too short: {w}");
                assert!(
                    w.chars().all(|c| c.is_ascii_alphabetic()),
                    "not plain ASCII: {w}"
                );
                assert!(
                    !EVERYDAY.contains(&w.to_lowercase().as_str()),
                    "everyday word: {w}"
                );
            }
        }
    }

    #[test]
    fn origin_detection() {
        assert_eq!(origin_of(["Priya", "Sharma"]), Origin::Indian);
        assert_eq!(origin_of(["Siobhan", "Fitzgerald"]), Origin::Western);
        assert_eq!(origin_of(["Zxqv"]), Origin::Indian);
        assert!(is_indian_name("Sharma,"));
        assert!(!is_indian_name("table"));
    }

    #[test]
    fn person_keeps_honorifics_initials_and_spacing() {
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let s = person("Dr.  R. Sharma", &mut rng);
        let parts: Vec<&str> = s.split(' ').collect();
        assert_eq!(parts.len(), 4, "{s}");
        assert_eq!(parts[0], "Dr.");
        assert_eq!(parts[1], "");
        assert_eq!(parts[2].len(), 2);
        assert!(parts[2].ends_with('.'));
        assert!(is_indian_name(parts[3]), "{s}");
        assert_ne!(parts[3], "Sharma");
    }
}
