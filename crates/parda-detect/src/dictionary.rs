//! Tier 0: the user's own dictionary.
//!
//! `rules.toml` holds person blocks (a person the user names, expanded into
//! the variants people actually type), literal terms, and an allow-list. This
//! module owns the file model and the Aho-Corasick detector built from it; the
//! allow-list filter lives in [`crate::allow`].

use std::collections::HashSet;

use aho_corasick::{AhoCorasick, Input, MatchKind};
use parda_core::{Detection, EntityKind, Error, Result, Source, Span};
use serde::{Deserialize, Serialize};

use crate::Detector;

/// The user's `rules.toml`: `[[person]]` and `[[term]]` tables plus a
/// top-level `allow = [...]` array.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesFile {
    #[serde(default)]
    pub person: Vec<PersonBlock>,
    #[serde(default)]
    pub term: Vec<Term>,
    #[serde(default)]
    pub allow: Vec<String>,
}

/// A person the user wants masked, with optional extra identifiers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonBlock {
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(default)]
    pub handles: Vec<String>,
}

/// A literal string to mask, reported as `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Term {
    pub text: String,
    #[serde(default = "default_term_kind")]
    pub kind: EntityKind,
}

fn default_term_kind() -> EntityKind {
    EntityKind::Custom("term".into())
}

impl Default for Term {
    fn default() -> Self {
        Term {
            text: String::new(),
            kind: default_term_kind(),
        }
    }
}

impl RulesFile {
    /// Parse a `rules.toml`. Errors carry the TOML message and line number but
    /// never the offending text, which may be personal data.
    pub fn from_toml_str(s: &str) -> Result<RulesFile> {
        toml::from_str(s).map_err(|e| {
            let line = e.span().map(|span| {
                let upto = span.start.min(s.len());
                s.as_bytes()[..upto].iter().filter(|&&b| b == b'\n').count() + 1
            });
            match line {
                Some(line) => Error::Config(format!("rules file, line {line}: {}", e.message())),
                None => Error::Config(format!("rules file: {}", e.message())),
            }
        })
    }

    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string(self).map_err(|e| Error::Config(format!("serialising rules file: {e}")))
    }
}

/// Standalone first/last name tokens that are also everyday words, particles
/// or honorifics. Matching them on their own would mask ordinary prose.
const STOPLIST: &[&str] = &[
    "an", "al", "li", "de", "la", "le", "van", "von", "da", "di", "do", "dr", "mr", "ms", "mrs",
    "sir", "madam", "ji", "bhai", "didi", "raja", "rani", "prem", "deep", "will", "mark", "may",
    "june", "april", "grace", "hope", "joy", "rose", "king", "young", "long", "little", "white",
    "black", "brown", "green", "gold", "rich", "bill", "frank", "sunny", "miss", "prof", "shri",
    "smt",
];

/// Titles dropped from the front of a name before variants are derived (the
/// name as written is still matched verbatim).
const HONORIFICS: &[&str] = &[
    "dr", "mr", "mrs", "ms", "miss", "sir", "madam", "shri", "smt", "prof",
];

/// Shortest standalone first/last name, in characters.
const MIN_STANDALONE_CHARS: usize = 3;
/// Shortest auto-generated variant, in characters.
const MIN_VARIANT_CHARS: usize = 4;
/// Shortest auto-generated variant without a separator ("ravisharma"); such
/// strings are the likeliest to collide with ordinary words.
const MIN_JOINED_CHARS: usize = 6;

/// Collects `(text, kind)` pairs, dropping blanks and case-insensitive repeats.
#[derive(Default)]
struct Entries {
    seen: HashSet<String>,
    items: Vec<(String, EntityKind)>,
}

impl Entries {
    fn add(&mut self, text: &str, kind: &EntityKind) {
        let text = text.trim();
        if text.is_empty() || !self.seen.insert(text.to_ascii_lowercase()) {
            return;
        }
        self.items.push((text.to_string(), kind.clone()));
    }
}

fn is_stoplisted(token: &str) -> bool {
    let lower = token.to_lowercase();
    STOPLIST.contains(&lower.as_str())
}

fn is_honorific(token: &str) -> bool {
    let lower = token.to_lowercase();
    HONORIFICS.contains(&lower.as_str())
}

fn standalone_ok(token: &str) -> bool {
    token.chars().count() >= MIN_STANDALONE_CHARS && !is_stoplisted(token)
}

/// Add a derived variant if it is long enough to be safe.
fn add_variant(out: &mut Entries, text: &str, joined: bool) {
    let min = if joined {
        MIN_JOINED_CHARS
    } else {
        MIN_VARIANT_CHARS
    };
    if text.chars().count() >= min {
        out.add(text, &EntityKind::Person);
    }
}

fn person_entries(p: &PersonBlock) -> Vec<(String, EntityKind)> {
    let mut out = Entries::default();
    let raw = p.name.trim();
    out.add(raw, &EntityKind::Person);
    out.add(
        &raw.split_whitespace().collect::<Vec<_>>().join(" "),
        &EntityKind::Person,
    );

    let cleaned: Vec<&str> = raw
        .split_whitespace()
        .map(|t| t.trim_matches(|c: char| c.is_ascii_punctuation()))
        .filter(|t| !t.is_empty())
        .collect();
    let skip = (0..cleaned.len().saturating_sub(1))
        .take_while(|&i| is_honorific(cleaned[i]))
        .count();
    let tokens = &cleaned[skip..];

    if let [first, .., last] = tokens {
        let n = tokens.len();
        let (first, last) = (*first, *last);
        let (fl, ll) = (first.to_lowercase(), last.to_lowercase());

        add_variant(&mut out, &format!("{first} {last}"), false);
        if n >= 3 {
            add_variant(&mut out, &format!("{first} {}", tokens[1]), false);
        }
        add_variant(&mut out, &format!("{fl}.{ll}"), false);
        add_variant(&mut out, &format!("{fl}_{ll}"), false);
        add_variant(&mut out, &format!("{fl}{ll}"), true);

        // Initials + last name: the first initial alone ("R. Sharma",
        // "r.sharma") and all given-name initials ("RK Sharma"). Only when
        // every initial is a plain ASCII letter (splitting a Devanagari
        // cluster would produce junk).
        for given in [&tokens[..1], &tokens[..n - 1]] {
            let initials: Option<Vec<char>> = given
                .iter()
                .map(|t| {
                    t.chars()
                        .next()
                        .filter(char::is_ascii_alphabetic)
                        .map(|c| c.to_ascii_uppercase())
                })
                .collect();
            let Some(ini) = initials else { continue };
            let joined: String = ini.iter().collect();
            let dotted: String = ini.iter().map(|c| format!("{c}.")).collect();
            let spaced = ini
                .iter()
                .map(|c| format!("{c}."))
                .collect::<Vec<_>>()
                .join(" ");
            let lower = joined.to_lowercase();
            add_variant(&mut out, &format!("{joined} {last}"), false);
            add_variant(&mut out, &format!("{dotted} {last}"), false);
            add_variant(&mut out, &format!("{spaced} {last}"), false);
            add_variant(&mut out, &format!("{dotted}{last}"), false);
            add_variant(&mut out, &format!("{lower}.{ll}"), false);
            add_variant(&mut out, &format!("{lower}{ll}"), true);
        }

        if standalone_ok(first) {
            out.add(first, &EntityKind::Person);
        }
        if standalone_ok(last) {
            out.add(last, &EntityKind::Person);
        }
    }

    for alias in &p.aliases {
        out.add(alias, &EntityKind::Person);
    }
    for email in &p.emails {
        out.add(email, &EntityKind::Email);
    }
    let handle_kind = EntityKind::Custom("Handle".into());
    for handle in &p.handles {
        out.add(handle, &handle_kind);
        // "@ravik" is also written "ravik" (GitHub, chat IDs, …).
        if let Some(bare) = handle.trim().strip_prefix('@')
            && bare.chars().count() >= MIN_STANDALONE_CHARS
        {
            out.add(bare, &handle_kind);
        }
    }
    out.items
}

/// Every string a person block should mask: the name and its common variants
/// (full name, first, last, `first.last`, `first_last`, `firstlast`, initials +
/// last name, …), then aliases, emails and handles.
///
/// Standalone first/last names are only included when they are at least three
/// characters and not a common word (see the stoplist), so "Will" or "Al" are
/// never masked on their own. The name exactly as written is always kept.
pub fn expand_person(p: &PersonBlock) -> Vec<String> {
    person_entries(p)
        .into_iter()
        .map(|(text, _)| text)
        .collect()
}

/// A letter or digit next to a match means the match is part of a larger word.
pub(crate) fn word_bounded(text: &str, start: usize, end: usize) -> bool {
    !text[..start]
        .chars()
        .next_back()
        .is_some_and(char::is_alphanumeric)
        && !text[end..]
            .chars()
            .next()
            .is_some_and(char::is_alphanumeric)
}

/// `pattern` itself, plus lower- and upper-cased forms when it contains
/// non-ASCII text (the automaton only folds ASCII case).
pub(crate) fn with_case_variants(pattern: &str) -> Vec<String> {
    let mut v = vec![pattern.to_string()];
    if !pattern.is_ascii() {
        for alt in [pattern.to_lowercase(), pattern.to_uppercase()] {
            if !v.contains(&alt) {
                v.push(alt);
            }
        }
    }
    v
}

/// Finds the user's terms and person-block variants. Case-insensitive,
/// leftmost-longest, and only at word boundaries.
pub struct DictionaryDetector {
    matcher: Option<AhoCorasick>,
    kinds: Vec<EntityKind>,
}

impl DictionaryDetector {
    /// Compile `rules` into a detector. Explicit terms take precedence over
    /// auto-generated person variants with the same text.
    ///
    /// # Panics
    /// Only if the automaton cannot be built (a pattern set beyond the
    /// library's size limits). A privacy filter must not silently run with an
    /// empty dictionary, so this fails loudly instead.
    pub fn new(rules: &RulesFile) -> Self {
        let mut entries = Entries::default();
        for term in &rules.term {
            entries.add(&term.text, &term.kind);
        }
        for person in &rules.person {
            for (text, kind) in person_entries(person) {
                entries.add(&text, &kind);
            }
        }

        let mut patterns = Vec::new();
        let mut kinds = Vec::new();
        for (text, kind) in &entries.items {
            for variant in with_case_variants(text) {
                patterns.push(variant);
                kinds.push(kind.clone());
            }
        }
        if patterns.is_empty() {
            return Self {
                matcher: None,
                kinds,
            };
        }
        let matcher = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .ascii_case_insensitive(true)
            .build(&patterns)
            .expect("dictionary automaton must build");
        Self {
            matcher: Some(matcher),
            kinds,
        }
    }
}

impl Detector for DictionaryDetector {
    fn name(&self) -> &str {
        "dictionary"
    }

    fn detect(&self, text: &str) -> Vec<Detection> {
        let Some(matcher) = &self.matcher else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < text.len() {
            let Some(m) = matcher.find(Input::new(text).span(pos..text.len())) else {
                break;
            };
            let start = m.start();
            let (mut end, mut pattern) = (m.end(), m.pattern());
            loop {
                if word_bounded(text, start, end) {
                    out.push(Detection {
                        span: Span { start, end },
                        kind: self.kinds[pattern.as_usize()].clone(),
                        score: 1.0,
                        source: Source::Dictionary,
                    });
                    pos = end;
                    break;
                }
                // The longest match sits inside a larger word. A shorter
                // pattern starting at the same place may still stand alone.
                let limit = text[..end]
                    .char_indices()
                    .next_back()
                    .map_or(start, |(i, _)| i);
                let shorter = if limit > start {
                    matcher
                        .find(Input::new(text).span(start..limit))
                        .filter(|s| s.start() == start)
                } else {
                    None
                };
                match shorter {
                    Some(s) => {
                        end = s.end();
                        pattern = s.pattern();
                    }
                    None => {
                        pos = start + text[start..].chars().next().map_or(1, char::len_utf8);
                        break;
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(name: &str) -> PersonBlock {
        PersonBlock {
            name: name.into(),
            ..Default::default()
        }
    }

    fn detector_for(people: Vec<PersonBlock>) -> DictionaryDetector {
        DictionaryDetector::new(&RulesFile {
            person: people,
            ..Default::default()
        })
    }

    fn texts<'a>(text: &'a str, dets: &[Detection]) -> Vec<&'a str> {
        dets.iter()
            .map(|d| &text[d.span.start..d.span.end])
            .collect()
    }

    #[test]
    fn person_variants() {
        let v = expand_person(&PersonBlock {
            name: "Ravi Kumar Sharma".into(),
            ..Default::default()
        });
        for want in [
            "Ravi Kumar Sharma",
            "Ravi Sharma",
            "ravi.sharma",
            "ravi_sharma",
            "ravisharma",
            "r.sharma",
            "Ravi",
            "Sharma",
        ] {
            assert!(
                v.iter().any(|x| x.eq_ignore_ascii_case(want)),
                "missing {want}: {v:?}"
            );
        }
    }

    #[test]
    fn initials_and_leading_names_are_variants() {
        let v = expand_person(&person("Ravi Kumar Sharma"));
        for want in [
            "Ravi Kumar",
            "R. Sharma",
            "R Sharma",
            "RK Sharma",
            "R.K. Sharma",
        ] {
            assert!(
                v.iter().any(|x| x.eq_ignore_ascii_case(want)),
                "missing {want}: {v:?}"
            );
        }
    }

    #[test]
    fn short_tokens_not_standalone() {
        let v = expand_person(&PersonBlock {
            name: "Al Li".into(),
            ..Default::default()
        });
        assert!(!v.iter().any(|x| x == "Al" || x == "Li"));
        // The name the user wrote is always kept.
        assert!(v.iter().any(|x| x == "Al Li"));
    }

    #[test]
    fn common_word_tokens_not_standalone() {
        let v = expand_person(&person("Will Smith"));
        assert!(!v.iter().any(|x| x.eq_ignore_ascii_case("will")), "{v:?}");
        assert!(v.iter().any(|x| x.eq_ignore_ascii_case("smith")), "{v:?}");
        let v = expand_person(&person("Mark Rich"));
        assert!(!v.iter().any(|x| x.eq_ignore_ascii_case("mark")), "{v:?}");
        assert!(!v.iter().any(|x| x.eq_ignore_ascii_case("rich")), "{v:?}");
        assert!(v.iter().any(|x| x.eq_ignore_ascii_case("Mark Rich")));
    }

    #[test]
    fn honorific_is_not_a_name_token() {
        let v = expand_person(&person("Dr. Ravi Kumar"));
        assert!(
            v.iter().any(|x| x.eq_ignore_ascii_case("Dr. Ravi Kumar")),
            "{v:?}"
        );
        assert!(
            v.iter().any(|x| x.eq_ignore_ascii_case("ravi.kumar")),
            "{v:?}"
        );
        assert!(v.iter().any(|x| x == "Ravi"), "{v:?}");
        assert!(!v.iter().any(|x| x.eq_ignore_ascii_case("dr")), "{v:?}");
    }

    #[test]
    fn single_token_name_is_kept_verbatim() {
        let v = expand_person(&person("Priyanka"));
        assert_eq!(v, vec!["Priyanka".to_string()]);
        assert!(expand_person(&person("   ")).is_empty());
    }

    #[test]
    fn aliases_emails_and_handles_are_expanded() {
        let p = PersonBlock {
            name: "Ravi Kumar".into(),
            aliases: vec!["Ravi bhai".into(), "RK".into()],
            emails: vec!["ravi@example.com".into()],
            handles: vec!["@ravik".into()],
        };
        let v = expand_person(&p);
        for want in ["Ravi bhai", "RK", "ravi@example.com", "@ravik", "ravik"] {
            assert!(v.iter().any(|x| x == want), "missing {want}: {v:?}");
        }
    }

    #[test]
    fn dict_detects_case_insensitive_word_bounded() {
        let rf = RulesFile {
            person: vec![PersonBlock {
                name: "Ravi Kumar".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let d = DictionaryDetector::new(&rf);
        let t = "Ask RAVI KUMAR, not Ravikumarswamy.";
        let found = d.detect(t);
        assert_eq!(found.len(), 1);
        assert_eq!(&t[found[0].span.start..found[0].span.end], "RAVI KUMAR");
    }

    #[test]
    fn detections_are_dictionary_sourced_with_full_score() {
        let d = detector_for(vec![person("Ravi Kumar")]);
        let found = d.detect("hello Ravi Kumar");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].source, Source::Dictionary);
        assert_eq!(found[0].score, 1.0);
        assert_eq!(found[0].kind, EntityKind::Person);
        assert_eq!(d.name(), "dictionary");
    }

    #[test]
    fn kinds_follow_the_entry_type() {
        let rf = RulesFile {
            person: vec![PersonBlock {
                name: "Ravi Kumar".into(),
                aliases: vec![],
                emails: vec!["ravi@example.com".into()],
                handles: vec!["@ravik".into()],
            }],
            term: vec![Term {
                text: "Project Falcon".into(),
                kind: EntityKind::Organization,
            }],
            allow: vec![],
        };
        let d = DictionaryDetector::new(&rf);
        let t = "Ravi Kumar <ravi@example.com> aka @ravik on Project Falcon";
        let found = d.detect(t);
        let pairs: Vec<(&str, EntityKind)> = found
            .iter()
            .map(|x| (&t[x.span.start..x.span.end], x.kind.clone()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("Ravi Kumar", EntityKind::Person),
                ("ravi@example.com", EntityKind::Email),
                ("@ravik", EntityKind::Custom("Handle".into())),
                ("Project Falcon", EntityKind::Organization),
            ]
        );
    }

    #[test]
    fn leftmost_longest_wins() {
        let d = detector_for(vec![person("Ravi Kumar")]);
        // "Ravi" alone is also a variant; the longer full name must win.
        let t = "Ravi Kumar and Ravi";
        assert_eq!(texts(t, &d.detect(t)), vec!["Ravi Kumar", "Ravi"]);
    }

    #[test]
    fn rejected_long_match_falls_back_to_shorter_bounded_match() {
        let d = detector_for(vec![person("Ravi Kumar")]);
        // "Ravi Kumar" is followed by a letter (rejected) but "Ravi" stands alone.
        let t = "Ravi Kumarx met";
        assert_eq!(texts(t, &d.detect(t)), vec!["Ravi"]);
    }

    #[test]
    fn devanagari_and_emoji_text_gets_exact_byte_spans() {
        let d = detector_for(vec![person("Ravi Kumar"), person("रवि कुमार")]);
        let t = "नमस्ते 👋 Ravi Kumar ने 🙏 रवि कुमार को भेजा";
        let found = d.detect(t);
        assert_eq!(texts(t, &found), vec!["Ravi Kumar", "रवि कुमार"]);
        assert_eq!(found[0].span.start, t.find("Ravi").unwrap());
        assert_eq!(
            found[0].span.end,
            t.find("Ravi").unwrap() + "Ravi Kumar".len()
        );
        assert_eq!(found[1].span.start, t.find("रवि").unwrap());
        assert!(t.is_char_boundary(found[1].span.start) && t.is_char_boundary(found[1].span.end));
    }

    #[test]
    fn neighbouring_non_ascii_letters_block_a_match() {
        let d = detector_for(vec![person("Priyanka")]);
        let t = "Priyankaजी and éPriyanka";
        assert!(d.detect(t).is_empty(), "{:?}", d.detect(t));
        // A danda (sentence punctuation) is not part of the word.
        let t = "मिलो Priyanka।";
        assert_eq!(texts(t, &d.detect(t)), vec!["Priyanka"]);
    }

    #[test]
    fn non_ascii_case_variants_match() {
        let d = DictionaryDetector::new(&RulesFile {
            term: vec![Term {
                text: "José Müller".into(),
                kind: EntityKind::Person,
            }],
            ..Default::default()
        });
        let t = "ask JOSÉ MÜLLER or josé müller";
        assert_eq!(texts(t, &d.detect(t)), vec!["JOSÉ MÜLLER", "josé müller"]);
    }

    #[test]
    fn explicit_term_beats_auto_variant_of_same_text() {
        let rf = RulesFile {
            person: vec![person("Ravi Kumar")],
            term: vec![Term {
                text: "ravi".into(),
                kind: EntityKind::Custom("Codename".into()),
            }],
            allow: vec![],
        };
        let d = DictionaryDetector::new(&rf);
        let found = d.detect("hi Ravi");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, EntityKind::Custom("Codename".into()));
    }

    #[test]
    fn empty_rules_file_finds_nothing() {
        let d = DictionaryDetector::new(&RulesFile::default());
        assert!(d.detect("Ravi Kumar lives at 10 Downing Street").is_empty());
        assert!(d.detect("").is_empty());
        // Blank entries must not turn into match-everything patterns.
        let d = DictionaryDetector::new(&RulesFile {
            person: vec![person("  ")],
            term: vec![Term {
                text: "".into(),
                kind: EntityKind::Person,
            }],
            allow: vec![],
        });
        assert!(d.detect("anything at all").is_empty());
    }

    #[test]
    fn toml_round_trip_with_person_term_and_allow() {
        let rf = RulesFile {
            person: vec![PersonBlock {
                name: "Ravi Kumar Sharma".into(),
                aliases: vec!["RK".into()],
                emails: vec!["ravi@example.com".into()],
                handles: vec!["@ravik".into()],
            }],
            term: vec![
                Term {
                    text: "Project Falcon".into(),
                    kind: EntityKind::Organization,
                },
                Term {
                    text: "EMP-4471".into(),
                    kind: EntityKind::Custom("EmployeeId".into()),
                },
            ],
            allow: vec!["Acme Corp".into(), "Taylor Swift".into()],
        };
        let s = rf.to_toml_string().unwrap();
        let back = RulesFile::from_toml_str(&s).unwrap();
        assert_eq!(back, rf);
        assert!(
            s.contains("[[person]]") && s.contains("[[term]]") && s.contains("allow"),
            "{s}"
        );
    }

    #[test]
    fn toml_accepts_documented_layout_and_defaults() {
        let rf = RulesFile::from_toml_str(
            r#"
allow = ["Acme Corp"]

[[person]]
name = "Ravi Kumar"
emails = ["ravi@example.com"]

[[term]]
text = "Project Falcon"
kind = "Organization"

[[term]]
text = "Mystery"
"#,
        )
        .unwrap();
        assert_eq!(rf.person[0].name, "Ravi Kumar");
        assert!(rf.person[0].aliases.is_empty() && rf.person[0].handles.is_empty());
        assert_eq!(rf.term[0].kind, EntityKind::Organization);
        assert_eq!(rf.term[1].kind, EntityKind::Custom("term".into()));
        assert_eq!(rf.allow, vec!["Acme Corp".to_string()]);
        assert_eq!(RulesFile::from_toml_str("").unwrap(), RulesFile::default());
    }

    #[test]
    fn invalid_toml_is_a_config_error_without_echoing_content() {
        let err = RulesFile::from_toml_str("[[person]]\nname = Ravi Kumar Secret\n").unwrap_err();
        assert!(matches!(err, parda_core::Error::Config(_)), "{err:?}");
        assert!(!err.to_string().contains("Secret"), "{err}");
        let err = RulesFile::from_toml_str("[[person]]\naliases = []\n").unwrap_err();
        assert!(matches!(err, parda_core::Error::Config(_)));
    }
}
