//! The command palette (`:` or Ctrl-K): every action by name, fuzzy-filtered.

use crate::app::Tab;
use crate::settings::Setting;

/// Something the palette (and some keys) can run.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Tab(Tab),
    Protection,
    /// Flip or cycle one setting, as Enter on its Settings row would.
    Setting(Setting),
    Inspect,
    AddPerson,
    AllowTerm,
    WipeVault,
    PauseLive,
    LiveSurface,
    LiveKind,
    ClearFilters,
    StartDaemon,
    Refresh,
    Help,
    Quit,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub label: String,
    /// The direct key, when there is one ("p", "1" …).
    pub key: &'static str,
    pub action: Action,
}

impl Entry {
    pub fn new(label: impl Into<String>, key: &'static str, action: Action) -> Self {
        Entry {
            label: label.into(),
            key,
            action,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Palette {
    pub query: String,
    /// Index into the filtered list.
    pub sel: usize,
}

/// Score `query` as a case-insensitive subsequence of `label`: None if it
/// is not one; higher is better (consecutive letters and word starts win).
pub fn score(query: &str, label: &str) -> Option<i32> {
    let q: Vec<char> = query
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    if q.is_empty() {
        return Some(0);
    }
    let l: Vec<char> = label.chars().flat_map(char::to_lowercase).collect();
    let mut qi = 0;
    let mut total = 0;
    let mut prev: Option<usize> = None;
    for (i, c) in l.iter().enumerate() {
        if qi < q.len() && *c == q[qi] {
            let word_start = i == 0 || !l[i - 1].is_alphanumeric();
            total += 1;
            if word_start {
                total += 8;
            }
            if prev.is_some_and(|p| p + 1 == i) {
                total += 5;
            }
            prev = Some(i);
            qi += 1;
        }
    }
    if qi < q.len() {
        return None;
    }
    // Prefer matches that start early and labels that are short.
    let first = l.iter().position(|c| *c == q[0]).unwrap_or(0) as i32;
    Some(total * 4 - first - l.len() as i32 / 8)
}

/// The entries matching `query`, best first (ties keep list order).
pub fn filter<'a>(entries: &'a [Entry], query: &str) -> Vec<&'a Entry> {
    let mut scored: Vec<(i32, usize, &Entry)> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| score(query, &e.label).map(|s| (s, i, e)))
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, _, e)| e).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<Entry> {
        vec![
            Entry::new("Go to Dashboard", "1", Action::Tab(Tab::Dashboard)),
            Entry::new("Go to Settings", "6", Action::Tab(Tab::Settings)),
            Entry::new("Protection: turn off", "p", Action::Protection),
            Entry::new("Wipe the vault (asks first)", "", Action::WipeVault),
            Entry::new(
                "AI-site intercept: turn on",
                "",
                Action::Setting(Setting::Intercept),
            ),
        ]
    }

    #[test]
    fn subsequence_matching_is_case_insensitive() {
        assert!(score("gts", "Go to Settings").is_some());
        assert!(score("GTS", "go to settings").is_some());
        assert!(score("xyz", "Go to Settings").is_none());
        assert_eq!(score("", "anything"), Some(0));
    }

    #[test]
    fn best_match_first_and_empty_query_keeps_order() {
        let e = entries();
        let all = filter(&e, "");
        assert_eq!(all.len(), e.len());
        assert_eq!(all[0].label, "Go to Dashboard");
        let f = filter(&e, "wipe");
        assert_eq!(f[0].action, Action::WipeVault);
        let f = filter(&e, "intercept");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].action, Action::Setting(Setting::Intercept));
        // Word starts beat letters scattered inside words.
        let f = filter(&e, "set");
        assert_eq!(f[0].label, "Go to Settings");
        let f = filter(&e, "prot");
        assert_eq!(f[0].action, Action::Protection);
    }
}
