//! Per-scope in-memory view of the vault: lookups by real value and by
//! surrogate (both case-insensitive) and the lazily rebuilt restore table.

use std::collections::HashMap;
use std::sync::Arc;

use parda_core::EntityKind;

use crate::restore::{Entry, RestoreTable};

#[derive(Default)]
pub(crate) struct ScopeIndex {
    entries: Vec<Entry>,
    by_real: HashMap<String, Vec<usize>>,
    by_sur: HashMap<String, Vec<usize>>,
    table: Option<Arc<RestoreTable>>,
}

impl ScopeIndex {
    pub(crate) fn from_entries(entries: Vec<Entry>) -> Self {
        let mut idx = ScopeIndex::default();
        for e in entries {
            idx.add(e);
        }
        idx
    }

    pub(crate) fn add(&mut self, e: Entry) {
        let i = self.entries.len();
        self.by_real
            .entry(e.real.to_lowercase())
            .or_default()
            .push(i);
        self.by_sur
            .entry(e.surrogate.to_lowercase())
            .or_default()
            .push(i);
        self.entries.push(e);
        self.table = None;
    }

    /// The mapping for exactly `real`.
    pub(crate) fn exact(&self, real: &str) -> Option<&Entry> {
        self.by_real
            .get(&real.to_lowercase())?
            .iter()
            .map(|&i| &self.entries[i])
            .find(|e| e.real == real)
    }

    /// A mapping for `real` written in any case.
    pub(crate) fn variant(&self, real: &str) -> Option<&Entry> {
        let ids = self.by_real.get(&real.to_lowercase())?;
        ids.first().map(|&i| &self.entries[i])
    }

    /// Would `candidate` be ambiguous as a surrogate for `real`? True when it
    /// already stands for a different value, or equals some real value.
    pub(crate) fn conflicts(&self, candidate: &str, real: &str) -> bool {
        let cand = candidate.to_lowercase();
        let real = real.to_lowercase();
        if cand == real {
            return true;
        }
        let taken = self.by_sur.get(&cand).is_some_and(|ids| {
            ids.iter()
                .any(|&i| self.entries[i].real.to_lowercase() != real)
        });
        taken || self.by_real.contains_key(&cand)
    }

    /// Next free number for a `[LABEL_n]` tag of `kind`.
    pub(crate) fn next_token_number(&self, kind: &EntityKind) -> u32 {
        let prefix = format!("[{}_", kind.tag_label());
        self.entries
            .iter()
            .filter_map(|e| {
                e.surrogate
                    .strip_prefix(&prefix)?
                    .strip_suffix(']')?
                    .parse::<u32>()
                    .ok()
            })
            .max()
            .unwrap_or(0)
            + 1
    }

    pub(crate) fn table(&mut self) -> Arc<RestoreTable> {
        if let Some(t) = &self.table {
            return t.clone();
        }
        let t = Arc::new(RestoreTable::build(&self.entries));
        self.table = Some(t.clone());
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(s: &str, r: &str) -> Entry {
        Entry {
            surrogate: s.into(),
            real: r.into(),
            kind: EntityKind::Person,
        }
    }

    #[test]
    fn lookups_and_conflicts() {
        let idx =
            ScopeIndex::from_entries(vec![e("Arjun Mehta", "Ravi Kumar"), e("Arjun", "Ravi")]);
        assert_eq!(idx.exact("Ravi Kumar").unwrap().surrogate, "Arjun Mehta");
        assert!(idx.exact("RAVI KUMAR").is_none());
        assert_eq!(idx.variant("RAVI KUMAR").unwrap().surrogate, "Arjun Mehta");
        // Same person in another case may share the surrogate.
        assert!(!idx.conflicts("ARJUN MEHTA", "RAVI KUMAR"));
        // A different person may not.
        assert!(idx.conflicts("arjun mehta", "Amit Shah"));
        // Nor may a surrogate equal to a real value.
        assert!(idx.conflicts("Ravi", "Amit"));
        assert!(!idx.conflicts("Kiran", "Amit"));
    }

    #[test]
    fn token_numbers() {
        let mut idx = ScopeIndex::default();
        assert_eq!(idx.next_token_number(&EntityKind::Email), 1);
        idx.add(Entry {
            surrogate: "[EMAIL_4]".into(),
            real: "a@b.c".into(),
            kind: EntityKind::Email,
        });
        assert_eq!(idx.next_token_number(&EntityKind::Email), 5);
        assert_eq!(idx.next_token_number(&EntityKind::Person), 1);
    }
}
