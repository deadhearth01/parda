//! JSON walking for the provider adapters. The generic helpers live in
//! `parda-wire`.
//!
//! A walker visits every redactable string as `&mut String`. Redaction runs
//! it twice in the same order: once to collect the texts (one engine batch),
//! once to write the results back.

pub(crate) use parda_wire::walk::{
    Visit, json_string, leaves, preserve_numbers, str_field, type_of,
};
#[cfg(test)]
use serde_json::Value;

/// What a request walker had to forward without scanning.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unscanned {
    /// Images, audio, binary documents, token ids.
    pub media: u32,
    /// Blocks / parts / items of a type parda does not know.
    pub unknown: u32,
}

impl Unscanned {
    pub(crate) const NONE: Unscanned = Unscanned {
        media: 0,
        unknown: 0,
    };
    pub(crate) const MEDIA: Unscanned = Unscanned {
        media: 1,
        unknown: 0,
    };
    pub(crate) const UNKNOWN: Unscanned = Unscanned {
        media: 0,
        unknown: 1,
    };

    pub(crate) fn total(self) -> u32 {
        self.media + self.unknown
    }
}

impl std::ops::AddAssign for Unscanned {
    fn add_assign(&mut self, o: Unscanned) {
        self.media += o.media;
        self.unknown += o.unknown;
    }
}

impl std::iter::Sum for Unscanned {
    fn sum<I: Iterator<Item = Unscanned>>(iter: I) -> Unscanned {
        let mut t = Unscanned::NONE;
        for u in iter {
            t += u;
        }
        t
    }
}

/// Collect the texts a walker visits (test helper).
#[cfg(test)]
pub(crate) fn collect(v: &mut Value, walker: impl Fn(&mut Value, Visit<'_>)) -> Vec<String> {
    let mut texts = Vec::new();
    walker(v, &mut |s: &mut String| texts.push(s.clone()));
    texts
}
