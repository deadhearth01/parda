//! A single finding: where it is, what it is, and which tier found it.

use serde::{Deserialize, Serialize};

use crate::kind::EntityKind;

/// Half-open byte range `[start, end)` into a UTF-8 string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Span { start, end }
    }

    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn overlaps(&self, other: &Span) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Shift the span by `offset` bytes (used when a fragment is located
    /// inside a larger text).
    pub fn shifted(&self, offset: usize) -> Span {
        Span {
            start: self.start + offset,
            end: self.end + offset,
        }
    }
}

/// Which detection tier produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Source {
    Dictionary,
    Rule { validated: bool },
    Ml,
}

impl Source {
    /// Trust order used when detections overlap: dictionary entries the user
    /// wrote, then checksum-validated rules, then the model, then
    /// pattern-only rules.
    pub fn rank(&self) -> u8 {
        match self {
            Source::Dictionary => 3,
            Source::Rule { validated: true } => 2,
            Source::Ml => 1,
            Source::Rule { validated: false } => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Detection {
    pub span: Span,
    pub kind: EntityKind,
    pub score: f32,
    pub source: Source,
}

impl Detection {
    pub fn text<'a>(&self, haystack: &'a str) -> &'a str {
        &haystack[self.span.start..self.span.end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_overlap() {
        assert!(Span::new(0, 5).overlaps(&Span::new(4, 6)));
        assert!(!Span::new(0, 4).overlaps(&Span::new(4, 6)));
        assert_eq!(Span::new(2, 5).shifted(10), Span::new(12, 15));
    }
}
