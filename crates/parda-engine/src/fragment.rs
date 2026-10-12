//! Splitting text into fragments: the unit of caching and of ML inference.
//!
//! Fragments are contiguous, cover the whole text, end on UTF-8 character
//! boundaries and are at most `max_bytes` long. Splits prefer paragraph
//! breaks, then line breaks, then sentence ends, then whitespace; only a run
//! with none of those is cut mid-word. Small neighbouring pieces are packed
//! together so a chat message is usually one fragment.

use parda_core::Span;

/// Fragment size used by the engine: comfortably inside a 512-token model
/// window for English and Indic text.
pub const DEFAULT_MAX_FRAGMENT_BYTES: usize = 2000;

const SEPARATORS: &[&[&str]] = &[
    &["\n\n"],
    &["\n"],
    &[". ", "? ", "! ", "। ", "; "],
    &[" ", "\t"],
];

/// Split `text` into contiguous spans of at most `max_bytes` (minimum 16).
pub fn split_fragments(text: &str, max_bytes: usize) -> Vec<Span> {
    let max = max_bytes.max(16);
    let mut out = Vec::new();
    split_level(text, 0, text.len(), max, 0, &mut out);
    out
}

fn split_level(
    text: &str,
    start: usize,
    end: usize,
    max: usize,
    level: usize,
    out: &mut Vec<Span>,
) {
    if end - start <= max {
        if end > start {
            out.push(Span::new(start, end));
        }
        return;
    }
    let Some(seps) = SEPARATORS.get(level) else {
        hard_split(text, start, end, max, out);
        return;
    };
    let seg = &text[start..end];
    // Pieces end right after each separator.
    let mut pieces = Vec::new();
    let mut last = 0;
    let mut i = 0;
    while i < seg.len() {
        if let Some(sep) = seps.iter().find(|s| seg[i..].starts_with(**s)) {
            let cut = i + sep.len();
            pieces.push((last, cut));
            last = cut;
            i = cut;
        } else {
            i += seg[i..].chars().next().map_or(1, char::len_utf8);
        }
    }
    if last < seg.len() {
        pieces.push((last, seg.len()));
    }

    // Greedily pack pieces; oversized pieces go one level down.
    let mut chunk: Option<(usize, usize)> = None;
    for (a, b) in pieces {
        if b - a > max {
            if let Some((cs, ce)) = chunk.take() {
                out.push(Span::new(start + cs, start + ce));
            }
            split_level(text, start + a, start + b, max, level + 1, out);
            continue;
        }
        chunk = match chunk {
            Some((cs, _)) if b - cs <= max => Some((cs, b)),
            Some((cs, ce)) => {
                out.push(Span::new(start + cs, start + ce));
                Some((a, b))
            }
            None => Some((a, b)),
        };
    }
    if let Some((cs, ce)) = chunk {
        out.push(Span::new(start + cs, start + ce));
    }
}

fn hard_split(text: &str, start: usize, end: usize, max: usize, out: &mut Vec<Span>) {
    let mut s = start;
    while s < end {
        let mut e = (s + max).min(end);
        while !text.is_char_boundary(e) {
            e -= 1;
        }
        if e == s {
            e = s + text[s..].chars().next().map_or(1, char::len_utf8);
        }
        out.push(Span::new(s, e));
        s = e;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(text: &str, max: usize) -> Vec<Span> {
        let spans = split_fragments(text, max);
        let mut pos = 0;
        for s in &spans {
            assert_eq!(s.start, pos, "gap or overlap in {spans:?}");
            assert!(s.end > s.start);
            assert!(s.len() <= max.max(16), "{s:?} longer than {max}");
            assert!(text.is_char_boundary(s.start) && text.is_char_boundary(s.end));
            pos = s.end;
        }
        assert_eq!(pos, text.len());
        spans
    }

    #[test]
    fn small_text_is_one_fragment() {
        assert_eq!(check("hello Ravi\n\nbye", 100), vec![Span::new(0, 15)]);
        assert!(split_fragments("", 100).is_empty());
    }

    #[test]
    fn splits_on_paragraphs_then_lines() {
        let text = format!("{}\n\n{}", "a".repeat(30), "b".repeat(30));
        let spans = check(&text, 40);
        assert_eq!(spans.len(), 2);
        assert_eq!(
            &text[spans[0].start..spans[0].end],
            format!("{}\n\n", "a".repeat(30))
        );
        let lines = "line one here\n".repeat(10);
        let spans = check(&lines, 30);
        for s in &spans {
            assert!(lines[s.start..s.end].ends_with('\n'));
        }
    }

    #[test]
    fn long_line_splits_on_sentences_then_words_then_bytes() {
        let text = "Ravi went home. ".repeat(20);
        for s in check(&text, 50) {
            assert!(text[s.start..s.end].ends_with(". "));
        }
        let words = "नमस्ते ".repeat(40);
        check(&words, 50);
        let blob = "x".repeat(100) + &"é".repeat(50);
        check(&blob, 33);
    }

    #[test]
    fn devanagari_emoji_boundaries() {
        let text = "नमस्ते Ravi Kumar 🙏\n".repeat(200);
        check(&text, 64);
        check(&text, 2000);
    }
}
