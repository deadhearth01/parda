//! Splitting text into fragments: the unit of ML inference and of the ML
//! cache. The dictionary and rule tiers always run over the whole text, so a
//! fragment edge can never cut a value they would find.
//!
//! Fragments are contiguous, cover the whole text, end on UTF-8 character
//! boundaries and are at most `max_bytes` long. Splits prefer paragraph
//! breaks, then line breaks, then sentence ends, then whitespace; a run with
//! none of those is cut after a non-alphanumeric character when there is one
//! nearby, and mid-word only as a last resort. Small neighbouring pieces are
//! packed together so a chat message is usually one fragment.
//!
//! [`ml_windows`] turns fragments into the model's input windows: each window
//! after the first also covers the end of the previous fragment, so a name
//! cut by a fragment edge is whole in one of the two windows.

use parda_core::Span;

/// Fragment size used by the engine: comfortably inside a 512-token model
/// window for English and Indic text.
pub const DEFAULT_MAX_FRAGMENT_BYTES: usize = 2000;

/// Bytes each model window repeats from the end of the previous fragment.
pub const ML_WINDOW_OVERLAP: usize = 256;

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

/// Model input windows over `text`, each at most `max_bytes` (minimum 16)
/// long. A text that fits is one window; a longer one is split into
/// fragments of `max_bytes - overlap`, and every window after the first
/// starts up to `overlap` bytes (a quarter of `max_bytes` at most) before its
/// fragment, at a word start when there is one in reach. Windows cover the
/// whole text and every substring shorter than about `overlap / 2` bytes lies
/// entirely inside one window.
pub fn ml_windows(text: &str, max_bytes: usize) -> Vec<Span> {
    let max = max_bytes.max(16);
    if text.len() <= max {
        return if text.is_empty() {
            Vec::new()
        } else {
            vec![Span::new(0, text.len())]
        };
    }
    let overlap = ML_WINDOW_OVERLAP.min(max / 4);
    let mut out = split_fragments(text, max - overlap);
    for w in out.iter_mut().skip(1) {
        let mut start = w.start - overlap;
        while !text.is_char_boundary(start) {
            start += 1;
        }
        // Prefer to begin right after a separator in the first half of the
        // overlap, so the model does not see a word cut in half.
        let mid = start + overlap / 2;
        if let Some((i, c)) = text[start..w.start]
            .char_indices()
            .take_while(|(i, _)| start + i < mid)
            .find(|(_, c)| !c.is_alphanumeric())
        {
            start += i + c.len_utf8();
        }
        w.start = start;
    }
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
        if e < end {
            // Back off to just after a non-alphanumeric character (`"`, `,`,
            // `:`, `/`, …) within the last quarter, so a value is not cut.
            let floor = e.saturating_sub(max / 4).max(s + 1);
            if let Some((i, c)) = text[..e]
                .char_indices()
                .rev()
                .take_while(|(i, _)| *i >= floor)
                .find(|(_, c)| !c.is_alphanumeric())
            {
                e = i + c.len_utf8();
            }
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
    fn hard_split_backs_off_to_a_separator() {
        // Minified JSON: no whitespace at all.
        let text = r#"{"phone":"9876543210","name":"Ravi"},"#.repeat(200);
        for s in check(&text, 100) {
            let piece = &text[s.start..s.end];
            if s.end < text.len() {
                assert!(
                    !piece.ends_with(|c: char| c.is_alphanumeric()),
                    "cut inside a token: {piece:?}"
                );
            }
        }
        // With no separator at all the cut still happens, at `max`.
        let blob = "x".repeat(250);
        assert_eq!(check(&blob, 100).len(), 3);
    }

    #[test]
    fn ml_windows_overlap_and_cover() {
        let text = "Ravi Kumar met Anna Schmidt in Pune. ".repeat(300);
        let max = 500;
        let wins = ml_windows(&text, max);
        assert!(wins.len() > 1);
        assert_eq!(wins[0].start, 0);
        assert_eq!(wins.last().unwrap().end, text.len());
        for w in &wins {
            assert!(w.len() <= max, "{w:?}");
            assert!(text.is_char_boundary(w.start) && text.is_char_boundary(w.end));
        }
        for pair in wins.windows(2) {
            assert!(pair[1].start < pair[0].end, "no overlap: {pair:?}");
            assert!(pair[0].end - pair[1].start + 4 >= ML_WINDOW_OVERLAP.min(max / 4) / 2);
        }
        // Every short substring is whole in some window.
        let probe = 40;
        for at in (0..text.len() - probe).filter(|&i| text.is_char_boundary(i)) {
            assert!(
                wins.iter().any(|w| w.start <= at && at + probe <= w.end),
                "{at}"
            );
        }
        assert_eq!(ml_windows("short", max), vec![Span::new(0, 5)]);
        assert!(ml_windows("", max).is_empty());
        let indic = "नमस्ते Ravi Kumar 🙏 ".repeat(200);
        for w in ml_windows(&indic, 300) {
            assert!(indic.is_char_boundary(w.start) && indic.is_char_boundary(w.end));
        }
    }

    #[test]
    fn devanagari_emoji_boundaries() {
        let text = "नमस्ते Ravi Kumar 🙏\n".repeat(200);
        check(&text, 64);
        check(&text, 2000);
    }
}
