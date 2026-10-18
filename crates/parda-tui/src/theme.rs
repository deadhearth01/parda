//! `NO_COLOR` and `PARDA_ASCII=1`.
//!
//! Widgets are drawn with colours and Unicode as usual; [`Theme::finish`]
//! then rewrites the frame: without colour, every colour is dropped and
//! emphasis is kept with bold / reversed (a coloured background, such as
//! the protection badge, becomes reversed video); in ASCII mode box drawing,
//! bars, bullets and arrows become plain ASCII. One pass over the cells,
//! so no widget can forget a fallback.

use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub color: bool,
    pub ascii: bool,
}

impl Default for Theme {
    fn default() -> Self {
        Theme {
            color: true,
            ascii: false,
        }
    }
}

impl Theme {
    /// `NO_COLOR` (any non-empty value) and `PARDA_ASCII=1`.
    pub fn from_env() -> Self {
        Self::from_vars(
            std::env::var_os("NO_COLOR").map(|v| v.to_string_lossy().into_owned()),
            std::env::var("PARDA_ASCII").ok(),
        )
    }

    pub fn from_vars(no_color: Option<String>, ascii: Option<String>) -> Self {
        Theme {
            color: no_color.is_none_or(|v| v.is_empty()),
            ascii: ascii.is_some_and(|v| v.trim() == "1"),
        }
    }

    /// The text cursor of an input.
    pub fn cursor(&self) -> &'static str {
        if self.ascii { "_" } else { "▏" }
    }

    /// Spinner frames for work in progress.
    pub fn spinner(&self, tick: usize) -> &'static str {
        const UNI: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        const ASC: [&str; 4] = ["|", "/", "-", "\\"];
        if self.ascii {
            ASC[tick % ASC.len()]
        } else {
            UNI[tick % UNI.len()]
        }
    }

    /// Apply the fallbacks to a drawn frame. Cells inside `text` (user and
    /// answer text) keep their characters in ASCII mode.
    pub fn finish(&self, buf: &mut Buffer, text: &[ratatui::layout::Rect]) {
        if self.color && !self.ascii {
            return;
        }
        let area = buf.area;
        for (i, cell) in buf.content.iter_mut().enumerate() {
            let at = ratatui::layout::Position::new(
                area.x + (i as u16 % area.width.max(1)),
                area.y + (i as u16 / area.width.max(1)),
            );
            let keep_text = text.iter().any(|r| r.contains(at));
            if !self.color {
                let mut m = cell.modifier;
                if cell.bg != Color::Reset {
                    m |= Modifier::REVERSED | Modifier::BOLD;
                }
                if matches!(cell.fg, Color::Red | Color::LightRed | Color::Yellow) {
                    m |= Modifier::BOLD;
                }
                cell.fg = Color::Reset;
                cell.bg = Color::Reset;
                cell.modifier = m;
            }
            if self.ascii
                && !keep_text
                && let Some(a) = ascii_for(cell.symbol())
            {
                cell.set_symbol(a);
            }
        }
    }
}

/// ASCII stand-in for a drawing symbol (None: keep it).
fn ascii_for(sym: &str) -> Option<&'static str> {
    let mut chars = sym.chars();
    let c = chars.next()?;
    if chars.next().is_some() || c.is_ascii() {
        return None;
    }
    Some(match c {
        '─' | '━' | '═' | '╌' | '┄' => "-",
        '│' | '┃' | '║' | '╎' | '┆' | '▏' | '▕' => "|",
        '┌' | '┐' | '└' | '┘' | '├' | '┤' | '┬' | '┴' | '┼' | '╭' | '╮' | '╯' | '╰' | '╔' | '╗'
        | '╚' | '╝' => "+",
        '▁' | '▂' => ".",
        '▃' | '▄' => ":",
        '▅' | '▆' => "=",
        '▇' | '█' | '■' => "#",
        '●' | '◆' | '•' => "*",
        '○' | '□' | '◇' => "o",
        '·' => ".",
        '—' | '–' => "-",
        '→' | '▶' | '›' => ">",
        '←' | '◀' | '‹' => "<",
        '↑' => "^",
        '↓' => "v",
        '↻' => "~",
        '…' => "~",
        '⇄' => "=",
        '×' => "x",
        '✓' => "+",
        '✗' => "x",
        '✎' => "=",
        '◌' => "o",
        '⠋' | '⠙' | '⠹' | '⠸' | '⠼' | '⠴' | '⠦' | '⠧' | '⠇' | '⠏' => "*",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::layout::Rect;
    use ratatui::style::Style;

    #[test]
    fn env_rules() {
        assert_eq!(Theme::from_vars(None, None), Theme::default());
        assert!(!Theme::from_vars(Some("1".into()), None).color);
        // NO_COLOR="" does not count (no-color.org).
        assert!(Theme::from_vars(Some(String::new()), None).color);
        assert!(Theme::from_vars(None, Some("1".into())).ascii);
        assert!(!Theme::from_vars(None, Some("0".into())).ascii);
    }

    #[test]
    fn mono_drops_colour_but_keeps_emphasis() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 3, 1));
        buf[(0, 0)].set_style(Style::default().fg(Color::Black).bg(Color::Green));
        buf[(1, 0)].set_style(Style::default().fg(Color::Red));
        buf[(2, 0)].set_style(Style::default().fg(Color::Cyan));
        Theme::from_vars(Some("1".into()), None).finish(&mut buf, &[]);
        for x in 0..3 {
            assert_eq!(buf[(x, 0)].fg, Color::Reset);
            assert_eq!(buf[(x, 0)].bg, Color::Reset);
        }
        assert!(buf[(0, 0)].modifier.contains(Modifier::REVERSED));
        assert!(buf[(1, 0)].modifier.contains(Modifier::BOLD));
        assert!(buf[(2, 0)].modifier.is_empty());
    }

    #[test]
    fn ascii_replaces_drawing_but_not_text() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 6, 1));
        for (x, s) in ["┌", "─", "●", "→", "é", "ज"].iter().enumerate() {
            buf[(x as u16, 0)].set_symbol(s);
        }
        Theme::from_vars(None, Some("1".into())).finish(&mut buf, &[]);
        let row: String = (0..6).map(|x| buf[(x, 0)].symbol().to_string()).collect();
        assert_eq!(row, "+-*>éज");
    }
}
