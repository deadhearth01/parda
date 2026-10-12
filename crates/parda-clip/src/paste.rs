//! Synthesising the platform paste keystroke.

use enigo::{Direction, Enigo, Key, Keyboard, Settings};

pub trait Paster: Send {
    fn paste(&mut self) -> anyhow::Result<()>;
}

/// Sends Cmd+V (macOS) or Ctrl+V. On macOS this needs the Accessibility
/// permission; `parda doctor` explains how to grant it.
#[derive(Default)]
pub struct EnigoPaster;

impl Paster for EnigoPaster {
    fn paste(&mut self) -> anyhow::Result<()> {
        let mut e = Enigo::new(&Settings::default())
            .map_err(|err| anyhow::anyhow!("cannot synthesise keystrokes: {err}"))?;
        let modifier = if cfg!(target_os = "macos") {
            Key::Meta
        } else {
            Key::Control
        };
        let res = (|| {
            e.key(modifier, Direction::Press)?;
            e.key(Key::Unicode('v'), Direction::Click)?;
            e.key(modifier, Direction::Release)
        })();
        // Never leave the modifier stuck down.
        if res.is_err() {
            let _ = e.key(modifier, Direction::Release);
        }
        res.map_err(|err| anyhow::anyhow!("paste keystroke failed: {err}"))
    }
}
