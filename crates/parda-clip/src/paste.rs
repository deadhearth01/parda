//! Synthesising the platform paste keystroke.

use std::time::{Duration, Instant};

use enigo::{Direction, Enigo, Key, Keyboard, Settings};

pub trait Paster: Send {
    fn paste(&mut self) -> anyhow::Result<()>;
}

/// How long to wait for the user to let go of the hotkey's modifiers.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(1);
/// Where the key state cannot be read (X11, Wayland): a short pause.
const UNKNOWN_STATE_PAUSE: Duration = Duration::from_millis(150);

/// Sends Cmd+V (macOS) or Ctrl+V. On macOS this needs the Accessibility
/// permission; `parda doctor` explains how to grant it.
#[derive(Default)]
pub struct EnigoPaster;

impl Paster for EnigoPaster {
    fn paste(&mut self) -> anyhow::Result<()> {
        // The hotkey fires on key release, but Cmd/Ctrl+Alt may still be
        // down: a synthetic V would then become Cmd+Alt+V (on Windows the
        // hotkey itself, swallowed or re-triggered).
        if !wait_for_release(modifiers_held, RELEASE_TIMEOUT) {
            anyhow::bail!("the hotkey's modifier keys are still held down");
        }
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

/// Wait until `held` reports no modifier key down, for at most `timeout`.
/// `held` returns `None` where the state cannot be read; then a short pause
/// stands in. Returns false if modifiers were still down at the deadline.
pub(crate) fn wait_for_release(held: impl Fn() -> Option<bool>, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match held() {
            Some(false) => return true,
            None => {
                std::thread::sleep(UNKNOWN_STATE_PAUSE);
                return true;
            }
            Some(true) if Instant::now() >= deadline => return false,
            Some(true) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

/// Shift, Control, Option or Command physically held down.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn modifiers_held() -> Option<bool> {
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGEventSourceFlagsState(state_id: i32) -> u64;
    }
    /// kCGEventSourceStateHIDSystemState: the hardware key state.
    const HID_SYSTEM_STATE: i32 = 1;
    /// kCGEventFlagMask{Shift, Control, Alternate, Command}.
    const MODIFIERS: u64 = 0x0002_0000 | 0x0004_0000 | 0x0008_0000 | 0x0010_0000;
    // SAFETY: a side-effect-free query of the current modifier flags; it
    // takes and returns plain integers.
    let flags = unsafe { CGEventSourceFlagsState(HID_SYSTEM_STATE) };
    Some(flags & MODIFIERS != 0)
}

/// Shift, Ctrl, Alt or a Windows key physically held down.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn modifiers_held() -> Option<bool> {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, VK_CONTROL, VK_LWIN, VK_MENU, VK_RWIN, VK_SHIFT,
    };
    let held = [VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN]
        .into_iter()
        .any(|vk| {
            // SAFETY: GetAsyncKeyState only reads the asynchronous key state
            // of one virtual key; no pointers are involved.
            let state = unsafe { GetAsyncKeyState(i32::from(vk)) };
            state < 0 // high bit: the key is down
        });
    Some(held)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn modifiers_held() -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn waits_until_the_modifiers_are_released() {
        let calls = Cell::new(0);
        let held = || {
            calls.set(calls.get() + 1);
            Some(calls.get() < 4)
        };
        assert!(wait_for_release(held, Duration::from_secs(2)));
        assert_eq!(calls.get(), 4);
    }

    #[test]
    fn gives_up_when_they_stay_down() {
        let started = Instant::now();
        assert!(!wait_for_release(|| Some(true), Duration::from_millis(60)));
        assert!(started.elapsed() >= Duration::from_millis(60));
        assert!(wait_for_release(|| None, Duration::ZERO));
    }

    #[test]
    fn modifier_query_does_not_crash() {
        let _ = modifiers_held();
    }
}
