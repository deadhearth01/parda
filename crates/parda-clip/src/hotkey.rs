//! The global paste-safe hotkey.
//!
//! Hotkey events need an event loop on the thread that registered them: a
//! CFRunLoop on macOS (main thread), a message pump on Windows; on X11 the
//! crate runs its own. Wayland has no global hotkeys: bind a desktop
//! shortcut to `parda paste-safe` instead.

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use global_hotkey::hotkey::{Code, HotKey, Modifiers};
use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState};

use crate::watcher::ClipHandle;

/// Parse `"cmd+alt+v"`, `"ctrl+shift+p"`, `"default"` (Cmd+Alt+V on macOS,
/// Ctrl+Alt+V elsewhere).
pub fn parse_hotkey(s: &str) -> anyhow::Result<HotKey> {
    let s = if s.trim().eq_ignore_ascii_case("default") {
        if cfg!(target_os = "macos") {
            "cmd+alt+v"
        } else {
            "ctrl+alt+v"
        }
    } else {
        s
    };
    let mut mods = Modifiers::empty();
    let mut code = None;
    for part in s.split('+').map(str::trim).filter(|p| !p.is_empty()) {
        match part.to_ascii_lowercase().as_str() {
            "cmd" | "command" | "super" | "meta" | "win" => mods |= Modifiers::SUPER,
            "ctrl" | "control" => mods |= Modifiers::CONTROL,
            "alt" | "option" | "opt" => mods |= Modifiers::ALT,
            "shift" => mods |= Modifiers::SHIFT,
            key => {
                if code.is_some() {
                    anyhow::bail!("hotkey `{s}` names more than one key");
                }
                code = Some(key_code(key)?);
            }
        }
    }
    let code = code.ok_or_else(|| anyhow::anyhow!("hotkey `{s}` has no key"))?;
    if mods.is_empty() {
        anyhow::bail!("hotkey `{s}` needs at least one modifier");
    }
    Ok(HotKey::new(Some(mods), code))
}

fn key_code(key: &str) -> anyhow::Result<Code> {
    let name = match key {
        k if k.len() == 1 && k.as_bytes()[0].is_ascii_alphabetic() => {
            format!("Key{}", k.to_ascii_uppercase())
        }
        k if k.len() == 1 && k.as_bytes()[0].is_ascii_digit() => format!("Digit{k}"),
        "space" => "Space".into(),
        k if k.starts_with('f') && k[1..].parse::<u8>().is_ok_and(|n| (1..=12).contains(&n)) => {
            k.to_ascii_uppercase()
        }
        other => anyhow::bail!("unknown hotkey key `{other}`"),
    };
    Code::from_str(&name).map_err(|_| anyhow::anyhow!("unknown hotkey key `{key}`"))
}

fn is_wayland() -> bool {
    cfg!(target_os = "linux")
        && std::env::var_os("WAYLAND_DISPLAY").is_some()
        && std::env::var_os("DISPLAY").is_none()
}

/// Register `hotkey` and run paste-safe on each press until `stop` is set.
/// Call from the main thread on macOS.
pub fn run_hotkey_loop(
    handle: ClipHandle,
    hotkey: &str,
    stop: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    if is_wayland() {
        tracing::warn!(
            "global hotkeys are not available on Wayland; bind a desktop shortcut to `parda paste-safe`"
        );
        while !stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(250));
        }
        return Ok(());
    }
    let hk = parse_hotkey(hotkey)?;
    let manager = GlobalHotKeyManager::new()
        .map_err(|e| anyhow::anyhow!("cannot set up global hotkeys: {e}"))?;
    manager
        .register(hk)
        .map_err(|e| anyhow::anyhow!("cannot register hotkey `{hotkey}`: {e}"))?;
    tracing::info!(hotkey, "paste-safe hotkey registered");
    let rx = GlobalHotKeyEvent::receiver();
    while !stop.load(Ordering::SeqCst) {
        pump_events(Duration::from_millis(200));
        while let Ok(ev) = rx.try_recv() {
            // Act on release so the user's modifiers are up before Cmd/Ctrl+V.
            if ev.id == hk.id() && ev.state == HotKeyState::Released {
                let h = handle.clone();
                std::thread::spawn(move || match h.paste_safe() {
                    Ok(outcome) => tracing::info!(?outcome, "paste-safe"),
                    Err(e) => tracing::warn!(error = %e, "paste-safe failed"),
                });
            }
        }
    }
    let _ = manager.unregister(hk);
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn pump_events(timeout: Duration) {
    use core_foundation::runloop::{CFRunLoop, kCFRunLoopDefaultMode};
    // SAFETY: reading an immutable CoreFoundation constant.
    let mode = unsafe { kCFRunLoopDefaultMode };
    CFRunLoop::run_in_mode(mode, timeout, false);
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn pump_events(timeout: Duration) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, TranslateMessage,
    };
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        // SAFETY: standard Win32 message pump on the registering thread; MSG
        // is plain data and only read after PeekMessageW fills it.
        unsafe {
            let mut msg: MSG = std::mem::zeroed();
            while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        std::thread::sleep(Duration::from_millis(15));
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn pump_events(timeout: Duration) {
    // X11: the hotkey crate runs its own event thread.
    std::thread::sleep(timeout);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hotkeys() {
        let hk = parse_hotkey("cmd+alt+v").unwrap();
        assert_eq!(
            hk,
            HotKey::new(Some(Modifiers::SUPER | Modifiers::ALT), Code::KeyV)
        );
        let hk = parse_hotkey("Ctrl + Shift + 7").unwrap();
        assert_eq!(
            hk,
            HotKey::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::Digit7)
        );
        assert!(parse_hotkey("default").is_ok());
        assert!(parse_hotkey("ctrl+f5").is_ok());
        assert!(parse_hotkey("v").is_err());
        assert!(parse_hotkey("ctrl+alt").is_err());
        assert!(parse_hotkey("ctrl+v+x").is_err());
        assert!(parse_hotkey("ctrl+enterr").is_err());
    }
}
