//! Clipboard protection for chat apps parda cannot proxy.
//!
//! * **Paste-safe** (hotkey or `parda paste-safe`): the clipboard is swapped
//!   for its redacted version, a paste keystroke is synthesised, and the
//!   original comes back on the clipboard shortly after (unless the user
//!   copied something else meanwhile). A request that could not be pasted
//!   within [`PASTE_MAX_AGE`] is dropped rather than pasted into whatever
//!   window has the focus by then.
//! * **Restore-on-copy**: copying a model answer that contains surrogates
//!   puts the real values on the clipboard instead.
//! * **Scan-on-copy**: new clipboard text is scanned in the background so a
//!   later paste-safe is instant (the engine caches detections).

mod hotkey;
mod paste;
mod watcher;

pub use hotkey::{parse_hotkey, run_hotkey_loop};
pub use paste::{EnigoPaster, Paster};
pub use watcher::{
    ArboardBackend, ClipEvent, ClipHandle, ClipRead, ClipService, ClipboardBackend, PASTE_MAX_AGE,
    PasteOutcome, RESTORE_DELAY, spawn,
};
