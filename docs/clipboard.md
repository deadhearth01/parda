# Chat apps: paste-safe and restore-on-copy

Web and desktop chat apps (ChatGPT, Claude, Gemini, Copilot, WhatsApp …) talk to their servers directly, so parda protects them through the clipboard.

## Paste-safe

1. Copy your text as usual.
2. In the chat box, press **⌘⌥V** (macOS) or **Ctrl+Alt+V** (Windows, Linux X11) instead of paste.
3. parda puts a redacted version on the clipboard, presses paste for you, and ~0.4 s later puts your original back.

If there is nothing to redact, the original is pasted. If parda cannot send the keystroke, the redacted text stays on the clipboard and the TUI tells you to paste manually. `parda paste-safe` does the same from a shell or a desktop shortcut.

- **macOS:** allow parda under *System Settings → Privacy & Security → Accessibility* (needed to send ⌘V).
- **Wayland:** global hotkeys are not available; bind a desktop shortcut to `parda paste-safe`.
- Change the key with `clipboard.hotkey`, e.g. `"ctrl+shift+v"`.

## Restore-on-copy

When you copy an answer that contains stand-ins parda created, the clipboard is replaced with the real values — so copying "Dear Arjun Mehta, …" gives you "Dear Ravi Kumar, …". Turn off with `clipboard.restore_on_copy = false`.

## Scan-on-copy

New clipboard text is scanned in the background, so paste-safe is instant and the TUI's Live tab shows when you copied something sensitive. Only kinds and counts are recorded.
