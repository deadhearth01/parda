//! The terminal dashboard (`parda`, `parda tui`): a ratatui app over the
//! daemon's IPC socket.
//!
//! Tabs: 1 Dashboard · 2 Live · 3 Inspector · 4 Rules · 5 Vault · 6 Settings,
//! plus a command palette (`:` / Ctrl-K), `/` filters, detail panes, inline
//! settings editing, toasts, and an offline screen that can start the daemon.
//!
//! Threads: the UI thread only draws and handles input. A worker
//! ([`worker`]) owns the IPC client(s) and the event subscription, an input
//! thread reads the terminal; both feed one channel the UI blocks on, so an
//! idle dashboard does not wake up, and it redraws only when something
//! changed ([`App::take_dirty`]). The [`App`] does no I/O, so it is tested
//! with a fake [`Backend`] and ratatui's `TestBackend`.

mod app;
mod palette;
pub mod settings;
mod tabs;
pub mod theme;
mod ui;
pub mod worker;

#[cfg(test)]
mod tests;

use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Instant;

use parda_ipc::{Client, Request};
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
};
use ratatui::crossterm::execute;
use serde_json::Value;

pub use app::{App, Conn, Hit, Level, MAX_EVENTS, Tab};
pub use theme::Theme;
pub use worker::{Cmd, Msg, Starter};

/// Where requests go (the daemon, or a fake in tests).
pub trait Backend {
    fn call(&mut self, req: Request) -> anyhow::Result<Value>;

    /// What [`Backend::start_daemon`] would do, for the offline screen.
    fn start_hint(&mut self) -> Option<String> {
        None
    }

    /// Start the daemon in the background (the offline screen's `s`).
    fn start_daemon(&mut self) -> anyhow::Result<String> {
        anyhow::bail!("start the daemon with `parda daemon` or `parda service install`")
    }
}

impl Backend for Client {
    fn call(&mut self, req: Request) -> anyhow::Result<Value> {
        Ok(Client::call(self, req)?)
    }
}

/// What wakes the UI thread.
pub enum UiEvent {
    Term(event::Event),
    Msg(Msg),
}

/// Render `app` into a `width`×`height` text screen (no terminal needed).
pub fn render_text(app: &App, width: u16, height: u16) -> String {
    let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height))
        .expect("test backend");
    let _ = t.draw(|f| app.draw(f));
    let buf = t.backend().buffer().clone();
    let mut s = String::with_capacity(usize::from(width + 1) * usize::from(height));
    for y in 0..buf.area.height {
        let line: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
        s.push_str(line.trim_end());
        s.push('\n');
    }
    s
}

/// Print every tab, as the live daemon would show it, as plain text
/// (`parda tui --dump`): for smoke tests, bug reports and docs.
pub fn dump(runtime_dir: &Path, width: u16, height: u16) -> anyhow::Result<String> {
    let mut client = Client::connect(runtime_dir)
        .map_err(|e| anyhow::anyhow!("cannot reach the daemon: {e}"))?;
    let mut app = App::new();
    let mut out = String::new();
    for tab in Tab::ALL {
        app.tab = tab;
        app.request_refresh();
        app.sync(&mut client);
        out.push_str(&format!("──── {} ────\n", tab.title()));
        out.push_str(&render_text(&app, width, height));
    }
    Ok(out)
}

/// Run the dashboard against the daemon in `runtime_dir`. When the daemon
/// is not running it shows the offline screen and keeps retrying; `starter`
/// (if any) is what its start key runs.
pub fn run(runtime_dir: &Path, starter: Option<Starter>) -> anyhow::Result<()> {
    // No terminal: an error, not a panic.
    let mut terminal =
        ratatui::try_init().map_err(|e| anyhow::anyhow!("the dashboard needs a terminal: {e}"))?;
    // ratatui's hook restores the screen; ours first switches off what we
    // switched on, so a panic never leaves mouse reporting or paste
    // brackets in the user's shell.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        release_terminal();
        previous(info);
    }));
    // Mouse: click tabs/rows/badge, wheel scrolls (text selection needs
    // Shift / Option while capture is on). Bracketed paste: pasted text
    // arrives as one event, so its newlines are never Enter.
    let _ = execute!(std::io::stdout(), EnableMouseCapture, EnableBracketedPaste);
    let result = run_loop(&mut terminal, runtime_dir, starter);
    release_terminal();
    ratatui::restore();
    result
}

fn release_terminal() {
    let _ = execute!(
        std::io::stdout(),
        DisableMouseCapture,
        DisableBracketedPaste
    );
}

fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    runtime_dir: &Path,
    starter: Option<Starter>,
) -> anyhow::Result<()> {
    let (tx, rx) = mpsc::channel::<UiEvent>();
    let mut app = App::new();
    app.theme = Theme::from_env();
    let cmds = worker::spawn(
        worker::Live::new(runtime_dir, tx.clone(), starter),
        tx.clone(),
    );
    let input_tx = tx;
    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            if input_tx.send(UiEvent::Term(ev)).is_err() {
                break;
            }
        }
    });
    loop {
        for c in app.take_cmds() {
            let _ = cmds.send(c);
        }
        if app.should_quit() {
            return Ok(());
        }
        if app.take_dirty() {
            terminal.draw(|f| app.draw(f))?;
        }
        let now = Instant::now();
        let first = match app.next_wakeup(now) {
            Some(at) => match rx.recv_timeout(at.saturating_duration_since(now)) {
                Ok(ev) => Some(ev),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            },
            None => match rx.recv() {
                Ok(ev) => Some(ev),
                Err(_) => return Ok(()),
            },
        };
        // Apply everything that is waiting before drawing once.
        for ev in first
            .into_iter()
            .chain(std::iter::from_fn(|| rx.try_recv().ok()))
            .take(1024)
        {
            match ev {
                UiEvent::Term(e) => app.on_term(e),
                UiEvent::Msg(m) => app.on_msg(m),
            }
        }
        app.tick(Instant::now());
    }
}
