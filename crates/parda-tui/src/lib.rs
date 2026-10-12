//! `parda tui`: a ratatui dashboard over the daemon's IPC socket.
//!
//! Tabs: 1 Dashboard · 2 Live · 3 Inspector · 4 Rules · 5 Vault · 6 Settings.
//! Keyboard and mouse: click tabs, rows and the protection switch; the wheel
//! scrolls lists.
//! The [`App`] is independent of the terminal and of the socket (see
//! [`Backend`]) so it can be tested with ratatui's `TestBackend`.

mod app;
pub mod settings;
mod tabs;

use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use parda_ipc::{Client, Event, Request};
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event as TermEvent, KeyEventKind,
};
use ratatui::crossterm::execute;
use serde_json::Value;

pub use app::{App, Hit, Tab};

/// Where the app sends requests (the daemon, or a fake in tests).
pub trait Backend {
    fn call(&mut self, req: Request) -> anyhow::Result<Value>;
}

impl Backend for Client {
    fn call(&mut self, req: Request) -> anyhow::Result<Value> {
        Ok(Client::call(self, req)?)
    }
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
        app.refresh(&mut client);
        out.push_str(&format!("──── {} ────\n", tab.title()));
        out.push_str(&render_text(&app, width, height));
    }
    Ok(out)
}

/// Run the dashboard against the daemon listening in `runtime_dir`.
pub fn run(runtime_dir: &Path) -> anyhow::Result<()> {
    let mut client = Client::connect(runtime_dir).map_err(|e| {
        if e.is_not_running() {
            anyhow::anyhow!(
                "the daemon is not running; start it with `parda daemon` or `parda service install`"
            )
        } else {
            anyhow::anyhow!(e)
        }
    })?;
    let (tx, rx) = mpsc::channel::<Event>();
    let dir = runtime_dir.to_path_buf();
    std::thread::spawn(move || {
        if let Ok(c) = Client::connect(&dir) {
            for ev in c.subscribe() {
                if tx.send(ev).is_err() {
                    break;
                }
            }
        }
    });

    let mut terminal = ratatui::init();
    // Mouse: click tabs/rows/switch, wheel scrolls. Text selection needs
    // Shift (Option on macOS) while capture is on.
    let _ = execute!(std::io::stdout(), EnableMouseCapture);
    let mut app = App::new();
    app.refresh(&mut client);
    let mut last_refresh = Instant::now();
    let result = (|| -> anyhow::Result<()> {
        while !app.should_quit() {
            terminal.draw(|f| app.draw(f))?;
            if event::poll(Duration::from_millis(250))? {
                match event::read()? {
                    TermEvent::Key(key) if key.kind == KeyEventKind::Press => {
                        app.on_key(key, &mut client)
                    }
                    TermEvent::Mouse(m) => app.on_mouse(m, &mut client),
                    _ => {}
                }
            }
            while let Ok(ev) = rx.try_recv() {
                app.on_event(ev);
            }
            if last_refresh.elapsed() >= Duration::from_secs(1) {
                app.refresh(&mut client);
                last_refresh = Instant::now();
            }
        }
        Ok(())
    })();
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    result
}
