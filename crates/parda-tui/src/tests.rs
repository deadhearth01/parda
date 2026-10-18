//! Key, mouse and rendering tests against a fake daemon.

use std::time::{Duration, Instant};

use parda_ipc::{Event, Request};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::style::Color;
use serde_json::{Value, json};

use crate::app::{App, Conn, Tab};
use crate::{Backend, render_text};

struct Fake {
    rules: String,
    config: String,
    calls: Vec<String>,
    online: bool,
    started: usize,
    hint_calls: usize,
    vault: Vec<Value>,
    fail_rules_set: bool,
}

impl Backend for Fake {
    fn call(&mut self, req: Request) -> anyhow::Result<Value> {
        self.calls.push(
            format!("{req:?}")
                .split([' ', '{'])
                .next()
                .unwrap_or("")
                .to_string(),
        );
        if !self.online {
            anyhow::bail!("the parda daemon is not running");
        }
        Ok(match req {
            Request::Status => json!({
                "pid": 42, "uptime_s": 7, "proxy": "127.0.0.1:8787", "clipboard": true,
                "intercept": {"enabled": true, "listening": "127.0.0.1:8788", "ca": true,
                              "error": null, "pac": "http://127.0.0.1:8788/parda.pac"},
                "hotkey": "default", "model": "gliner-pii-edge", "mode": "strict", "style": "surrogate",
                "stats": {"redactions": 3, "cache_hits": 1, "fragments": 4, "ml_calls": 2,
                          "ml_ms_total": 18, "ml_failures": 0,
                          "entities": {"Person": 2, "Email": 1},
                          "by_source": {"model": 2, "rules": 1}},
                "activity": {"surfaces": {"proxy": {"events": 2, "redacted": 3, "warnings": 0, "kinds": {}}},
                             "latency_ms": {"samples": 2, "p50": 4, "p95": 9, "max": 9}},
                "paths": {"config": "/x/config.toml"}
            }),
            Request::Redact { text, .. } => json!({
                "text": text.replace("Ravi Kumar", "Arjun Mehta"),
                "replaced": [{"kind": "Person", "surrogate": "Arjun Mehta", "source": "Dictionary"}]
            }),
            Request::Restore { text, .. } => {
                json!({"text": text.replace("Arjun Mehta", "Ravi Kumar")})
            }
            Request::RulesGet => json!({"toml": self.rules}),
            Request::RulesSet { .. } if self.fail_rules_set => {
                anyhow::bail!("rules: invalid rules.toml")
            }
            Request::RulesSet { rules_toml } => {
                self.rules = rules_toml;
                json!({})
            }
            Request::VaultStats => json!({"stats": self.vault}),
            Request::VaultWipe { scope } => {
                let before = self.vault.len();
                self.vault
                    .retain(|r| scope.as_deref().is_some_and(|s| r["scope"] != s));
                json!({"removed": before - self.vault.len()})
            }
            Request::ConfigGet => json!({"toml": self.config}),
            Request::ConfigSet { toml } => {
                let old = parda_core::Config::from_toml_str(&self.config).unwrap();
                let new = parda_core::Config::from_toml_str(&toml).unwrap();
                self.config = toml;
                // As a daemon without a CA answers.
                let intercept = new.intercept.enabled.then(|| {
                    json!({"listening": null, "pac": null,
                           "error": "intercept: no CA — run `parda ca create`"})
                });
                json!({
                    "restart_required": old.proxy.enabled != new.proxy.enabled
                        || old.proxy.listen != new.proxy.listen,
                    "intercept": intercept,
                })
            }
            _ => json!({}),
        })
    }

    fn start_hint(&mut self) -> Option<String> {
        self.hint_calls += 1;
        Some("runs `parda daemon` for PARDA_HOME /x/home".into())
    }

    fn start_daemon(&mut self) -> anyhow::Result<String> {
        self.started += 1;
        self.online = true;
        Ok("starting the daemon in the background".into())
    }
}

fn fake() -> Fake {
    Fake {
        rules: "[[person]]\nname = \"Ravi Kumar\"\n".into(),
        config: parda_core::Config::default().to_toml_string().unwrap(),
        calls: vec![],
        online: true,
        started: 0,
        hint_calls: 0,
        fail_rules_set: false,
        vault: vec![
            json!({"scope": "global", "kind": "Person", "count": 5}),
            json!({"scope": "global", "kind": "Email", "count": 2}),
            json!({"scope": "work", "kind": "Phone", "count": 1}),
        ],
    }
}

/// An app that has had its first refresh.
fn online(b: &mut Fake) -> App {
    let mut app = App::new();
    app.request_refresh();
    app.sync(b);
    app
}

fn key(c: KeyCode) -> KeyEvent {
    KeyEvent::new(c, KeyModifiers::NONE)
}

fn press(app: &mut App, b: &mut Fake, c: KeyCode) {
    app.on_key(key(c));
    app.sync(b);
}

fn ctrl(app: &mut App, b: &mut Fake, c: char) {
    app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL));
    app.sync(b);
}

fn typ(app: &mut App, b: &mut Fake, s: &str) {
    for c in s.chars() {
        press(app, b, KeyCode::Char(c));
    }
}

fn cfg(b: &Fake) -> parda_core::Config {
    parda_core::Config::from_toml_str(&b.config).unwrap()
}

fn click_at(app: &mut App, b: &mut Fake, x: u16, y: u16, button: MouseButton) {
    app.on_mouse(MouseEvent {
        kind: MouseEventKind::Down(button),
        column: x,
        row: y,
        modifiers: KeyModifiers::NONE,
    });
    app.sync(b);
}

fn wheel(app: &mut App, b: &mut Fake, down: bool) {
    app.on_mouse(MouseEvent {
        kind: if down {
            MouseEventKind::ScrollDown
        } else {
            MouseEventKind::ScrollUp
        },
        column: 10,
        row: 10,
        modifiers: KeyModifiers::NONE,
    });
    app.sync(b);
}

fn find_in(app: &App, needle: &str, w: u16, h: u16) -> (u16, u16) {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| app.draw(f)).unwrap();
    let buf = t.backend().buffer().clone();
    let want: Vec<String> = needle.chars().map(|c| c.to_string()).collect();
    for y in 0..buf.area.height {
        let row: Vec<String> = (0..buf.area.width)
            .map(|x| buf[(x, y)].symbol().to_string())
            .collect();
        if let Some(x) = row.windows(want.len()).position(|w| w == want.as_slice()) {
            return (x as u16, y);
        }
    }
    panic!("{needle:?} not on screen:\n{}", render_text(app, w, h));
}

/// Render at 100×30, then return the cell position of `needle`.
fn find(app: &App, needle: &str) -> (u16, u16) {
    find_in(app, needle, 100, 30)
}

fn render(app: &App) -> String {
    render_text(app, 100, 30)
}

fn event(surface: &str, summary: &str, counts: &[(&str, u32)], ms: Option<u64>) -> Event {
    let mut e = Event::now(surface, summary);
    for (k, n) in counts {
        e.counts.insert((*k).into(), *n);
    }
    e.latency_ms = ms;
    e
}

// ── carried over from v1 ────────────────────────────────────────────────

#[test]
fn every_tab_renders_and_number_keys_switch() {
    let mut b = fake();
    let mut app = online(&mut b);
    app.on_event(Event::now(
        "proxy",
        "anthropic /v1/messages → 200 · 2 redacted",
    ));
    let screen = render(&app);
    for t in Tab::ALL {
        assert!(
            screen.contains(t.title()),
            "missing tab title {}",
            t.title()
        );
    }
    assert!(screen.contains("pid 42") && screen.contains("gliner-pii-edge"));
    assert!(screen.contains("Person"));
    assert!(screen.contains("3 values"), "{screen}");
    assert!(screen.contains("p95 9 ms"));
    assert!(screen.contains("model") && screen.contains("proxy (2 events)"));
    assert!(screen.contains("9.0 ms avg") && screen.contains("25% hits"));
    for (k, want) in [
        ('2', "Live ("),
        ('3', "Input"),
        ('4', "Ravi Kumar"),
        ('5', "global"),
        ('6', "ANTHROPIC_BASE_URL"),
    ] {
        press(&mut app, &mut b, KeyCode::Char(k));
        let screen = render(&app);
        assert!(screen.contains(want), "tab {k} lacks {want:?}:\n{screen}");
    }
    press(&mut app, &mut b, KeyCode::Char('1'));
    assert_eq!(app.tab, Tab::Dashboard);
}

#[test]
fn inspector_shows_redacted_output_and_restore_preview() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('3'));
    press(&mut app, &mut b, KeyCode::Char('i'));
    // While editing, digits, q and : are text, not commands.
    typ(&mut app, &mut b, "hi Ravi Kumar q1:");
    assert_eq!(app.tab, Tab::Inspector);
    assert!(!app.should_quit() && app.palette.is_none());
    // Enter queues the redaction for the worker and shows a spinner.
    app.on_key(key(KeyCode::Enter));
    assert!(app.inspector.busy);
    assert!(render(&app).contains("redacting"), "{}", render(&app));
    app.sync(&mut b);
    assert!(!app.inspector.busy);
    let screen = render(&app);
    assert!(screen.contains("hi Arjun Mehta"), "{screen}");
    assert!(screen.contains("Person"));
    press(&mut app, &mut b, KeyCode::Char('r'));
    assert!(render(&app).contains("Restored"));
}

#[test]
fn rules_add_person_saves_through_backend() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('4'));
    press(&mut app, &mut b, KeyCode::Char('a'));
    typ(&mut app, &mut b, "Zubin Wadia");
    press(&mut app, &mut b, KeyCode::Enter);
    assert!(b.rules.contains("Zubin Wadia") && b.rules.contains("Ravi Kumar"));
    assert!(render(&app).contains("Zubin Wadia"));
    assert_eq!(app.message(), Some("rules saved"));
}

#[test]
fn q_quits_and_live_feed_shows_events() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('2'));
    app.on_event(event(
        "clipboard",
        "pasted with 1 value(s) redacted",
        &[("Person", 1)],
        None,
    ));
    let screen = render(&app);
    assert!(screen.contains("pasted with 1 value(s) redacted") && screen.contains("Person×1"));
    assert!(!app.should_quit());
    press(&mut app, &mut b, KeyCode::Char('q'));
    assert!(app.should_quit());
}

#[test]
fn ctrl_c_quits_from_anywhere() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char(':'));
    assert!(app.palette.is_some());
    ctrl(&mut app, &mut b, 'c');
    assert!(app.should_quit());
}

#[test]
fn p_toggles_protection_and_header_shows_it() {
    let mut b = fake();
    let mut app = online(&mut b);
    assert!(render(&app).contains("PROTECTION ON"));
    press(&mut app, &mut b, KeyCode::Char('p'));
    assert!(!cfg(&b).protection.enabled);
    let screen = render(&app);
    assert!(screen.contains("PROTECTION OFF"), "{screen}");
    assert!(screen.contains("text is sent unfiltered"), "{screen}");
    assert!(app.message().unwrap().contains("protection OFF"));
    press(&mut app, &mut b, KeyCode::Char('p'));
    assert!(cfg(&b).protection.enabled);
    assert!(app.message().unwrap().contains("protection ON"));
}

#[test]
fn clicking_tabs_and_the_switch() {
    let mut b = fake();
    let mut app = online(&mut b);
    let (x, y) = find(&app, "3 Inspector");
    click_at(&mut app, &mut b, x + 2, y, MouseButton::Left);
    assert_eq!(app.tab, Tab::Inspector);
    let (x, y) = find(&app, "6 Settings");
    click_at(&mut app, &mut b, x, y, MouseButton::Left);
    assert_eq!(app.tab, Tab::Settings);
    let (x, y) = find(&app, "PROTECTION ON");
    click_at(&mut app, &mut b, x + 3, y, MouseButton::Left);
    assert!(!cfg(&b).protection.enabled);
    // Clicking the inspector's input box starts editing.
    press(&mut app, &mut b, KeyCode::Char('3'));
    let (x, y) = find(&app, "Input (press i to type)");
    click_at(&mut app, &mut b, x, y + 1, MouseButton::Left);
    assert!(app.inspector.editing);
}

#[test]
fn settings_tab_lists_options_and_changes_them() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('6'));
    let screen = render_text(&app, 160, 48);
    for want in [
        "protection",
        "when the model fails",
        "agent proxy",
        "india (Aadhaar",
        "ANTHROPIC_BASE_URL",
    ] {
        assert!(screen.contains(want), "missing {want:?}:\n{screen}");
    }
    // Down to "when the model fails", Enter switches strict → fast.
    press(&mut app, &mut b, KeyCode::Down);
    press(&mut app, &mut b, KeyCode::Enter);
    assert_eq!(cfg(&b).detect.mode, parda_core::Mode::Fast);
    // Tags are the default; clicking the style row changes it, right-click changes it back.
    assert_eq!(cfg(&b).replace.style, parda_core::Style::Token);
    let (x, y) = find(&app, "replacement style");
    click_at(&mut app, &mut b, x, y, MouseButton::Left);
    assert_eq!(cfg(&b).replace.style, parda_core::Style::Surrogate);
    click_at(&mut app, &mut b, x, y, MouseButton::Right);
    assert_eq!(cfg(&b).replace.style, parda_core::Style::Token);
    // Restart-required settings say so.
    let (x, y) = find(&app, "agent proxy (");
    click_at(&mut app, &mut b, x, y, MouseButton::Left);
    assert!(!cfg(&b).proxy.enabled);
    assert!(
        app.message().unwrap_or("").contains("restart"),
        "{:?}",
        app.message()
    );
}

#[test]
fn risky_setting_asks_first_and_wheel_moves_selection() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('6'));
    let i = crate::settings::all()
        .iter()
        .position(|s| *s == crate::settings::Setting::LogValues)
        .unwrap();
    for _ in 0..i {
        wheel(&mut app, &mut b, true);
    }
    assert_eq!(app.settings_sel, i);
    press(&mut app, &mut b, KeyCode::Enter);
    assert!(!cfg(&b).privacy.log_values, "must not change before y");
    assert!(render(&app).contains("personal data"), "{}", render(&app));
    press(&mut app, &mut b, KeyCode::Char('n'));
    assert!(!cfg(&b).privacy.log_values);
    press(&mut app, &mut b, KeyCode::Enter);
    press(&mut app, &mut b, KeyCode::Char('y'));
    assert!(cfg(&b).privacy.log_values);
    // The selected row stays visible after scrolling far down.
    let last = crate::settings::all().len() - 1;
    for _ in 0..last + 5 {
        wheel(&mut app, &mut b, true);
    }
    assert_eq!(app.settings_sel, last);
    assert!(render(&app).contains("Organization"));
}

#[test]
fn dashboard_says_whether_ai_sites_are_intercepted() {
    let mut b = fake();
    let mut app = online(&mut b);
    let screen = render(&app);
    assert!(
        screen.contains("intercept  on · 127.0.0.1:8788 · system proxy set"),
        "{screen}"
    );
    let mut st = app.status.clone().unwrap();
    for (intercept, want) in [
        (
            json!({"enabled": true, "listening": "127.0.0.1:8788", "ca": true, "error": null, "pac": null}),
            "on · 127.0.0.1:8788 · NO system proxy",
        ),
        (
            json!({"enabled": true, "listening": null, "ca": false,
                   "error": "intercept: no CA — run `parda ca create`", "pac": null}),
            "NOT LISTENING — intercept: no",
        ),
        (
            json!({"enabled": false, "listening": null, "ca": true, "error": null, "pac": null}),
            "intercept  off",
        ),
        (
            // Enabled, but the daemon runs with --no-proxy.
            json!({"enabled": true, "listening": null, "ca": true, "error": null, "pac": null}),
            "NOT LISTENING — the daemon runs without",
        ),
        (
            json!({"enabled": false, "listening": null, "ca": true, "error": null,
                   "pac": "http://127.0.0.1:8788/parda.pac"}),
            "OFF but the system proxy",
        ),
        (
            json!({"enabled": true, "listening": "127.0.0.1:9999", "ca": true, "error": null,
                   "pac": "http://127.0.0.1:8788/parda.pac", "pac_matches": false}),
            "sites fail to load; run parda intercept on",
        ),
    ] {
        st["intercept"] = intercept;
        app.status = Some(st.clone());
        let screen = render_text(&app, 160, 48);
        assert!(screen.contains(want), "{want:?}:\n{screen}");
    }
    // An older daemon without the field: no intercept line.
    st.as_object_mut().unwrap().remove("intercept");
    app.status = Some(st);
    assert!(!render(&app).contains("intercept  "));
}

#[test]
fn live_feed_tags_intercept_events() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('2'));
    app.on_event(event(
        "intercept",
        "chatgpt.com → 200 · 2 redacted",
        &[("Person", 2)],
        None,
    ));
    let mut t = Terminal::new(TestBackend::new(100, 30)).unwrap();
    t.draw(|f| app.draw(f)).unwrap();
    let buf = t.backend().buffer().clone();
    let (x, y) = find(&app, "intercept chatgpt.com");
    assert_eq!(buf[(x, y)].fg, Color::Magenta);
    let screen = render(&app);
    assert!(screen.contains("chatgpt.com → 200 · 2 redacted") && screen.contains("Person×2"));
}

#[test]
fn settings_switch_intercept_and_its_unscanned_rule_live() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('6'));
    let screen = render(&app);
    assert!(screen.contains("parda intercept on"), "{screen}");
    let (x, y) = find(&app, "filter AI sites in browsers");
    click_at(&mut app, &mut b, x, y, MouseButton::Left);
    assert!(cfg(&b).intercept.enabled);
    let msg = app.message().unwrap_or_default().to_string();
    assert!(
        msg.contains("not listening — intercept: no CA — run `parda ca create`"),
        "{msg}"
    );
    let (x, y) = find(&app, "files & images sent to AI sites");
    click_at(&mut app, &mut b, x, y, MouseButton::Left);
    assert_eq!(
        cfg(&b).intercept.unscanned,
        parda_core::UnscannedMedia::Block
    );
}

#[test]
fn live_feed_scrolls_with_wheel() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('2'));
    for i in 0..60 {
        app.on_event(Event::now("proxy", format!("request number {i:02}")));
    }
    assert!(render(&app).contains("request number 59"));
    for _ in 0..40 {
        wheel(&mut app, &mut b, false);
    }
    let screen = render(&app);
    assert!(
        !screen.contains("request number 59") && screen.contains("newer hidden"),
        "{screen}"
    );
    press(&mut app, &mut b, KeyCode::End);
    assert!(render(&app).contains("request number 59"));
}

// ── v2: offline screen and starting the daemon ──────────────────────────

#[test]
fn offline_screen_starts_the_daemon_only_on_the_key() {
    let mut b = fake();
    b.online = false;
    let mut app = online(&mut b);
    assert!(app.offline());
    let screen = render_text(&app, 80, 24);
    assert!(
        screen.contains("daemon offline") && screen.contains("start it in the background"),
        "{screen}"
    );
    assert!(screen.contains("s start the daemon"), "footer:\n{screen}");
    // Refreshes (the worker retries every second) never start anything.
    for _ in 0..5 {
        app.request_refresh();
        app.sync(&mut b);
    }
    // Neither do keys that mean something else on other screens.
    for c in ['1', 'p', 'j', 'x'] {
        press(&mut app, &mut b, KeyCode::Char(c));
    }
    assert_eq!(b.started, 0);
    assert!(cfg(&b).protection.enabled, "p does nothing while offline");
    press(&mut app, &mut b, KeyCode::Char('s'));
    assert_eq!(b.started, 1);
    assert!(app.starting.is_some());
    assert!(render_text(&app, 80, 24).contains("starting"));
    // A second press while waiting does not start a second daemon.
    press(&mut app, &mut b, KeyCode::Char('s'));
    assert_eq!(b.started, 1);
    // The next retry connects: the dashboard opens by itself.
    app.request_refresh();
    app.sync(&mut b);
    assert_eq!(app.conn, Conn::Online);
    assert!(app.starting.is_none());
    let screen = render_text(&app, 80, 24);
    assert!(
        screen.contains("pid 42") && !screen.contains("daemon offline"),
        "{screen}"
    );
}

#[test]
fn clicking_the_start_button_starts_the_daemon() {
    let mut b = fake();
    b.online = false;
    let mut app = online(&mut b);
    let (x, y) = find_in(&app, "start it in the background", 80, 24);
    click_at(&mut app, &mut b, x, y, MouseButton::Left);
    assert_eq!(b.started, 1);
}

#[test]
fn losing_the_daemon_shows_the_offline_screen_and_gives_up_waiting() {
    let mut b = fake();
    let mut app = online(&mut b);
    b.online = false;
    app.request_refresh();
    app.sync(&mut b);
    assert!(app.offline());
    let mut b2 = fake();
    b2.online = false;
    // A start that never connects ends with an error toast after a while.
    struct Never;
    impl Backend for Never {
        fn call(&mut self, _: Request) -> anyhow::Result<Value> {
            anyhow::bail!("the parda daemon is not running")
        }
        fn start_daemon(&mut self) -> anyhow::Result<String> {
            Ok("started".into())
        }
    }
    app.on_key(key(KeyCode::Char('s')));
    app.sync(&mut Never);
    assert!(app.starting.is_some());
    app.tick(Instant::now() + Duration::from_secs(20));
    assert!(app.starting.is_none());
    assert!(app.message().unwrap().contains("did not come up"));
    drop(b2);
}

// ── v2: palette ─────────────────────────────────────────────────────────

#[test]
fn palette_filters_and_runs_actions() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char(':'));
    let screen = render_text(&app, 80, 24);
    assert!(
        screen.contains("commands") && screen.contains("Go to Settings"),
        "{screen}"
    );
    typ(&mut app, &mut b, "go to vault");
    let screen = render_text(&app, 80, 24);
    assert!(
        screen.contains("Go to Vault") && !screen.contains("Go to Settings"),
        "{screen}"
    );
    press(&mut app, &mut b, KeyCode::Enter);
    assert!(app.palette.is_none() && app.confirm.is_none());
    assert_eq!(app.tab, Tab::Vault);
    // Ctrl-K opens it too; intercept is toggled through ConfigSet.
    ctrl(&mut app, &mut b, 'k');
    assert!(app.palette.is_some());
    typ(&mut app, &mut b, "intercept");
    press(&mut app, &mut b, KeyCode::Enter);
    assert!(cfg(&b).intercept.enabled);
    // Esc closes without running anything.
    press(&mut app, &mut b, KeyCode::Char(':'));
    typ(&mut app, &mut b, "quit");
    press(&mut app, &mut b, KeyCode::Esc);
    assert!(app.palette.is_none() && !app.should_quit());
}

#[test]
fn palette_destructive_actions_still_confirm() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char(':'));
    typ(&mut app, &mut b, "wipe");
    press(&mut app, &mut b, KeyCode::Enter);
    assert_eq!(app.tab, Tab::Vault);
    assert!(app.confirm.is_some());
    assert!(!b.calls.iter().any(|c| c == "VaultWipe"));
    assert!(render_text(&app, 80, 24).contains("Wipe ALL 8 mapping(s)?"));
    press(&mut app, &mut b, KeyCode::Char('y'));
    assert!(b.calls.iter().any(|c| c == "VaultWipe"));
    assert!(b.vault.is_empty());
    assert!(app.message().unwrap().contains("removed 3 mapping(s)"));
}

#[test]
fn palette_click_and_arrows() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char(':'));
    press(&mut app, &mut b, KeyCode::Down);
    press(&mut app, &mut b, KeyCode::Enter);
    assert_eq!(app.tab, Tab::Live, "second entry is Go to Live");
    press(&mut app, &mut b, KeyCode::Char(':'));
    let (x, y) = find_in(&app, "Go to Rules", 80, 24);
    click_at(&mut app, &mut b, x, y, MouseButton::Left);
    assert_eq!(app.tab, Tab::Rules);
    assert!(app.palette.is_none());
}

// ── v2: filters, pause, detail ──────────────────────────────────────────

fn live_app(b: &mut Fake) -> App {
    let mut app = online(b);
    press(&mut app, b, KeyCode::Char('2'));
    app.on_event(event(
        "proxy",
        "anthropic /v1/messages → 200 · 2 redacted",
        &[("Person", 2)],
        Some(4),
    ));
    app.on_event(event(
        "intercept",
        "chatgpt.com → 200 · 1 redacted",
        &[("Email", 1)],
        Some(7),
    ));
    app.on_event(event(
        "clipboard",
        "pasted with 1 value(s) redacted",
        &[("Phone", 1)],
        None,
    ));
    app.on_event(event(
        "intercept",
        "claude.ai → 400 · refused, not sent (body is not valid JSON)",
        &[],
        Some(2),
    ));
    app
}

#[test]
fn live_filter_narrows_rows_and_esc_clears() {
    let mut b = fake();
    let mut app = live_app(&mut b);
    press(&mut app, &mut b, KeyCode::Char('/'));
    typ(&mut app, &mut b, "chat");
    let screen = render_text(&app, 80, 24);
    assert!(
        screen.contains("chatgpt.com") && !screen.contains("claude.ai"),
        "{screen}"
    );
    assert!(screen.contains("/ filter events: chat"), "{screen}");
    // Backspace widens it again (full rescan).
    for _ in 0..4 {
        press(&mut app, &mut b, KeyCode::Backspace);
    }
    assert_eq!(app.live_len(), 4);
    typ(&mut app, &mut b, "email");
    assert_eq!(app.live_len(), 1, "matches kinds too");
    // Enter keeps the filter and gives the keys back to the list.
    press(&mut app, &mut b, KeyCode::Enter);
    assert!(!app.live.filter.editing && app.live.filter.active());
    press(&mut app, &mut b, KeyCode::Esc);
    assert!(!app.live.filter.active());
    assert_eq!(app.live_len(), 4);
}

#[test]
fn live_surface_and_kind_filters_cycle() {
    let mut b = fake();
    let mut app = live_app(&mut b);
    press(&mut app, &mut b, KeyCode::Char('f'));
    assert_eq!(app.live_len(), 1, "proxy only");
    press(&mut app, &mut b, KeyCode::Char('f'));
    assert_eq!(app.live_len(), 2, "intercept only");
    assert!(render_text(&app, 80, 24).contains("surface intercept"));
    press(&mut app, &mut b, KeyCode::Char('f'));
    press(&mut app, &mut b, KeyCode::Char('f'));
    assert_eq!(app.live_len(), 4, "back to all");
    press(&mut app, &mut b, KeyCode::Char('t'));
    assert_eq!(app.live.kind.as_deref(), Some("Email"));
    assert_eq!(app.live_len(), 1);
    // A new matching event joins the filtered view incrementally.
    app.on_event(event(
        "proxy",
        "openai → 200 · 1 redacted",
        &[("Email", 1)],
        Some(3),
    ));
    assert_eq!(app.live_len(), 2);
    press(&mut app, &mut b, KeyCode::Char('c'));
    assert_eq!(app.live_len(), 5);
}

#[test]
fn space_pauses_the_live_feed() {
    let mut b = fake();
    let mut app = live_app(&mut b);
    press(&mut app, &mut b, KeyCode::Char(' '));
    assert!(app.live.paused.is_some());
    app.on_event(Event::now("proxy", "arrived while paused"));
    let screen = render_text(&app, 80, 24);
    assert!(!screen.contains("arrived while paused"), "{screen}");
    assert!(screen.contains("PAUSED, 1 new"), "{screen}");
    assert!(screen.contains("space resume"), "footer:\n{screen}");
    press(&mut app, &mut b, KeyCode::Char(' '));
    assert!(render_text(&app, 80, 24).contains("arrived while paused"));
}

#[test]
fn enter_opens_event_detail_without_values() {
    let mut b = fake();
    let mut app = live_app(&mut b);
    press(&mut app, &mut b, KeyCode::Enter);
    assert!(app.live.detail);
    let screen = render_text(&app, 80, 24);
    for want in [
        "surface",
        "claude.ai",
        "400",
        "body is not valid JSON",
        "2 ms added",
    ] {
        assert!(screen.contains(want), "missing {want:?}:\n{screen}");
    }
    // Up selects the clipboard event; its kinds and counts show.
    press(&mut app, &mut b, KeyCode::Up);
    let screen = render_text(&app, 80, 24);
    assert!(screen.contains("Phone 1"), "{screen}");
    // Wide terminals put the detail next to the list.
    let wide = render_text(&app, 160, 48);
    assert!(wide.contains("Event (kinds and counts only)"));
    press(&mut app, &mut b, KeyCode::Esc);
    assert!(!app.live.detail);
    // g / G jump to the oldest / newest.
    press(&mut app, &mut b, KeyCode::Char('g'));
    assert_eq!(app.live.cursor, app.live_len() - 1);
    press(&mut app, &mut b, KeyCode::Char('G'));
    assert_eq!(app.live.cursor, 0);
}

#[test]
fn selection_stays_on_its_event_as_new_ones_arrive() {
    let mut b = fake();
    let mut app = live_app(&mut b);
    press(&mut app, &mut b, KeyCode::Up);
    let before = app.live_selected().unwrap().summary.clone();
    app.on_event(Event::now("proxy", "newer"));
    assert_eq!(app.live_selected().unwrap().summary, before);
}

#[test]
fn event_buffer_is_bounded() {
    let mut app = App::new();
    for i in 0..(crate::MAX_EVENTS + 50) {
        app.on_event(Event::now("proxy", format!("e{i}")));
    }
    assert_eq!(app.events.len(), crate::MAX_EVENTS);
    assert_eq!(app.live_len(), crate::MAX_EVENTS);
    assert_eq!(app.live_rows().next().unwrap().1.summary, "e50");
}

#[test]
fn rules_and_vault_filter_and_detail() {
    let mut b = fake();
    b.rules = "allow = [\"Acme\"]\n[[person]]\nname = \"Ravi Kumar\"\nemails = [\"r@x.in\"]\n\
               [[person]]\nname = \"Zubin Wadia\"\n"
        .into();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('4'));
    press(&mut app, &mut b, KeyCode::Char('/'));
    typ(&mut app, &mut b, "zub");
    let screen = render_text(&app, 80, 24);
    assert!(
        screen.contains("Zubin Wadia") && !screen.contains("Ravi Kumar"),
        "{screen}"
    );
    press(&mut app, &mut b, KeyCode::Enter);
    // d deletes the selected row of the filtered view, not row 0.
    press(&mut app, &mut b, KeyCode::Char('d'));
    assert!(
        !b.rules.contains("Zubin") && b.rules.contains("Ravi Kumar"),
        "{}",
        b.rules
    );
    press(&mut app, &mut b, KeyCode::Esc);
    press(&mut app, &mut b, KeyCode::Enter);
    let screen = render_text(&app, 80, 24);
    assert!(
        screen.contains("1 email(s)") && !screen.contains("r@x.in"),
        "{screen}"
    );

    press(&mut app, &mut b, KeyCode::Char('5'));
    press(&mut app, &mut b, KeyCode::Char('/'));
    typ(&mut app, &mut b, "work");
    assert_eq!(app.vault_view().len(), 1);
    press(&mut app, &mut b, KeyCode::Enter);
    press(&mut app, &mut b, KeyCode::Enter);
    let screen = render_text(&app, 80, 24);
    assert!(screen.contains("in scope 1 mapping(s)"), "{screen}");
    press(&mut app, &mut b, KeyCode::Char('x'));
    assert!(render_text(&app, 80, 24).contains("Forget every mapping in scope 'work'"));
    press(&mut app, &mut b, KeyCode::Char('y'));
    assert_eq!(b.vault.len(), 2);
    assert!(app.message().unwrap().contains("forgot scope 'work'"));
}

// ── v2: settings editing ────────────────────────────────────────────────

fn select_setting(app: &mut App, b: &mut Fake, s: crate::settings::Setting) {
    press(app, b, KeyCode::Char('6'));
    press(app, b, KeyCode::Char('g'));
    let i = crate::settings::all().iter().position(|x| *x == s).unwrap();
    for _ in 0..i {
        press(app, b, KeyCode::Char('j'));
    }
    assert_eq!(app.settings_sel, i);
}

#[test]
fn settings_numbers_edit_inline_with_validation() {
    use crate::settings::Setting;
    let mut b = fake();
    let mut app = online(&mut b);
    select_setting(&mut app, &mut b, Setting::Threshold);
    press(&mut app, &mut b, KeyCode::Enter);
    assert!(app.editor.is_some());
    ctrl(&mut app, &mut b, 'u');
    typ(&mut app, &mut b, "2");
    press(&mut app, &mut b, KeyCode::Enter);
    // Rejected: the editor stays open and says why; nothing was sent.
    assert!(app.editor.as_ref().unwrap().error.is_some());
    assert!(render_text(&app, 80, 24).contains("0.30 to 0.95"));
    assert!(!b.calls.iter().any(|c| c == "ConfigSet"));
    ctrl(&mut app, &mut b, 'u');
    typ(&mut app, &mut b, "0.42");
    press(&mut app, &mut b, KeyCode::Enter);
    assert!(app.editor.is_none());
    assert!((cfg(&b).detect.ml_threshold - 0.42).abs() < 1e-6);
    assert_eq!(app.message(), Some("saved and applied"));
    // ←/→ still step through presets, from the typed value to the next
    // larger one; Esc cancels an edit.
    press(&mut app, &mut b, KeyCode::Right);
    assert!((cfg(&b).detect.ml_threshold - 0.45).abs() < 1e-6);
    press(&mut app, &mut b, KeyCode::Enter);
    typ(&mut app, &mut b, "9");
    press(&mut app, &mut b, KeyCode::Esc);
    assert!(app.editor.is_none());
    assert!((cfg(&b).detect.ml_threshold - 0.45).abs() < 1e-6);
}

#[test]
fn settings_text_edit_shows_the_daemons_answer() {
    use crate::settings::Setting;
    let mut b = fake();
    let mut app = online(&mut b);
    select_setting(&mut app, &mut b, Setting::ProxyListen);
    press(&mut app, &mut b, KeyCode::Enter);
    let screen = render_text(&app, 80, 24);
    assert!(screen.contains("[127.0.0.1:8787"), "{screen}");
    ctrl(&mut app, &mut b, 'u');
    typ(&mut app, &mut b, "127.0.0.1:9000");
    press(&mut app, &mut b, KeyCode::Enter);
    assert_eq!(cfg(&b).proxy.listen, "127.0.0.1:9000");
    assert!(app.message().unwrap().contains("restart the daemon"));
    // Space on a text-only row opens the editor rather than doing nothing.
    press(&mut app, &mut b, KeyCode::Char(' '));
    assert!(app.editor.is_some());
}

// ── v2: chrome ──────────────────────────────────────────────────────────

#[test]
fn footer_shows_the_keys_for_the_current_state() {
    let mut b = fake();
    let mut app = online(&mut b);
    let keys = |app: &App| -> Vec<&'static str> {
        crate::ui::footer_keys(app)
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    };
    assert!(keys(&app).contains(&"p"));
    press(&mut app, &mut b, KeyCode::Char('2'));
    assert!(keys(&app).contains(&"space") && keys(&app).contains(&"/"));
    press(&mut app, &mut b, KeyCode::Char('/'));
    assert_eq!(keys(&app), ["type", "Enter", "Esc"]);
    press(&mut app, &mut b, KeyCode::Esc);
    press(&mut app, &mut b, KeyCode::Char('5'));
    assert!(keys(&app).contains(&"x"));
    press(&mut app, &mut b, KeyCode::Char('6'));
    assert!(
        crate::ui::footer_keys(&app)
            .iter()
            .any(|(_, w)| w == "toggle")
    );
    press(&mut app, &mut b, KeyCode::Char(':'));
    assert!(keys(&app).contains(&"Enter"));
    // The footer is one line and fits 80 columns.
    let screen = render_text(&app, 80, 24);
    assert!(screen.lines().nth(23).unwrap().chars().count() <= 80);
}

#[test]
fn toasts_expire() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('p'));
    assert!(app.message().is_some());
    assert!(render_text(&app, 80, 24).contains("protection OFF"));
    let at = app
        .next_wakeup(Instant::now())
        .expect("a toast is waiting to expire");
    app.tick(at + Duration::from_millis(1));
    assert!(app.message().is_none());
    assert!(app.next_wakeup(Instant::now()).is_none());
}

#[test]
fn status_bar_shows_daemon_protection_intercept_proxy_model_mode() {
    let mut b = fake();
    let app = online(&mut b);
    let top = render_text(&app, 160, 48)
        .lines()
        .next()
        .unwrap()
        .to_string();
    for want in [
        "parda",
        "online",
        "PROTECTION ON",
        "intercept 127.0.0.1:8788",
        "proxy 127.0.0.1:8787",
        "model gliner-pii-edge",
        "strict",
    ] {
        assert!(top.contains(want), "{want:?} not in {top:?}");
    }
    // At 80 columns the low-priority parts drop off, the badge stays.
    let top = render_text(&app, 80, 24)
        .lines()
        .next()
        .unwrap()
        .to_string();
    assert!(
        top.contains("PROTECTION ON") && top.chars().count() <= 80,
        "{top}"
    );
}

#[test]
fn dashboard_warns_and_draws_sparklines() {
    let mut b = fake();
    let mut app = online(&mut b);
    for i in 0..5 {
        let mut e = event(
            "proxy",
            "x → 200 · 2 redacted",
            &[("Person", 2)],
            Some(5 + i),
        );
        e.ts_ms -= 60_000 * i;
        app.on_event(e);
    }
    let screen = render_text(&app, 80, 24);
    assert!(
        screen.contains("values/min") && screen.contains("latency p95"),
        "{screen}"
    );
    assert!(screen.contains("2 this minute"), "{screen}");
    let mut st = app.status.clone().unwrap();
    st["intercept"] = json!({"enabled": true, "listening": null, "ca": false,
                             "error": null, "pac": "http://127.0.0.1:8788/parda.pac"});
    st["model"] = Value::Null;
    st["model_error"] = json!("model file missing");
    app.status = Some(st);
    let screen = render_text(&app, 80, 24);
    assert!(screen.contains("Warnings"), "{screen}");
    let wide = render_text(&app, 160, 48);
    for want in ["nothing listens", "no CA", "name model unavailable"] {
        assert!(wide.contains(want), "missing {want:?}:\n{wide}");
    }
}

#[test]
fn no_color_and_ascii_modes() {
    let mut b = fake();
    let mut app = online(&mut b);
    app.theme = crate::Theme::from_vars(Some("1".into()), Some("1".into()));
    let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
    t.draw(|f| app.draw(f)).unwrap();
    let buf = t.backend().buffer().clone();
    assert!(
        buf.content
            .iter()
            .all(|c| c.fg == Color::Reset && c.bg == Color::Reset)
    );
    let screen = render_text(&app, 80, 24);
    assert!(screen.is_ascii() || !screen.contains('│'), "{screen}");
    assert!(
        screen.contains("PROTECTION ON") && screen.contains("+-"),
        "{screen}"
    );
}

#[test]
fn help_overlay_fits_80x24() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('?'));
    let screen = render_text(&app, 80, 24);
    assert!(
        screen.contains("command palette") && screen.contains("Ctrl-C"),
        "{screen}"
    );
    press(&mut app, &mut b, KeyCode::Esc);
    assert!(!app.help);
}

#[test]
fn hjkl_and_tab_keys_navigate() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('l'));
    assert_eq!(app.tab, Tab::Live);
    press(&mut app, &mut b, KeyCode::Char('h'));
    assert_eq!(app.tab, Tab::Dashboard);
    press(&mut app, &mut b, KeyCode::BackTab);
    assert_eq!(app.tab, Tab::Settings);
    press(&mut app, &mut b, KeyCode::Tab);
    assert_eq!(app.tab, Tab::Dashboard);
    press(&mut app, &mut b, KeyCode::Char('4'));
    press(&mut app, &mut b, KeyCode::PageDown);
    press(&mut app, &mut b, KeyCode::PageUp);
    assert_eq!(app.rules_sel, 0);
}

// ── v2: performance ─────────────────────────────────────────────────────

#[test]
fn nothing_changed_means_no_redraw() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('2'));
    assert!(app.take_dirty());
    // The same status and config again (the worker's 1 s refresh): no redraw.
    app.request_refresh();
    app.sync(&mut b);
    assert!(!app.take_dirty(), "an unchanged refresh must not redraw");
    // Idle: no timers pending, so the loop blocks until input or data.
    assert!(app.next_wakeup(Instant::now()).is_none());
    app.tick(Instant::now());
    assert!(!app.take_dirty());
    // New data does redraw.
    app.on_event(Event::now("proxy", "new"));
    assert!(app.take_dirty());
}

#[test]
fn only_the_visible_tab_loads_its_data() {
    let mut b = fake();
    let mut app = online(&mut b);
    assert!(!b.calls.iter().any(|c| c == "RulesGet" || c == "VaultStats"));
    b.calls.clear();
    press(&mut app, &mut b, KeyCode::Char('5'));
    assert!(b.calls.iter().any(|c| c == "VaultStats"));
    assert!(!b.calls.iter().any(|c| c == "RulesGet"));
}

fn big_app() -> App {
    let mut b = fake();
    b.vault = (0..10_000)
        .map(|i| json!({"scope": format!("scope{}", i / 10), "kind": "Person", "count": i}))
        .collect();
    let mut app = online(&mut b);
    for i in 0..crate::MAX_EVENTS {
        app.on_event(event(
            if i % 2 == 0 { "proxy" } else { "intercept" },
            &format!("host{i} → 200 · 1 redacted"),
            &[("Person", 1)],
            Some(i as u64 % 40),
        ));
    }
    app.tab = Tab::Vault;
    app.request_refresh();
    app.sync(&mut b);
    assert_eq!(app.vault.len(), 10_000);
    app
}

fn time_frames(app: &mut App, tabs: &[Tab], n: u32) -> Duration {
    let mut t = Terminal::new(TestBackend::new(160, 48)).unwrap();
    let start = Instant::now();
    for _ in 0..n {
        for tab in tabs {
            app.tab = *tab;
            t.draw(|f| app.draw(f)).unwrap();
        }
    }
    start.elapsed() / (n * tabs.len() as u32)
}

/// A generous bound that holds even in debug builds.
#[test]
fn big_lists_render_quickly() {
    let mut app = big_app();
    let per = time_frames(&mut app, &[Tab::Live, Tab::Vault, Tab::Dashboard], 5);
    assert!(per < Duration::from_millis(100), "{per:?} per frame");
}

/// Release only: a full 160×48 frame with 500 events / 10k vault rows.
#[test]
#[cfg_attr(debug_assertions, ignore = "timing is only meaningful in release")]
fn big_lists_render_in_a_few_ms_release() {
    let mut app = big_app();
    let per = time_frames(&mut app, &[Tab::Live, Tab::Vault, Tab::Dashboard], 50);
    eprintln!("per frame: {per:?}");
    assert!(per < Duration::from_millis(4), "{per:?} per frame");
}

#[test]
fn vault_filter_on_10k_rows_is_incremental() {
    let mut app = big_app();
    let mut b = fake();
    b.vault = app.vault.clone();
    press(&mut app, &mut b, KeyCode::Char('/'));
    let start = Instant::now();
    typ(&mut app, &mut b, "scope99");
    assert_eq!(app.vault_view().len(), 110, "scope99 and scope990..999");
    assert!(start.elapsed() < Duration::from_millis(500));
}

/// Prints the 80×24 screens used in the report (`--nocapture`).
#[test]
#[ignore = "prints screens"]
fn print_screens() {
    let mut b = fake();
    let mut app = live_app(&mut b);
    for t in Tab::ALL {
        press(
            &mut app,
            &mut b,
            KeyCode::Char((b'1' + t.index() as u8) as char),
        );
        app.toasts.clear();
        println!("──── {} ────\n{}", t.title(), render_text(&app, 80, 24));
    }
    press(&mut app, &mut b, KeyCode::Char(':'));
    println!("──── palette ────\n{}", render_text(&app, 80, 24));
    let mut off = fake();
    off.online = false;
    let app = online(&mut off);
    println!("──── offline ────\n{}", render_text(&app, 80, 24));
}

#[test]
fn worker_thread_retries_offline_and_starts_only_when_asked() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::UiEvent;
    use crate::worker::{self, Cmd, Msg, Starter};

    let dir = std::env::temp_dir().join(format!("parda-tui-worker-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let started = Arc::new(AtomicUsize::new(0));
    let s2 = Arc::clone(&started);
    let described = Arc::new(AtomicUsize::new(0));
    let d2 = Arc::clone(&described);
    let starter = Starter {
        describe: Box::new(move || {
            d2.fetch_add(1, Ordering::SeqCst);
            "runs `parda daemon` for PARDA_HOME /t".into()
        }),
        start: Box::new(move || {
            s2.fetch_add(1, Ordering::SeqCst);
            Ok("started".into())
        }),
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let cmds = worker::spawn(worker::Live::new(&dir, tx.clone(), Some(starter)), tx);
    let next_status = || loop {
        match rx
            .recv_timeout(Duration::from_secs(5))
            .expect("worker answers")
        {
            UiEvent::Msg(Msg::Status(r)) => return r,
            _ => continue,
        }
    };
    let t0 = Instant::now();
    let e = next_status().unwrap_err();
    assert!(e.contains("not running"), "{e}");
    // The retry comes about a second later, on the worker's own timer.
    assert!(next_status().is_err());
    assert!(
        t0.elapsed() >= Duration::from_millis(800),
        "{:?}",
        t0.elapsed()
    );
    assert_eq!(started.load(Ordering::SeqCst), 0, "never starts by itself");
    assert_eq!(
        described.load(Ordering::SeqCst),
        1,
        "the service lookup runs once, on the worker, after the first failure"
    );
    cmds.send(Cmd::StartDaemon).unwrap();
    loop {
        match rx
            .recv_timeout(Duration::from_secs(5))
            .expect("worker answers")
        {
            UiEvent::Msg(Msg::Started(r)) => {
                assert_eq!(r.as_deref(), Ok("started"));
                break;
            }
            _ => continue,
        }
    }
    assert_eq!(started.load(Ordering::SeqCst), 1);
    drop(cmds);
    let _ = std::fs::remove_dir_all(&dir);
}

// ── fix round 1 ─────────────────────────────────────────────────────────

#[test]
fn c1_start_hint_comes_from_the_worker_once_offline() {
    let mut b = fake();
    let mut app = online(&mut b);
    assert_eq!(
        b.hint_calls, 0,
        "no service lookup while the daemon answers"
    );
    assert!(app.start_hint.is_none());
    b.online = false;
    app.request_refresh();
    app.sync(&mut b);
    assert!(b.hint_calls >= 1);
    let screen = render_text(&app, 80, 24);
    assert!(screen.contains("PARDA_HOME /x/home"), "{screen}");
}

fn paste(app: &mut App, b: &mut Fake, s: &str) {
    app.on_term(ratatui::crossterm::event::Event::Paste(s.into()));
    app.sync(b);
}

#[test]
fn i1_paste_goes_into_the_active_input_and_newlines_never_submit() {
    let mut b = fake();
    let mut app = online(&mut b);
    // Nothing active: pasted text is not keys.
    paste(&mut app, &mut b, "q3p\n");
    assert!(!app.should_quit());
    assert_eq!(app.tab, Tab::Dashboard);
    assert!(cfg(&b).protection.enabled);
    // Inspector: multi-line text is kept, nothing runs.
    press(&mut app, &mut b, KeyCode::Char('3'));
    paste(&mut app, &mut b, "line one\r\nline two\nq");
    assert!(
        app.inspector.editing,
        "pasting on the Inspector starts typing"
    );
    assert_eq!(app.inspector.input, "line one\nline two\nq");
    assert!(!b.calls.iter().any(|c| c == "Redact"));
    press(&mut app, &mut b, KeyCode::Esc);
    // Prompt: one line, the newline does not add the rule.
    press(&mut app, &mut b, KeyCode::Char('4'));
    press(&mut app, &mut b, KeyCode::Char('a'));
    paste(&mut app, &mut b, "Zubin\nWadia\n");
    assert_eq!(
        app.prompt.as_ref().map(|p| p.1.as_str()),
        Some("Zubin Wadia")
    );
    assert!(!b.calls.iter().any(|c| c == "RulesSet"));
    press(&mut app, &mut b, KeyCode::Esc);
    // Filter.
    press(&mut app, &mut b, KeyCode::Char('/'));
    paste(&mut app, &mut b, "ravi\n");
    assert_eq!(app.rules_filter.text, "ravi");
    assert!(app.rules_filter.editing);
    press(&mut app, &mut b, KeyCode::Esc);
    // Palette.
    press(&mut app, &mut b, KeyCode::Char(':'));
    paste(&mut app, &mut b, "vault\n");
    assert_eq!(
        app.palette.as_ref().map(|p| p.query.as_str()),
        Some("vault")
    );
    press(&mut app, &mut b, KeyCode::Esc);
    // Settings editor.
    select_setting(&mut app, &mut b, crate::settings::Setting::ProxyListen);
    press(&mut app, &mut b, KeyCode::Enter);
    ctrl(&mut app, &mut b, 'u');
    paste(&mut app, &mut b, "127.0.0.1:9100\n");
    assert_eq!(
        app.editor.as_ref().map(|e| e.buf.as_str()),
        Some("127.0.0.1:9100")
    );
    assert!(!b.calls.iter().any(|c| c == "ConfigSet"));
}

#[test]
fn i2_going_offline_closes_inputs_and_typing_never_starts_the_daemon() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('3'));
    press(&mut app, &mut b, KeyCode::Char('i'));
    typ(&mut app, &mut b, "hello");
    b.online = false;
    app.request_refresh();
    app.sync(&mut b);
    assert!(app.offline());
    assert!(
        !app.inspector.editing,
        "typing stops when the daemon goes away"
    );
    // The next keys of the sentence the user was typing do nothing.
    typ(&mut app, &mut b, " is this safe");
    assert_eq!(b.started, 0);

    let mut b = fake();
    let mut app = online(&mut b);
    select_setting(&mut app, &mut b, crate::settings::Setting::Threshold);
    press(&mut app, &mut b, KeyCode::Enter);
    assert!(app.editor.is_some());
    press(&mut app, &mut b, KeyCode::Char('2'));
    press(&mut app, &mut b, KeyCode::Char('/'));
    b.online = false;
    app.request_refresh();
    app.sync(&mut b);
    assert!(app.editor.is_none());
    typ(&mut app, &mut b, "s");
    assert_eq!(b.started, 0);

    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('2'));
    press(&mut app, &mut b, KeyCode::Char('/'));
    b.online = false;
    app.request_refresh();
    app.sync(&mut b);
    assert!(!app.live.filter.editing);
    // An open palette still takes the keys: `s` is text there.
    press(&mut app, &mut b, KeyCode::Char(':'));
    typ(&mut app, &mut b, "s");
    assert_eq!(b.started, 0);
}

#[test]
fn i3_only_s_starts_the_daemon_not_enter() {
    let mut b = fake();
    b.online = false;
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Enter);
    assert_eq!(b.started, 0);
    press(&mut app, &mut b, KeyCode::Char('?'));
    let help = render_text(&app, 80, 24);
    assert!(help.contains("only s"), "{help}");
    press(&mut app, &mut b, KeyCode::Esc);
    press(&mut app, &mut b, KeyCode::Char('s'));
    assert_eq!(b.started, 1);
}

#[test]
fn i4_a_failed_rules_save_leaves_no_phantom_rule() {
    let mut b = fake();
    let mut app = online(&mut b);
    press(&mut app, &mut b, KeyCode::Char('4'));
    b.fail_rules_set = true;
    press(&mut app, &mut b, KeyCode::Char('a'));
    typ(&mut app, &mut b, "Phantom Person");
    press(&mut app, &mut b, KeyCode::Enter);
    assert!(app.message().unwrap().contains("saving rules failed"));
    assert!(!b.rules.contains("Phantom"));
    assert!(
        !app.rule_rows().iter().any(|(_, t)| t.contains("Phantom")),
        "the list shows what the daemon has: {:?}",
        app.rule_rows()
    );
    assert!(!render_text(&app, 80, 24).contains("Phantom"));
    // A delete that fails comes back too.
    press(&mut app, &mut b, KeyCode::Char('d'));
    assert!(
        app.rule_rows()
            .iter()
            .any(|(_, t)| t.contains("Ravi Kumar"))
    );
    // And a later successful save applies normally.
    b.fail_rules_set = false;
    press(&mut app, &mut b, KeyCode::Char('w'));
    typ(&mut app, &mut b, "Acme");
    press(&mut app, &mut b, KeyCode::Enter);
    assert!(b.rules.contains("Acme"));
    assert!(app.rule_rows().iter().any(|(_, t)| t == "Acme"));
}

/// Every screen the app can show, set up on a fresh app.
fn all_screens() -> Vec<(&'static str, App)> {
    type Setup = fn(&mut App, &mut Fake);
    let setups: Vec<(&'static str, Setup)> = vec![
        ("dashboard", |app, _| {
            let mut st = app.status.clone().unwrap();
            st["intercept"] = json!({"enabled": true, "listening": null, "ca": false,
                                     "error": null, "pac": "http://127.0.0.1:8788/parda.pac"});
            st["model"] = Value::Null;
            st["model_error"] = json!("model file missing");
            app.status = Some(st);
        }),
        ("live", |app, b| {
            press(app, b, KeyCode::Char('2'));
            press(app, b, KeyCode::Char('/'));
            typ(app, b, "a");
            press(app, b, KeyCode::Enter);
            press(app, b, KeyCode::Enter);
        }),
        ("inspector", |app, b| {
            press(app, b, KeyCode::Char('3'));
            press(app, b, KeyCode::Char('i'));
            typ(app, b, "hi Ravi Kumar");
            press(app, b, KeyCode::Enter);
            app.inspector.busy = true;
        }),
        ("rules", |app, b| {
            press(app, b, KeyCode::Char('4'));
            press(app, b, KeyCode::Enter);
            press(app, b, KeyCode::Char('/'));
        }),
        ("vault", |app, b| {
            press(app, b, KeyCode::Char('5'));
            press(app, b, KeyCode::Enter);
        }),
        ("settings editor", |app, b| {
            select_setting(app, b, crate::settings::Setting::Threshold);
            press(app, b, KeyCode::Enter);
            typ(app, b, "x");
            press(app, b, KeyCode::Enter);
        }),
        ("palette", |app, b| press(app, b, KeyCode::Char(':'))),
        ("help", |app, b| press(app, b, KeyCode::Char('?'))),
        ("toasts", |app, _| {
            for i in 0..3 {
                app.toast(
                    format!("{i} a rather long message that has to wrap over several lines here"),
                    crate::Level::Warn,
                );
            }
        }),
        ("confirm", |app, b| {
            press(app, b, KeyCode::Char('5'));
            press(app, b, KeyCode::Char('w'));
        }),
        ("prompt", |app, b| {
            press(app, b, KeyCode::Char('4'));
            press(app, b, KeyCode::Char('a'));
            typ(app, b, "Zubin");
        }),
        ("offline", |app, b| {
            b.online = false;
            app.request_refresh();
            app.sync(b);
        }),
        ("starting", |app, b| {
            b.online = false;
            app.request_refresh();
            app.sync(b);
            app.starting = Some(Instant::now());
        }),
    ];
    setups
        .into_iter()
        .map(|(name, f)| {
            let mut b = fake();
            let mut app = live_app(&mut b);
            press(&mut app, &mut b, KeyCode::Char('1'));
            f(&mut app, &mut b);
            (name, app)
        })
        .collect()
}

#[test]
fn i5_every_screen_renders_at_every_size_without_panicking() {
    let widths: Vec<u16> = (1..=40).chain((41..=100).step_by(3)).chain([100]).collect();
    let mut failures = Vec::new();
    for (name, app) in all_screens() {
        'screen: for &w in &widths {
            for h in 1..=40u16 {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    render_text(&app, w, h);
                }));
                if r.is_err() {
                    // The first size per screen is enough to go on.
                    failures.push(format!("{name} at {w}×{h}"));
                    break 'screen;
                }
            }
        }
    }
    assert!(failures.is_empty(), "panics: {failures:?}");
}
