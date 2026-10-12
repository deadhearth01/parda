//! Rendering of each tab.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, Tabs, Wrap,
};
use serde_json::Value;

use crate::app::{App, Prompt, Tab};

const ACCENT: Color = Color::Cyan;

pub fn draw(app: &App, f: &mut Frame) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);

    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| Line::from(format!("{} {}", i + 1, t.title())))
        .collect();
    let selected = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);
    let state = if app.connected {
        "● connected"
    } else {
        "○ daemon offline"
    };
    let tabs = Tabs::new(titles)
        .select(selected)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Line::from(vec![
                    Span::styled(
                        " parda ",
                        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("{state} ")),
                ])),
        )
        .highlight_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD));
    f.render_widget(tabs, chunks[0]);

    match app.tab {
        Tab::Dashboard => dashboard(app, f, chunks[1]),
        Tab::Live => live(app, f, chunks[1]),
        Tab::Inspector => inspector(app, f, chunks[1]),
        Tab::Rules => rules(app, f, chunks[1]),
        Tab::Vault => vault(app, f, chunks[1]),
        Tab::Setup => setup(app, f, chunks[1]),
    }

    let footer = match (&app.message, app.tab) {
        (Some(m), _) => m.clone(),
        (None, Tab::Inspector) => {
            "i/Enter edit · Enter run · r restore preview · Esc clear · q quit".into()
        }
        (None, Tab::Rules) => "a add person · w allow term · d delete · ↑↓ select · q quit".into(),
        (None, Tab::Vault) => "w wipe all · q quit".into(),
        (None, Tab::Setup) => "m strict/fast · s surrogate/token · q quit".into(),
        _ => "1-6 tabs · Tab next · ? help · q quit".into(),
    };
    f.render_widget(
        Paragraph::new(footer).style(Style::default().fg(Color::DarkGray)),
        chunks[2],
    );

    if let Some((kind, buf)) = &app.prompt {
        let title = match kind {
            Prompt::AddPerson => " Person to always mask ",
            Prompt::AllowTerm => " Term never to mask ",
        };
        let r = centered(area, 60, 3);
        f.render_widget(Clear, r);
        f.render_widget(
            Paragraph::new(format!("{buf}▏"))
                .block(Block::default().borders(Borders::ALL).title(title)),
            r,
        );
    }
    if app.help {
        let r = centered(area, 64, 12);
        f.render_widget(Clear, r);
        f.render_widget(
            Paragraph::new(vec![
                Line::from("1 Dashboard  2 Live  3 Inspector  4 Rules  5 Vault  6 Setup"),
                Line::from(""),
                Line::from("Inspector: type text, Enter shows what would be sent"),
                Line::from("Rules: a add a person, w allow a term, d delete"),
                Line::from("Vault: w wipes every mapping (asks first)"),
                Line::from("Setup: m strict/fast mode, s surrogate/token style"),
                Line::from(""),
                Line::from("Values are never shown in the live feed: kinds and counts only."),
                Line::from("? closes this help · q quits"),
            ])
            .block(Block::default().borders(Borders::ALL).title(" help ")),
            r,
        );
    }
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

fn block(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .title(format!(" {title} "))
}

fn s<'a>(v: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(v, |acc, k| &acc[*k])
}

fn text(v: &Value) -> String {
    match v {
        Value::Null => "-".into(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn percentile(mut xs: Vec<u64>, p: f64) -> Option<u64> {
    if xs.is_empty() {
        return None;
    }
    xs.sort_unstable();
    let i = ((xs.len() - 1) as f64 * p).round() as usize;
    xs.get(i).copied()
}

fn dashboard(app: &App, f: &mut Frame, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let null = Value::Null;
    let st = app.status.as_ref().unwrap_or(&null);
    let latencies: Vec<u64> = app
        .events
        .iter()
        .filter(|e| e.surface == "proxy")
        .filter_map(|e| e.latency_ms)
        .collect();
    let lat = match (
        percentile(latencies.clone(), 0.5),
        percentile(latencies, 0.95),
    ) {
        (Some(a), Some(b)) => format!("p50 {a} ms · p95 {b} ms"),
        _ => "no proxied requests yet".into(),
    };
    let model = match (st["model"].as_str(), st["model_error"].as_str()) {
        (Some(m), _) => m.to_string(),
        (None, Some(e)) => format!("NOT LOADED — {e}"),
        _ => "none (rules only)".into(),
    };
    let lines = vec![
        Line::from(format!(
            "daemon     {}",
            if app.connected {
                format!(
                    "running · pid {} · up {} s",
                    text(&st["pid"]),
                    text(&st["uptime_s"])
                )
            } else {
                "unreachable".into()
            }
        )),
        Line::from(format!(
            "proxy      {}",
            st["proxy"]
                .as_str()
                .map(|a| format!("http://{a}"))
                .unwrap_or_else(|| "off".into())
        )),
        Line::from(format!(
            "clipboard  {}",
            if st["clipboard"].as_bool() == Some(true) {
                format!("on · hotkey {}", text(&st["hotkey"]))
            } else {
                "off".into()
            }
        )),
        Line::from(format!("model      {model}")),
        Line::from(format!(
            "mode       {}  ·  style {}",
            text(&st["mode"]),
            text(&st["style"])
        )),
        Line::from(format!("latency    {lat}")),
        Line::from(format!(
            "activity   {} redactions · {} cache hits · {} ML calls ({} failed)",
            text(s(st, &["stats", "redactions"])),
            text(s(st, &["stats", "cache_hits"])),
            text(s(st, &["stats", "ml_calls"])),
            text(s(st, &["stats", "ml_failures"])),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .block(block("Status"))
            .wrap(Wrap { trim: true }),
        cols[0],
    );

    let rows: Vec<Row> = st["stats"]["entities"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| Row::new(vec![Cell::from(k.clone()), Cell::from(text(v))]))
                .collect()
        })
        .unwrap_or_default();
    let table = Table::new(
        rows,
        [Constraint::Percentage(70), Constraint::Percentage(30)],
    )
    .header(Row::new(vec!["kind", "redacted"]).style(Style::default().add_modifier(Modifier::BOLD)))
    .block(block("Redacted since start"));
    f.render_widget(table, cols[1]);
}

fn live(app: &App, f: &mut Frame, area: Rect) {
    let height = area.height.saturating_sub(2) as usize;
    let items: Vec<ListItem> = app
        .events
        .iter()
        .rev()
        .take(height.max(1))
        .rev()
        .map(|e| {
            let secs = (e.ts_ms / 1000) % 86_400;
            let ts = format!(
                "{:02}:{:02}:{:02}",
                secs / 3600,
                (secs / 60) % 60,
                secs % 60
            );
            let kinds: Vec<String> = e.counts.iter().map(|(k, n)| format!("{k}×{n}")).collect();
            let ms = e.latency_ms.map(|m| format!(" {m}ms")).unwrap_or_default();
            let style = if e.level == "warn" {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{ts} "), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{:<9} ", e.surface), Style::default().fg(ACCENT)),
                Span::styled(e.summary.clone(), style),
                Span::raw(format!("{ms} {}", kinds.join(" "))),
            ]))
        })
        .collect();
    let title = format!("Live ({} events · values never shown)", app.events.len());
    f.render_widget(List::new(items).block(block(&title)), area);
}

fn inspector(app: &App, f: &mut Frame, area: Rect) {
    let ins = &app.inspector;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(3),
            Constraint::Length(8),
        ])
        .split(area);
    let cursor = if ins.editing { "▏" } else { "" };
    let title = if ins.editing {
        "Input (editing — Enter to run, Esc to stop)"
    } else {
        "Input (press i to type)"
    };
    f.render_widget(
        Paragraph::new(format!("{}{cursor}", ins.input))
            .wrap(Wrap { trim: false })
            .block(block(title)),
        rows[0],
    );
    let (out_title, out) = match (&ins.error, ins.show_restore) {
        (Some(e), _) => ("Error", e.clone()),
        (None, false) => ("Sent to the AI", ins.redacted.clone().unwrap_or_default()),
        (None, true) => (
            "Restored (what you would see back)",
            ins.restored.clone().unwrap_or_default(),
        ),
    };
    f.render_widget(
        Paragraph::new(out)
            .wrap(Wrap { trim: false })
            .block(block(out_title)),
        rows[1],
    );
    let rows_t: Vec<Row> = ins
        .replaced
        .iter()
        .map(|r| {
            Row::new(vec![
                Cell::from(text(&r["kind"])),
                Cell::from(text(&r["surrogate"])),
                Cell::from(match &r["source"] {
                    Value::String(s) => s.clone(),
                    Value::Object(o) => o.keys().next().cloned().unwrap_or_default(),
                    other => other.to_string(),
                }),
            ])
        })
        .collect();
    let table = Table::new(
        rows_t,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(50),
            Constraint::Percentage(25),
        ],
    )
    .header(
        Row::new(vec!["kind", "replaced with", "found by"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(block("Replacements"));
    f.render_widget(table, rows[2]);
}

fn rules(app: &App, f: &mut Frame, area: Rect) {
    let rows = app.rule_rows();
    let items: Vec<ListItem> = if rows.is_empty() {
        vec![ListItem::new(
            "no rules yet — press a to add a person to always mask",
        )]
    } else {
        rows.iter()
            .map(|(section, t)| {
                let color = match *section {
                    "person" => Color::Green,
                    "term" => Color::Magenta,
                    _ => Color::Blue,
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{section:<7}"), Style::default().fg(color)),
                    Span::raw(t.clone()),
                ]))
            })
            .collect()
    };
    let mut state = ListState::default();
    if !rows.is_empty() {
        state.select(Some(app.rules_sel.min(rows.len() - 1)));
    }
    let list = List::new(items)
        .block(block(
            "Rules (people & terms always masked · allow-list never masked)",
        ))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(list, area, &mut state);
}

fn vault(app: &App, f: &mut Frame, area: Rect) {
    let rows: Vec<Row> = app
        .vault
        .iter()
        .map(|r| Row::new(vec![text(&r["scope"]), text(&r["kind"]), text(&r["count"])]))
        .collect();
    let total: u64 = app.vault.iter().filter_map(|r| r["count"].as_u64()).sum();
    let title = format!("Vault — {total} mappings (encrypted at rest)");
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(40),
            Constraint::Percentage(20),
        ],
    )
    .header(
        Row::new(vec!["scope", "kind", "mappings"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(block(&title));
    f.render_widget(table, area);
}

fn setup(app: &App, f: &mut Frame, area: Rect) {
    let null = Value::Null;
    let st = app.status.as_ref().unwrap_or(&null);
    let url = st["proxy"]
        .as_str()
        .map(|a| format!("http://{a}"))
        .unwrap_or_else(|| "http://127.0.0.1:8787".into());
    let lines = vec![
        Line::styled("Agents", Style::default().add_modifier(Modifier::BOLD)),
        Line::from(format!("  Claude Code   export ANTHROPIC_BASE_URL={url}")),
        Line::from(format!("  Codex / SDKs  export OPENAI_BASE_URL={url}/v1")),
        Line::from(""),
        Line::styled("Chat apps", Style::default().add_modifier(Modifier::BOLD)),
        Line::from(format!(
            "  copy, then press the paste-safe hotkey ({}) instead of paste",
            text(&st["hotkey"])
        )),
        Line::from(""),
        Line::styled("Behaviour", Style::default().add_modifier(Modifier::BOLD)),
        Line::from(format!(
            "  mode   {}   (m: strict refuses when the model fails; fast continues rules-only)",
            text(&st["mode"])
        )),
        Line::from(format!(
            "  style  {}   (s: realistic stand-ins or ⟦TOKENS⟧)",
            text(&st["style"])
        )),
        Line::from(format!(
            "  model  {}",
            st["model"].as_str().unwrap_or("none")
        )),
        Line::from(""),
        Line::from(format!("  config {}", text(s(st, &["paths", "config"])))),
        Line::from("  run `parda doctor` for a full check"),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .block(block("Setup"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Backend;
    use parda_ipc::{Event, Request};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use serde_json::json;

    struct Fake {
        rules: String,
        calls: Vec<String>,
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
            Ok(match req {
                Request::Status => json!({
                    "pid": 42, "uptime_s": 7, "proxy": "127.0.0.1:8787", "clipboard": true,
                    "hotkey": "default", "model": "gliner-pii-edge", "mode": "strict", "style": "surrogate",
                    "stats": {"redactions": 3, "cache_hits": 1, "ml_calls": 2, "ml_failures": 0,
                              "entities": {"Person": 2, "Email": 1}},
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
                Request::RulesSet { rules_toml } => {
                    self.rules = rules_toml;
                    json!({})
                }
                Request::VaultStats => {
                    json!({"stats": [{"scope": "global", "kind": "Person", "count": 5}]})
                }
                _ => json!({}),
            })
        }
    }

    fn fake() -> Fake {
        Fake {
            rules: "[[person]]\nname = \"Ravi Kumar\"\n".into(),
            calls: vec![],
        }
    }

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn render(app: &App) -> String {
        let mut t = Terminal::new(TestBackend::new(100, 30)).unwrap();
        t.draw(|f| app.draw(f)).unwrap();
        let buf = t.backend().buffer().clone();
        let mut s = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn every_tab_renders_and_number_keys_switch() {
        let mut b = fake();
        let mut app = App::new();
        app.refresh(&mut b);
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
        for (k, want) in [
            ('2', "Live ("),
            ('3', "Input"),
            ('4', "Ravi Kumar"),
            ('5', "global"),
            ('6', "ANTHROPIC_BASE_URL"),
        ] {
            app.on_key(key(KeyCode::Char(k)), &mut b);
            let screen = render(&app);
            assert!(screen.contains(want), "tab {k} lacks {want:?}:\n{screen}");
        }
        app.on_key(key(KeyCode::Char('1')), &mut b);
        assert_eq!(app.tab, Tab::Dashboard);
    }

    #[test]
    fn inspector_shows_redacted_output_and_restore_preview() {
        let mut b = fake();
        let mut app = App::new();
        app.on_key(key(KeyCode::Char('3')), &mut b);
        app.on_key(key(KeyCode::Char('i')), &mut b);
        for c in "hi Ravi Kumar".chars() {
            app.on_key(key(KeyCode::Char(c)), &mut b);
        }
        // While editing, digits and q are text, not commands.
        assert_eq!(app.tab, Tab::Inspector);
        app.on_key(key(KeyCode::Enter), &mut b);
        let screen = render(&app);
        assert!(screen.contains("hi Arjun Mehta"), "{screen}");
        assert!(screen.contains("Person"));
        app.on_key(key(KeyCode::Char('r')), &mut b);
        assert!(render(&app).contains("Restored"));
    }

    #[test]
    fn rules_add_person_saves_through_backend() {
        let mut b = fake();
        let mut app = App::new();
        app.on_key(key(KeyCode::Char('4')), &mut b);
        app.on_key(key(KeyCode::Char('a')), &mut b);
        for c in "Zubin Wadia".chars() {
            app.on_key(key(KeyCode::Char(c)), &mut b);
        }
        app.on_key(key(KeyCode::Enter), &mut b);
        assert!(b.rules.contains("Zubin Wadia") && b.rules.contains("Ravi Kumar"));
        assert!(render(&app).contains("Zubin Wadia"));
    }

    #[test]
    fn q_quits_and_live_feed_shows_events() {
        let mut b = fake();
        let mut app = App::new();
        app.on_key(key(KeyCode::Char('2')), &mut b);
        let mut e = Event::now("clipboard", "pasted with 1 value(s) redacted");
        e.counts.insert("Person".into(), 1);
        app.on_event(e);
        let screen = render(&app);
        assert!(screen.contains("pasted with 1 value(s) redacted") && screen.contains("Person×1"));
        assert!(!app.should_quit());
        app.on_key(key(KeyCode::Char('q')), &mut b);
        assert!(app.should_quit());
    }
}
