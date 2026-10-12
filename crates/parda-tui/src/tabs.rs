//! Rendering of each tab.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, Tabs, Wrap,
};
use serde_json::Value;

use crate::app::{App, Hit, Prompt, Tab};
use crate::settings;

const ACCENT: Color = Color::Cyan;

fn hit(app: &App, r: Rect, h: Hit) {
    app.hits.borrow_mut().push((r, h));
}

/// First visible row so that `sel` stays inside a window of `height` rows.
fn window_start(sel: usize, height: usize) -> usize {
    if height == 0 || sel < height {
        0
    } else {
        sel + 1 - height
    }
}

pub fn draw(app: &App, f: &mut Frame) {
    app.hits.borrow_mut().clear();
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
    let on = app.protection_on();
    let switch = if on {
        Span::styled(
            " ■ PROTECTION ON ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " □ PROTECTION OFF — p to resume ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        )
    };
    let switch_w = switch.width() as u16;
    let header = chunks[0];
    let tabs = Tabs::new(titles.clone())
        .select(selected)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(if on {
                    Style::default()
                } else {
                    Style::default().fg(Color::Red)
                })
                .title(Line::from(vec![
                    Span::styled(
                        " parda ",
                        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("{state} ")),
                ]))
                .title_top(Line::from(switch).right_aligned()),
        )
        .highlight_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD));
    f.render_widget(tabs, header);
    // Clickable regions: the switch (right end of the top border) and each
    // tab title (Tabs draws " title " separated by a 1-cell divider).
    if header.width > switch_w + 2 {
        hit(
            app,
            Rect::new(header.right() - 1 - switch_w, header.y, switch_w, 1),
            Hit::Protection,
        );
    }
    let mut x = header.x + 1;
    for (t, title) in Tab::ALL.iter().zip(&titles) {
        let w = title.width() as u16 + 2;
        if x >= header.right() {
            break;
        }
        hit(
            app,
            Rect::new(x, header.y + 1, w.min(header.right() - x), 1),
            Hit::Tab(*t),
        );
        x += w + 1;
    }

    match app.tab {
        Tab::Dashboard => dashboard(app, f, chunks[1]),
        Tab::Live => live(app, f, chunks[1]),
        Tab::Inspector => inspector(app, f, chunks[1]),
        Tab::Rules => rules(app, f, chunks[1]),
        Tab::Vault => vault(app, f, chunks[1]),
        Tab::Settings => settings_tab(app, f, chunks[1]),
    }

    let footer = match (&app.message, app.tab) {
        (Some(m), _) => m.clone(),
        (None, Tab::Inspector) => {
            "i/Enter/click edit · Enter run · r restore preview · Esc clear · q quit".into()
        }
        (None, Tab::Rules) => {
            "a add person · w allow term · d delete · ↑↓/wheel/click select · q quit".into()
        }
        (None, Tab::Vault) => "w wipe all · q quit".into(),
        (None, Tab::Live) => "↑↓/wheel scroll · End newest · p protection · q quit".into(),
        (None, Tab::Settings) => {
            "↑↓ select · Enter/Space/click change · ←/right-click back · p protection · q quit"
                .into()
        }
        _ => "1-6 or click tabs · p protection on/off · ? help · q quit".into(),
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
        let r = centered(area, 72, 15);
        f.render_widget(Clear, r);
        f.render_widget(
            Paragraph::new(vec![
                Line::from("1 Dashboard  2 Live  3 Inspector  4 Rules  5 Vault  6 Settings"),
                Line::from(""),
                Line::from("p (anywhere) or click the header switch: protection on / off"),
                Line::from("Inspector: type text, Enter shows what would be sent"),
                Line::from("Rules: a add a person, w allow a term, d delete"),
                Line::from("Vault: w wipes every mapping (asks first)"),
                Line::from(
                    "Settings: Enter/Space/click changes a value, ← or right-click goes back",
                ),
                Line::from(""),
                Line::from("Mouse: click tabs, rows and the switch; wheel scrolls lists."),
                Line::from("Hold Shift (Option on macOS) while dragging to select text."),
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

fn num(v: &Value) -> u64 {
    v.as_u64().unwrap_or(0)
}

fn kv_rows(map: &Value) -> Vec<(String, u64)> {
    let mut rows: Vec<(String, u64)> = map
        .as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), num(v))).collect())
        .unwrap_or_default();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    rows
}

fn dashboard(app: &App, f: &mut Frame, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(area);
    let null = Value::Null;
    let st = app.status.as_ref().unwrap_or(&null);
    let stats = &st["stats"];
    let act = &st["activity"];

    // Latency: daemon-side percentiles, else what this session has seen.
    let lat = match (
        act["latency_ms"]["p50"].as_u64(),
        act["latency_ms"]["p95"].as_u64(),
    ) {
        (Some(a), Some(b)) => format!(
            "p50 {a} ms · p95 {b} ms · max {} ms ({} requests)",
            text(&act["latency_ms"]["max"]),
            text(&act["latency_ms"]["samples"])
        ),
        _ => {
            let latencies: Vec<u64> = app
                .events
                .iter()
                .filter(|e| e.surface == "proxy")
                .filter_map(|e| e.latency_ms)
                .collect();
            match (
                percentile(latencies.clone(), 0.5),
                percentile(latencies, 0.95),
            ) {
                (Some(a), Some(b)) => format!("p50 {a} ms · p95 {b} ms"),
                _ => "no proxied requests yet".into(),
            }
        }
    };
    let model = match (st["model"].as_str(), st["model_error"].as_str()) {
        (Some(m), _) => m.to_string(),
        (None, Some(e)) => format!("NOT LOADED — {e}"),
        _ => "none (rules only)".into(),
    };
    let ml_calls = num(&stats["ml_calls"]);
    let ml_avg = if ml_calls > 0 {
        format!(
            "{:.1} ms avg",
            num(&stats["ml_ms_total"]) as f64 / ml_calls as f64
        )
    } else {
        "-".into()
    };
    let frags = num(&stats["fragments"]);
    let hit_rate = if frags > 0 {
        format!(
            "{:.0}%",
            100.0 * num(&stats["cache_hits"]) as f64 / frags as f64
        )
    } else {
        "-".into()
    };
    let total: u64 = kv_rows(&stats["entities"]).iter().map(|(_, n)| n).sum();
    let protection = if app.protection_on() {
        Line::from(vec![
            Span::styled("protection ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "ON",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled("protection ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "OFF — text is sent unfiltered (press p)",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ])
    };
    let lines = vec![
        protection,
        Line::from(vec![
            Span::styled("filtered   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{total} values"),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" in {} redactions", text(&stats["redactions"]))),
        ]),
        Line::from(format!(
            "daemon     {}",
            if app.connected {
                format!(
                    "running · pid {} · up {}",
                    text(&st["pid"]),
                    uptime(num(&st["uptime_s"]))
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
            "model use  {ml_calls} calls · {ml_avg} · {} failed · {} skipped",
            num(&stats["ml_failures"]),
            num(&stats["ml_skipped"])
        )),
        Line::from(format!(
            "cache      {hit_rate} hits ({} of {} fragments)",
            num(&stats["cache_hits"]),
            frags
        )),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .block(block("Status"))
            .wrap(Wrap { trim: true }),
        cols[0],
    );

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(cols[1]);
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let kind_rows: Vec<Row> = kv_rows(&stats["entities"])
        .into_iter()
        .map(|(k, n)| Row::new(vec![Cell::from(k), Cell::from(n.to_string())]))
        .collect();
    let title = format!("Filtered by kind ({total})");
    let table = Table::new(
        kind_rows,
        [Constraint::Percentage(70), Constraint::Percentage(30)],
    )
    .header(Row::new(vec!["kind", "count"]).style(bold))
    .block(block(&title));
    f.render_widget(table, right[0]);

    let mut rows: Vec<Row> = kv_rows(&stats["by_source"])
        .into_iter()
        .map(|(k, n)| Row::new(vec!["found by".to_string(), k, n.to_string()]))
        .collect();
    if let Some(surfaces) = act["surfaces"].as_object() {
        for (name, s) in surfaces {
            if name == "daemon" {
                continue;
            }
            rows.push(Row::new(vec![
                "surface".to_string(),
                format!("{name} ({} events)", num(&s["events"])),
                num(&s["redacted"]).to_string(),
            ]));
        }
    }
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(50),
            Constraint::Percentage(25),
        ],
    )
    .header(Row::new(vec!["", "source", "values"]).style(bold))
    .block(block("Where from"));
    f.render_widget(table, right[1]);
}

fn uptime(s: u64) -> String {
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m {}s", s / 60, s % 60),
        _ => format!("{}h {}m", s / 3600, (s / 60) % 60),
    }
}

fn live(app: &App, f: &mut Frame, area: Rect) {
    let height = area.height.saturating_sub(2) as usize;
    let scroll = app.live_scroll.min(app.events.len().saturating_sub(1));
    let items: Vec<ListItem> = app
        .events
        .iter()
        .rev()
        .skip(scroll)
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
    let title = if scroll > 0 {
        format!(
            "Live ({} events · {scroll} newer hidden, End to jump · values never shown)",
            app.events.len()
        )
    } else {
        format!("Live ({} events · values never shown)", app.events.len())
    };
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
    hit(app, rows[0], Hit::Input);
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
    let title = "Rules (people & terms always masked · allow-list never masked)";
    if rows.is_empty() {
        f.render_widget(
            List::new(vec![ListItem::new(
                "no rules yet — press a to add a person to always mask",
            )])
            .block(block(title)),
            area,
        );
        return;
    }
    let height = area.height.saturating_sub(2) as usize;
    let sel = app.rules_sel.min(rows.len() - 1);
    let start = window_start(sel, height);
    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .skip(start)
        .take(height)
        .map(|(i, (section, t))| {
            let color = match *section {
                "person" => Color::Green,
                "term" => Color::Magenta,
                _ => Color::Blue,
            };
            hit(
                app,
                Rect::new(
                    area.x + 1,
                    area.y + 1 + (i - start) as u16,
                    area.width.saturating_sub(2),
                    1,
                ),
                Hit::Row(i),
            );
            ListItem::new(Line::from(vec![
                Span::styled(format!("{section:<7}"), Style::default().fg(color)),
                Span::raw(t.clone()),
            ]))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(sel - start));
    let list = List::new(items)
        .block(block(title))
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

fn settings_tab(app: &App, f: &mut Frame, area: Rect) {
    let null = Value::Null;
    let st = app.status.as_ref().unwrap_or(&null);
    let url = st["proxy"]
        .as_str()
        .map(|a| format!("http://{a}"))
        .unwrap_or_else(|| "http://127.0.0.1:8787".into());
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(4),
            Constraint::Length(4),
        ])
        .split(area);
    let connect = vec![
        Line::from(format!("Claude Code   export ANTHROPIC_BASE_URL={url}")),
        Line::from(format!("Codex / SDKs  export OPENAI_BASE_URL={url}/v1")),
        Line::from(format!(
            "Chat apps     copy, then press the paste-safe hotkey ({}) instead of paste · config {}",
            text(&st["hotkey"]),
            text(s(st, &["paths", "config"]))
        )),
    ];
    f.render_widget(
        Paragraph::new(connect)
            .block(block("Connect"))
            .wrap(Wrap { trim: false }),
        parts[0],
    );

    let Some(cfg) = &app.config else {
        f.render_widget(
            Paragraph::new("configuration not loaded — is the daemon running?")
                .block(block("Settings")),
            parts[1],
        );
        return;
    };
    let all = settings::all();
    let rows: Vec<settings::Row> = all.iter().map(|x| settings::row(x, cfg)).collect();
    let list_area = parts[1];
    let height = list_area.height.saturating_sub(2) as usize;
    let sel = app.settings_sel.min(rows.len() - 1);
    let start = window_start(sel, height);
    let label_w = list_area.width.saturating_sub(2).saturating_sub(12 + 26) as usize;
    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .skip(start)
        .take(height)
        .map(|(i, r)| {
            hit(
                app,
                Rect::new(
                    list_area.x + 1,
                    list_area.y + 1 + (i - start) as u16,
                    list_area.width.saturating_sub(2),
                    1,
                ),
                Hit::Row(i),
            );
            let value_style = match (r.on, r.risky) {
                (Some(true), true) => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                (Some(true), false) => Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
                (Some(false), _) => Style::default().fg(Color::DarkGray),
                (None, _) => Style::default().fg(ACCENT),
            };
            let value = match r.on {
                Some(true) => format!("● {}", r.value),
                Some(false) => format!("○ {}", r.value),
                None => format!("◆ {}", r.value),
            };
            let mut label: String = r.label.chars().take(label_w.max(8)).collect();
            if r.restart {
                label.push_str(" ↻");
            }
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<11} ", r.group),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(format!("{label:<width$} ", width = label_w.max(8) + 2)),
                Span::styled(value, value_style),
            ]))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(sel - start));
    let title = format!(
        "Settings ({}/{}) · ↻ = applies after a daemon restart",
        sel + 1,
        rows.len()
    );
    f.render_stateful_widget(
        List::new(items)
            .block(block(&title))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        list_area,
        &mut state,
    );
    let r = &rows[sel];
    f.render_widget(
        Paragraph::new(r.help)
            .wrap(Wrap { trim: true })
            .block(block(&r.label)),
        parts[2],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Backend;
    use parda_ipc::{Event, Request};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{
        KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    };
    use serde_json::json;

    struct Fake {
        rules: String,
        config: String,
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
                Request::RulesSet { rules_toml } => {
                    self.rules = rules_toml;
                    json!({})
                }
                Request::VaultStats => {
                    json!({"stats": [{"scope": "global", "kind": "Person", "count": 5}]})
                }
                Request::ConfigGet => json!({"toml": self.config}),
                Request::ConfigSet { toml } => {
                    let old = parda_core::Config::from_toml_str(&self.config).unwrap();
                    let new = parda_core::Config::from_toml_str(&toml).unwrap();
                    self.config = toml;
                    json!({"restart_required": old.proxy.enabled != new.proxy.enabled})
                }
                _ => json!({}),
            })
        }
    }

    fn fake() -> Fake {
        Fake {
            rules: "[[person]]\nname = \"Ravi Kumar\"\n".into(),
            config: parda_core::Config::default().to_toml_string().unwrap(),
            calls: vec![],
        }
    }

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn cfg(b: &Fake) -> parda_core::Config {
        parda_core::Config::from_toml_str(&b.config).unwrap()
    }

    fn click_at(app: &mut App, b: &mut Fake, x: u16, y: u16, button: MouseButton) {
        app.on_mouse(
            MouseEvent {
                kind: MouseEventKind::Down(button),
                column: x,
                row: y,
                modifiers: KeyModifiers::NONE,
            },
            b,
        );
    }

    fn wheel(app: &mut App, b: &mut Fake, down: bool) {
        app.on_mouse(
            MouseEvent {
                kind: if down {
                    MouseEventKind::ScrollDown
                } else {
                    MouseEventKind::ScrollUp
                },
                column: 10,
                row: 10,
                modifiers: KeyModifiers::NONE,
            },
            b,
        );
    }

    /// Render, then return the cell position of `needle` (ASCII) on screen.
    fn find(app: &App, needle: &str) -> (u16, u16) {
        let mut t = Terminal::new(TestBackend::new(100, 30)).unwrap();
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
        panic!("{needle:?} not on screen");
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

    #[test]
    fn p_toggles_protection_and_header_shows_it() {
        let mut b = fake();
        let mut app = App::new();
        app.refresh(&mut b);
        assert!(render(&app).contains("PROTECTION ON"));
        app.on_key(key(KeyCode::Char('p')), &mut b);
        assert!(!cfg(&b).protection.enabled);
        let screen = render(&app);
        assert!(screen.contains("PROTECTION OFF"), "{screen}");
        assert!(screen.contains("text is sent unfiltered"), "{screen}");
        app.on_key(key(KeyCode::Char('p')), &mut b);
        assert!(cfg(&b).protection.enabled);
    }

    #[test]
    fn clicking_tabs_and_the_switch() {
        let mut b = fake();
        let mut app = App::new();
        app.refresh(&mut b);
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
        app.on_key(key(KeyCode::Char('3')), &mut b);
        let (x, y) = find(&app, "Input (press i to type)");
        click_at(&mut app, &mut b, x, y + 1, MouseButton::Left);
        assert!(app.inspector.editing);
    }

    #[test]
    fn settings_tab_lists_options_and_changes_them() {
        let mut b = fake();
        let mut app = App::new();
        app.on_key(key(KeyCode::Char('6')), &mut b);
        let screen = render(&app);
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
        app.on_key(key(KeyCode::Down), &mut b);
        app.on_key(key(KeyCode::Enter), &mut b);
        assert_eq!(cfg(&b).detect.mode, parda_core::Mode::Fast);
        // Clicking the replacement-style row changes it; right-click changes it back.
        let (x, y) = find(&app, "replacement style");
        click_at(&mut app, &mut b, x, y, MouseButton::Left);
        assert_eq!(cfg(&b).replace.style, parda_core::Style::Token);
        click_at(&mut app, &mut b, x, y, MouseButton::Right);
        assert_eq!(cfg(&b).replace.style, parda_core::Style::Surrogate);
        // Restart-required settings say so.
        let (x, y) = find(&app, "agent proxy");
        click_at(&mut app, &mut b, x, y, MouseButton::Left);
        assert!(!cfg(&b).proxy.enabled);
        assert!(
            app.message.as_deref().unwrap_or("").contains("restart"),
            "{:?}",
            app.message
        );
    }

    #[test]
    fn risky_setting_asks_first_and_wheel_moves_selection() {
        let mut b = fake();
        let mut app = App::new();
        app.on_key(key(KeyCode::Char('6')), &mut b);
        let i = crate::settings::all()
            .iter()
            .position(|s| *s == crate::settings::Setting::LogValues)
            .unwrap();
        for _ in 0..i {
            wheel(&mut app, &mut b, true);
        }
        assert_eq!(app.settings_sel, i);
        app.on_key(key(KeyCode::Enter), &mut b);
        assert!(!cfg(&b).privacy.log_values, "must not change before y");
        app.on_key(key(KeyCode::Char('n')), &mut b);
        assert!(!cfg(&b).privacy.log_values);
        app.on_key(key(KeyCode::Enter), &mut b);
        app.on_key(key(KeyCode::Char('y')), &mut b);
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
    fn live_feed_scrolls_with_wheel() {
        let mut b = fake();
        let mut app = App::new();
        app.on_key(key(KeyCode::Char('2')), &mut b);
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
        app.on_key(key(KeyCode::End), &mut b);
        assert!(render(&app).contains("request number 59"));
    }
}
