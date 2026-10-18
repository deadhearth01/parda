//! The body of each tab. Lists build widgets for the visible rows only.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Sparkline, Table, TableState,
    Wrap,
};
use serde_json::Value;

use crate::app::{App, Filter, Hit, Level, SURFACES};
use crate::settings::{self, Edit};

pub const ACCENT: Color = Color::Cyan;
/// Intercepted AI-site traffic, told apart from the agent proxy at a glance.
pub const INTERCEPT: Color = Color::Magenta;
pub const DIM: Color = Color::DarkGray;

pub fn surface_color(surface: &str) -> Color {
    match surface {
        "intercept" => INTERCEPT,
        "clipboard" => Color::Blue,
        _ => ACCENT,
    }
}

pub fn level_style(l: Level) -> Style {
    match l {
        Level::Info => Style::default().fg(ACCENT),
        Level::Warn => Style::default().fg(Color::Yellow),
        Level::Error => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

pub fn dim() -> Style {
    Style::default().fg(DIM)
}

pub fn bold() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

pub fn hit(app: &App, r: Rect, h: Hit) {
    app.hits.borrow_mut().push((r, h));
}

/// First visible row so that `sel` stays inside a window of `height` rows.
pub fn window_start(sel: usize, height: usize) -> usize {
    if height == 0 || sel < height {
        0
    } else {
        sel + 1 - height
    }
}

pub fn block(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .title(format!(" {title} "))
}

pub fn s<'a>(v: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(v, |acc, k| &acc[*k])
}

pub fn text(v: &Value) -> String {
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

fn uptime(s: u64) -> String {
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m {}s", s / 60, s % 60),
        _ => format!("{}h {}m", s / 3600, (s / 60) % 60),
    }
}

fn clock(ts_ms: u64) -> String {
    let secs = (ts_ms / 1000) % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// A one-line `/` filter bar on top of `area` when the filter is in use;
/// returns the rest.
fn filter_bar(f: &mut Frame, area: Rect, filter: &Filter, what: &str) -> Rect {
    if !filter.active() && !filter.editing {
        return area;
    }
    let [bar, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);
    let cursor = if filter.editing { "▏" } else { "" };
    let hint = if filter.editing {
        "  Enter keep · Esc clear"
    } else {
        "  / edit · Esc clear"
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!(" / {what}: "), Style::default().fg(ACCENT)),
            Span::styled(format!("{}{cursor}", filter.text), bold()),
            Span::styled(hint, dim()),
        ])),
        bar,
    );
    rest
}

// ── Dashboard ───────────────────────────────────────────────────────────

/// Problems worth a box of their own on the dashboard.
pub fn warnings(st: &Value) -> Vec<(String, Level)> {
    let mut w = Vec::new();
    let it = &st["intercept"];
    if it.is_object() {
        let enabled = it["enabled"].as_bool() == Some(true);
        let listening = it["listening"].as_str();
        let pac = it["pac"].as_str();
        match (pac, listening) {
            (Some(_), None) => w.push((
                "the system proxy sends AI sites to parda, but nothing listens — they fail to \
                 load (parda intercept on, or parda intercept off)"
                    .to_string(),
                Level::Error,
            )),
            (Some(pac), Some(addr)) if it["pac_matches"].as_bool() == Some(false) => w.push((
                format!(
                    "the system proxy points at {pac} but the listener is on {addr} — run parda \
                     intercept on"
                ),
                Level::Error,
            )),
            _ => {}
        }
        if enabled && it["ca"].as_bool() == Some(false) {
            w.push((
                "AI-site filtering is on but there is no CA — run parda ca create, then parda \
                 ca install"
                    .into(),
                Level::Error,
            ));
        } else if enabled && listening.is_none() {
            match it["error"].as_str() {
                Some(e) => w.push((format!("intercept not listening — {e}"), Level::Error)),
                None => w.push((crate::app::NO_PROXY.to_string(), Level::Warn)),
            }
        }
    }
    match (st["model"].as_str(), st["model_error"].as_str()) {
        (None, Some(e)) => w.push((
            format!("name model unavailable — {e} (format rules still run)"),
            Level::Warn,
        )),
        (None, None) if st["model_configured"].as_str().is_some_and(|m| m != "none") => w.push((
            "name model not loaded — only format rules run".into(),
            Level::Warn,
        )),
        _ => {}
    }
    w
}

/// The dashboard's intercept line, from the daemon status; `None` for a
/// daemon too old to report it.
fn intercept_line(it: &Value) -> Option<Line<'static>> {
    if !it.is_object() {
        return None;
    }
    let label = Span::raw("intercept  ");
    let pac_set = it["pac"].is_string();
    let warn = Style::default().fg(Color::Yellow);
    let bad = Style::default().fg(Color::Red).add_modifier(Modifier::BOLD);
    let (msg, style) = match (it["listening"].as_str(), it["error"].as_str()) {
        (Some(addr), _) if pac_set && it["pac_matches"].as_bool() == Some(false) => (
            format!(
                "on · {addr} · system proxy points at {} — AI sites fail to load; run parda \
                 intercept on",
                it["pac"].as_str().unwrap_or_default()
            ),
            bad,
        ),
        (Some(addr), _) if pac_set => (
            format!("on · {addr} · system proxy set"),
            Style::default().fg(INTERCEPT),
        ),
        (Some(addr), _) => (
            format!("on · {addr} · NO system proxy (parda intercept on)"),
            warn,
        ),
        (None, Some(e)) => (format!("NOT LISTENING — {e}"), bad),
        (None, None) if it["enabled"].as_bool() == Some(true) => {
            (crate::app::NO_PROXY.to_string(), bad)
        }
        (None, None) if pac_set => (
            "OFF but the system proxy still points here — AI sites fail to load; \
             run parda intercept off"
                .to_string(),
            bad,
        ),
        (None, None) => ("off".to_string(), dim()),
    };
    Some(Line::from(vec![label, Span::styled(msg, style)]))
}

fn status_lines(app: &App) -> Vec<Line<'static>> {
    let null = Value::Null;
    let st = app.status.as_ref().unwrap_or(&null);
    let stats = &st["stats"];
    let act = &st["activity"];
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
                .filter(|e| e.surface == "proxy" || e.surface == "intercept")
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
            Span::styled("protection ", dim()),
            Span::styled(
                "ON",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled("protection ", dim()),
            Span::styled(
                "OFF — text is sent unfiltered (press p)",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ])
    };
    let mut lines = vec![
        protection,
        Line::from(vec![
            Span::styled("filtered   ", dim()),
            Span::styled(
                format!("{total} values"),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" in {} redactions", text(&stats["redactions"]))),
        ]),
        Line::from(format!(
            "daemon     {}",
            if app.connected() {
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
    ];
    if let Some(l) = intercept_line(&st["intercept"]) {
        lines.push(l);
    }
    lines.extend([
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
    ]);
    lines
}

/// Per-minute values for the last `n` minutes (oldest first).
fn series(app: &App, n: usize, f: impl Fn(&crate::app::Bucket) -> u64) -> Vec<u64> {
    let mut out = vec![0u64; n];
    if n == 0 {
        return out;
    }
    let last = app.buckets.back().map_or(0, |b| b.minute);
    let end = last.max(app.now_ms / 60_000);
    let start = (end + 1).saturating_sub(n as u64);
    for b in &app.buckets {
        if b.minute >= start && b.minute <= end {
            out[(b.minute - start) as usize] = f(b);
        }
    }
    out
}

fn p95(xs: &[u64]) -> u64 {
    percentile(xs.to_vec(), 0.95).unwrap_or(0)
}

fn activity(app: &App, f: &mut Frame, area: Rect) {
    let b = block("Activity this session (per minute)");
    let inner = b.inner(area);
    f.render_widget(b, area);
    if inner.height == 0 || inner.width < 20 {
        return;
    }
    let rows = inner.height as usize;
    let per = (rows / 2).max(1) as u16;
    let label_w = 15u16;
    let value_w = 22u16.min(inner.width / 3);
    let spark_w = inner.width.saturating_sub(label_w + value_w + 1);
    let all_lat: Vec<u64> = app
        .buckets
        .iter()
        .flat_map(|b| b.latencies.iter().copied())
        .collect();
    let this_min = series(app, 1, |b| b.values)[0];
    let values = series(app, spark_w as usize, |b| b.values);
    let lat = series(app, spark_w as usize, |b| p95(&b.latencies));
    let lines = [
        (
            "values/min",
            values,
            format!("{this_min} this minute"),
            Style::default().fg(ACCENT),
        ),
        (
            "latency p95",
            lat,
            match (percentile(all_lat.clone(), 0.5), percentile(all_lat, 0.95)) {
                (Some(a), Some(b)) => format!("p50 {a} · p95 {b} ms"),
                _ => "no requests yet".into(),
            },
            Style::default().fg(INTERCEPT),
        ),
    ];
    for (i, (label, data, value, style)) in lines.into_iter().enumerate() {
        let y = inner.y + i as u16 * per;
        if y >= inner.bottom() {
            break;
        }
        let h = per.min(inner.bottom() - y);
        f.render_widget(
            Paragraph::new(Span::styled(label, dim())),
            Rect::new(inner.x, y, label_w, 1),
        );
        f.render_widget(
            Sparkline::default()
                .data(&data)
                .bar_set(symbols::bar::NINE_LEVELS)
                .style(style),
            Rect::new(inner.x + label_w, y, spark_w, h),
        );
        f.render_widget(
            Paragraph::new(Span::raw(value)),
            Rect::new(inner.x + label_w + spark_w + 1, y, value_w, 1),
        );
    }
}

fn kinds_table(app: &App, f: &mut Frame, area: Rect) {
    let null = Value::Null;
    let st = app.status.as_ref().unwrap_or(&null);
    let rows_all = kv_rows(&st["stats"]["entities"]);
    let total: u64 = rows_all.iter().map(|(_, n)| n).sum();
    let height = area.height.saturating_sub(3) as usize;
    let max = rows_all.first().map_or(1, |r| r.1.max(1));
    let bar_w = area.width.saturating_sub(2 + 16 + 8) as u64;
    let rows: Vec<Row> = rows_all
        .into_iter()
        .take(height)
        .map(|(k, n)| {
            let bar = "■".repeat(((n * bar_w).div_ceil(max)) as usize);
            Row::new(vec![
                Cell::from(k),
                Cell::from(n.to_string()),
                Cell::from(Span::styled(bar, Style::default().fg(ACCENT))),
            ])
        })
        .collect();
    let title = format!("Filtered by kind ({total})");
    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(7),
            Constraint::Min(1),
        ],
    )
    .header(Row::new(vec!["kind", "count", ""]).style(bold()))
    .block(block(&title));
    f.render_widget(table, area);
}

fn where_from(app: &App, f: &mut Frame, area: Rect) {
    let null = Value::Null;
    let st = app.status.as_ref().unwrap_or(&null);
    let mut rows: Vec<Row> = kv_rows(&st["stats"]["by_source"])
        .into_iter()
        .map(|(k, n)| Row::new(vec!["found by".to_string(), k, n.to_string()]))
        .collect();
    if let Some(surfaces) = st["activity"]["surfaces"].as_object() {
        for (name, s) in surfaces {
            if name == "daemon" {
                continue;
            }
            let warn = num(&s["warnings"]);
            let style = if warn > 0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(surface_color(name))
            };
            rows.push(
                Row::new(vec![
                    "surface".to_string(),
                    if warn > 0 {
                        format!("{name} ({} events, {warn} warn)", num(&s["events"]))
                    } else {
                        format!("{name} ({} events)", num(&s["events"]))
                    },
                    num(&s["redacted"]).to_string(),
                ])
                .style(style),
            );
        }
    }
    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Min(10),
            Constraint::Length(7),
        ],
    )
    .header(Row::new(vec!["", "source", "values"]).style(bold()))
    .block(block("Where from"));
    f.render_widget(table, area);
}

pub fn dashboard(app: &App, f: &mut Frame, area: Rect) {
    let null = Value::Null;
    let st = app.status.as_ref().unwrap_or(&null);
    let warns = warnings(st);
    let mut constraints = Vec::new();
    if !warns.is_empty() {
        constraints.push(Constraint::Length((warns.len() as u16 + 2).min(6)));
    }
    let activity_h = if area.height >= 36 { 6 } else { 4 };
    constraints.push(Constraint::Min(6));
    constraints.push(Constraint::Length(activity_h));
    let parts = Layout::vertical(constraints).split(area);
    let mut i = 0;
    if !warns.is_empty() {
        let lines: Vec<Line> = warns
            .iter()
            .map(|(t, l)| Line::from(Span::styled(format!("! {t}"), level_style(*l))))
            .collect();
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: true })
                .block(block("Warnings").border_style(Style::default().fg(Color::Red))),
            parts[0],
        );
        i = 1;
    }
    let main = parts[i];
    let status = Paragraph::new(status_lines(app))
        .block(block("Status"))
        .wrap(Wrap { trim: true });
    if area.width < 70 {
        // Narrow: status above the per-kind counters.
        let [a, b] = Layout::vertical([Constraint::Min(6), Constraint::Length(7)]).areas(main);
        f.render_widget(status, a);
        kinds_table(app, f, b);
    } else {
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(56), Constraint::Percentage(44)])
                .areas(main);
        f.render_widget(status, left);
        let [k, w] =
            Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(right);
        kinds_table(app, f, k);
        where_from(app, f, w);
    }
    activity(app, f, parts[i + 1]);
}

// ── Live ────────────────────────────────────────────────────────────────

/// (target, status) from an event summary such as
/// `chatgpt.com → 200 · 2 redacted` or `anthropic /v1/messages → 200 · …`.
pub fn summary_parts(summary: &str) -> (Option<&str>, Option<&str>) {
    match summary.split_once(" → ") {
        Some((target, rest)) => (
            Some(target.trim()),
            rest.split([' ', '·']).find(|t| !t.is_empty()),
        ),
        None => (None, None),
    }
}

/// Why a request was refused or failed, from its summary.
pub fn refusal(summary: &str) -> Option<String> {
    if let Some(i) = summary.find("refused, not sent (") {
        let r = &summary[i + "refused, not sent (".len()..];
        let end = r.rfind(')').unwrap_or(r.len());
        return Some(r[..end].to_string());
    }
    if let Some(i) = summary.find("blocked by policy") {
        return Some(summary[i..].to_string());
    }
    if let Some((_, rest)) = summary.split_once(" → ")
        && let (Some(open), Some(close)) = (rest.find('('), rest.rfind(')'))
        && open < close
        && !rest.contains("redacted")
    {
        return Some(rest[open + 1..close].to_string());
    }
    None
}

fn live_title(app: &App, hidden: usize) -> String {
    let mut t = format!("Live ({} events", app.live_len());
    if let Some(s) = SURFACES[app.live.surface] {
        t.push_str(&format!(" · surface {s}"));
    }
    if let Some(k) = &app.live.kind {
        t.push_str(&format!(" · kind {k}"));
    }
    if app.live.paused.is_some() {
        t.push_str(&format!(" · PAUSED, {} new", app.live_held()));
    }
    if hidden > 0 {
        t.push_str(&format!(" · {hidden} newer hidden, End to jump"));
    }
    t.push_str(" · values never shown)");
    t
}

fn event_detail(app: &App, f: &mut Frame, area: Rect) {
    let Some(e) = app.live_selected() else {
        f.render_widget(
            Paragraph::new("no event selected").block(block("Event")),
            area,
        );
        return;
    };
    let (target, status) = summary_parts(&e.summary);
    let kinds = if e.counts.is_empty() {
        "-".to_string()
    } else {
        e.counts
            .iter()
            .map(|(k, n)| format!("{k} {n}"))
            .collect::<Vec<_>>()
            .join(" · ")
    };
    let row =
        |k: &str, v: String| Line::from(vec![Span::styled(format!("{k:<9}"), dim()), Span::raw(v)]);
    let mut lines = vec![
        row("time", clock(e.ts_ms)),
        Line::from(vec![
            Span::styled(format!("{:<9}", "surface"), dim()),
            Span::styled(
                e.surface.clone(),
                Style::default().fg(surface_color(&e.surface)),
            ),
        ]),
    ];
    if let Some(t) = target {
        lines.push(row("target", t.to_string()));
    }
    if let Some(s) = status {
        lines.push(row("status", s.to_string()));
    }
    lines.push(row("kinds", kinds));
    lines.push(row(
        "latency",
        e.latency_ms
            .map_or("-".into(), |m| format!("{m} ms added by parda")),
    ));
    if e.level == "warn" {
        lines.push(Line::from(vec![
            Span::styled(format!("{:<9}", "level"), dim()),
            Span::styled("warning", Style::default().fg(Color::Yellow)),
        ]));
    }
    if let Some(r) = refusal(&e.summary) {
        lines.push(Line::from(vec![
            Span::styled(format!("{:<9}", "reason"), dim()),
            Span::styled(r, Style::default().fg(Color::Red)),
        ]));
    }
    lines.push(row("summary", e.summary.clone()));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(block("Event (kinds and counts only)")),
        area,
    );
}

pub fn live(app: &App, f: &mut Frame, area: Rect) {
    let area = filter_bar(f, area, &app.live.filter, "filter events");
    let (list_area, detail_area) = if app.live.detail {
        if area.width >= 110 {
            let [a, b] =
                Layout::horizontal([Constraint::Min(40), Constraint::Length(46)]).areas(area);
            (a, Some(b))
        } else {
            let [a, b] = Layout::vertical([Constraint::Min(4), Constraint::Length(10)]).areas(area);
            (a, Some(b))
        }
    } else {
        (area, None)
    };
    let h = list_area.height.saturating_sub(2) as usize;
    app.page.set(h.max(1));
    let n = app.live_len();
    let cursor = app.live.cursor.min(n.saturating_sub(1));
    let hidden = cursor.saturating_sub(h.saturating_sub(1));
    let end = n - hidden.min(n);
    let start = end.saturating_sub(h);
    let mark = app.live.cursor > 0 || app.live.detail || app.live.paused.is_some();
    let sel_idx = n.saturating_sub(1).saturating_sub(cursor);
    let mut items = Vec::with_capacity(end - start);
    for (row, (idx, (_, e))) in app
        .live_rows()
        .enumerate()
        .skip(start)
        .take(end - start)
        .enumerate()
    {
        hit(
            app,
            Rect::new(
                list_area.x + 1,
                list_area.y + 1 + row as u16,
                list_area.width.saturating_sub(2),
                1,
            ),
            Hit::Row(n - 1 - idx),
        );
        let kinds: Vec<String> = e.counts.iter().map(|(k, n)| format!("{k}×{n}")).collect();
        let ms = e.latency_ms.map(|m| format!(" {m}ms")).unwrap_or_default();
        let style = if e.level == "warn" {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };
        items.push(ListItem::new(Line::from(vec![
            Span::styled(format!("{} ", clock(e.ts_ms)), dim()),
            Span::styled(
                format!("{:<9} ", e.surface),
                Style::default().fg(surface_color(&e.surface)),
            ),
            Span::styled(e.summary.clone(), style),
            Span::raw(format!("{ms} {}", kinds.join(" "))),
        ])));
    }
    let empty = items.is_empty();
    let mut state = ListState::default();
    if mark && !empty {
        state.select(Some(sel_idx - start));
    }
    let list = if empty {
        List::new(vec![ListItem::new(Span::styled(
            if app.events.is_empty() {
                "no events yet — they appear here as agents, AI sites and the clipboard are filtered"
            } else {
                "no events match the filters (c clears them)"
            },
            dim(),
        ))])
    } else {
        List::new(items)
    };
    f.render_stateful_widget(
        list.block(block(&live_title(app, hidden)))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        list_area,
        &mut state,
    );
    if let Some(d) = detail_area {
        event_detail(app, f, d);
    }
}

// ── Inspector ───────────────────────────────────────────────────────────

pub fn inspector(app: &App, f: &mut Frame, area: Rect) {
    let ins = &app.inspector;
    let replace_h = if area.height >= 20 { 8 } else { 5 };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(3),
            Constraint::Length(replace_h),
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
        (Some(e), _) => ("Error".to_string(), e.clone()),
        (None, false) => (
            "Sent to the AI".to_string(),
            ins.redacted.clone().unwrap_or_default(),
        ),
        (None, true) => (
            "Restored (what you would see back)".to_string(),
            ins.restored.clone().unwrap_or_default(),
        ),
    };
    let out_title = if ins.busy {
        format!("{out_title} {} redacting…", app.theme.spinner(app.spin))
    } else {
        out_title
    };
    f.render_widget(
        Paragraph::new(out)
            .wrap(Wrap { trim: false })
            .block(block(&out_title)),
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
    .header(Row::new(vec!["kind", "replaced with", "found by"]).style(bold()))
    .block(block("Replacements"));
    f.render_widget(table, rows[2]);
}

// ── Rules ───────────────────────────────────────────────────────────────

fn rule_detail(app: &App, i: usize) -> Vec<Line<'static>> {
    let np = app.rules.person.len();
    let nt = app.rules.term.len();
    if let Some(p) = app.rules.person.get(i) {
        vec![
            Line::from(format!("person   {}", p.name)),
            Line::from(format!(
                "also     {} alias(es) · {} email(s) · {} handle(s) — name variants are added \
                 automatically",
                p.aliases.len(),
                p.emails.len(),
                p.handles.len()
            )),
            Line::from(Span::styled(
                "always masked; edit the details with `parda rules edit`",
                dim(),
            )),
        ]
    } else if let Some(t) = i.checked_sub(np).and_then(|j| app.rules.term.get(j)) {
        vec![
            Line::from(format!("term     {}", t.text)),
            Line::from(format!("kind     {}", t.kind)),
            Line::from(Span::styled("always masked as this kind", dim())),
        ]
    } else if let Some(a) = i.checked_sub(np + nt).and_then(|j| app.rules.allow.get(j)) {
        vec![
            Line::from(format!("allow    {a}")),
            Line::from(Span::styled(
                "never masked, even when a rule matches",
                dim(),
            )),
        ]
    } else {
        vec![]
    }
}

pub fn rules(app: &App, f: &mut Frame, area: Rect) {
    let area = filter_bar(f, area, &app.rules_filter, "filter rules");
    let all = app.rule_rows();
    let view = app.rules_view();
    let title = if app.rules_filter.active() {
        format!(
            "Rules ({} of {}) · always masked · allow-list never masked",
            view.len(),
            all.len()
        )
    } else {
        "Rules (people & terms always masked · allow-list never masked)".to_string()
    };
    let (list_area, detail_area) = if app.rules_detail && !view.is_empty() {
        let [a, b] = Layout::vertical([Constraint::Min(3), Constraint::Length(5)]).areas(area);
        (a, Some(b))
    } else {
        (area, None)
    };
    if view.is_empty() {
        let msg = if all.is_empty() {
            "no rules yet — press a to add a person to always mask"
        } else {
            "no rules match the filter (Esc clears it)"
        };
        f.render_widget(
            List::new(vec![ListItem::new(msg)]).block(block(&title)),
            list_area,
        );
        return;
    }
    let height = list_area.height.saturating_sub(2) as usize;
    app.page.set(height.max(1));
    let sel = app.rules_sel.min(view.len() - 1);
    let start = window_start(sel, height);
    let items: Vec<ListItem> = view
        .iter()
        .enumerate()
        .skip(start)
        .take(height)
        .map(|(vi, ri)| {
            let (section, t) = &all[*ri];
            let color = match *section {
                "person" => Color::Green,
                "term" => Color::Magenta,
                _ => Color::Blue,
            };
            hit(
                app,
                Rect::new(
                    list_area.x + 1,
                    list_area.y + 1 + (vi - start) as u16,
                    list_area.width.saturating_sub(2),
                    1,
                ),
                Hit::Row(vi),
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
        .block(block(&title))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(list, list_area, &mut state);
    if let Some(d) = detail_area {
        f.render_widget(
            Paragraph::new(rule_detail(app, view[sel]))
                .wrap(Wrap { trim: true })
                .block(block("Rule")),
            d,
        );
    }
}

// ── Vault ───────────────────────────────────────────────────────────────

pub fn vault(app: &App, f: &mut Frame, area: Rect) {
    let area = filter_bar(f, area, &app.vault_filter, "search scope / kind");
    let view = app.vault_view();
    let total: u64 = app.vault.iter().filter_map(|r| r["count"].as_u64()).sum();
    let title = if app.vault_filter.active() {
        format!(
            "Vault — {total} mappings (encrypted at rest) · {} of {} rows",
            view.len(),
            app.vault.len()
        )
    } else {
        format!("Vault — {total} mappings (encrypted at rest)")
    };
    let (list_area, detail_area) = if app.vault_detail && !view.is_empty() {
        let [a, b] = Layout::vertical([Constraint::Min(4), Constraint::Length(6)]).areas(area);
        (a, Some(b))
    } else {
        (area, None)
    };
    let height = list_area.height.saturating_sub(3) as usize;
    app.page.set(height.max(1));
    let sel = app.vault_sel.min(view.len().saturating_sub(1));
    let start = window_start(sel, height);
    let rows: Vec<Row> = view
        .iter()
        .enumerate()
        .skip(start)
        .take(height)
        .map(|(vi, i)| {
            hit(
                app,
                Rect::new(
                    list_area.x + 1,
                    list_area.y + 2 + (vi - start) as u16,
                    list_area.width.saturating_sub(2),
                    1,
                ),
                Hit::Row(vi),
            );
            let r = &app.vault[*i];
            Row::new(vec![text(&r["scope"]), text(&r["kind"]), text(&r["count"])])
        })
        .collect();
    let empty = rows.is_empty();
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(40),
            Constraint::Percentage(20),
        ],
    )
    .header(Row::new(vec!["scope", "kind", "mappings"]).style(bold()))
    .block(block(&title))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut state = TableState::default();
    if !empty {
        state.select(Some(sel - start));
    }
    f.render_stateful_widget(table, list_area, &mut state);
    if let (Some(d), Some(r)) = (detail_area, app.vault_selected()) {
        let scope = text(&r["scope"]);
        let (scope_total, kinds) = app
            .vault
            .iter()
            .filter(|x| x["scope"] == r["scope"])
            .fold((0u64, 0usize), |(t, k), x| (t + num(&x["count"]), k + 1));
        let lines = vec![
            Line::from(format!("scope    {scope}")),
            Line::from(format!(
                "kind     {} · {} mapping(s)",
                text(&r["kind"]),
                text(&r["count"])
            )),
            Line::from(format!(
                "in scope {scope_total} mapping(s) across {kinds} kind(s)"
            )),
            Line::from(Span::styled(
                "x forgets this whole scope · w wipes everything (both ask first)",
                dim(),
            )),
        ];
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: true })
                .block(block("Mappings")),
            d,
        );
    }
}

// ── Settings ────────────────────────────────────────────────────────────

pub fn settings_tab(app: &App, f: &mut Frame, area: Rect) {
    let null = Value::Null;
    let st = app.status.as_ref().unwrap_or(&null);
    let url = st["proxy"]
        .as_str()
        .map(|a| format!("http://{a}"))
        .unwrap_or_else(|| "http://127.0.0.1:8787".into());
    let roomy = area.height >= 26;
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(if roomy { 5 } else { 1 }),
            Constraint::Min(4),
            Constraint::Length(4),
        ])
        .split(area);
    if roomy {
        let connect = vec![
            Line::from(format!(
                "Agents    export ANTHROPIC_BASE_URL={url} OPENAI_BASE_URL={url}/v1"
            )),
            Line::from(format!(
                "Chat apps copy, then press the paste-safe hotkey ({}) instead of paste",
                text(&st["hotkey"]),
            )),
            Line::from(
                "AI sites  parda ca create · parda ca install · parda intercept on · undo: parda intercept off",
            ),
        ];
        f.render_widget(
            Paragraph::new(connect)
                .block(block("Connect"))
                .wrap(Wrap { trim: false }),
            parts[0],
        );
    } else {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" agents ", dim()),
                Span::raw(format!("ANTHROPIC_BASE_URL={url}")),
                Span::styled("  AI sites ", dim()),
                Span::raw("parda intercept on"),
            ])),
            parts[0],
        );
    }

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
    app.page.set(height.max(1));
    let sel = app.settings_sel.min(rows.len() - 1);
    let start = window_start(sel, height);
    let label_w = (list_area.width.saturating_sub(2).saturating_sub(12 + 26) as usize).max(8);
    let editor = app.editor.as_ref();
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
                (Some(false), _) => dim(),
                (None, _) => Style::default().fg(ACCENT),
            };
            let editing = i == sel && editor.is_some();
            let value = if editing {
                format!("[{}▏]", editor.map(|e| e.buf.as_str()).unwrap_or_default())
            } else {
                match (r.on, settings::edit_kind(&all[i])) {
                    (Some(true), _) => format!("● {}", r.value),
                    (Some(false), _) => format!("○ {}", r.value),
                    (None, Edit::Number | Edit::Text) => format!("✎ {}", r.value),
                    (None, _) => format!("◆ {}", r.value),
                }
            };
            let mut label: String = r.label.chars().take(label_w).collect();
            if r.restart {
                label.push_str(" ↻");
            }
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<11} ", r.group), dim()),
                Span::raw(format!("{label:<width$} ", width = label_w + 2)),
                Span::styled(
                    value,
                    if editing {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        value_style
                    },
                ),
            ]))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(sel - start));
    let title = format!(
        "Settings ({}/{}) · ↻ = applies after a daemon restart · {}",
        sel + 1,
        rows.len(),
        text(s(st, &["paths", "config"]))
    );
    f.render_stateful_widget(
        List::new(items)
            .block(block(&title))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        list_area,
        &mut state,
    );
    let r = &rows[sel];
    let help = match editor.and_then(|e| e.error.as_deref()) {
        Some(e) => Paragraph::new(Line::from(Span::styled(
            format!("✗ {e}"),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ))),
        None if editor.is_some() => Paragraph::new(vec![
            Line::from(r.help),
            Line::from(Span::styled(
                "Enter saves · Esc cancels · Ctrl-U clears",
                dim(),
            )),
        ]),
        None => Paragraph::new(r.help),
    };
    f.render_widget(
        help.wrap(Wrap { trim: true }).block(block(&r.label)),
        parts[2],
    );
}
