//! Screen chrome: status bar, tab strip, context footer, toasts, overlays
//! (help, palette, prompt, confirm) and the offline screen.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap};
use serde_json::Value;

use crate::app::{App, Confirm, Conn, Hit, Level, Prompt, Tab};
use crate::palette;
use crate::settings::{self, Edit};
use crate::tabs::{self, ACCENT, INTERCEPT, block, bold, dim, hit, level_style};

pub fn draw(app: &App, f: &mut Frame) {
    app.hits.borrow_mut().clear();
    let area = f.area();
    let [bar, strip, body, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(area);
    status_bar(app, f, bar);
    tab_strip(app, f, strip);
    if app.offline() {
        offline(app, f, body);
    } else {
        match app.tab {
            Tab::Dashboard => tabs::dashboard(app, f, body),
            Tab::Live => tabs::live(app, f, body),
            Tab::Inspector => tabs::inspector(app, f, body),
            Tab::Rules => tabs::rules(app, f, body),
            Tab::Vault => tabs::vault(app, f, body),
            Tab::Settings => tabs::settings_tab(app, f, body),
        }
    }
    footer(app, f, foot);
    toasts(app, f, body);
    if let Some((kind, buf)) = &app.prompt {
        let title = match kind {
            Prompt::AddPerson => " Person to always mask (Enter adds · Esc cancels) ",
            Prompt::AllowTerm => " Term never to mask (Enter adds · Esc cancels) ",
        };
        let r = centered(area, 64, 3);
        f.render_widget(Clear, r);
        f.render_widget(
            Paragraph::new(format!("{buf}▏")).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(ACCENT))
                    .title(title),
            ),
            r,
        );
    }
    if let Some(c) = &app.confirm {
        confirm(app, c, f, area);
    }
    if app.palette.is_some() {
        palette_overlay(app, f, area);
    }
    if app.help {
        help(app, f, area);
    }
    app.theme.finish(f.buffer_mut());
}

pub fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

// ── status bar and tabs ─────────────────────────────────────────────────

fn status_bar(app: &App, f: &mut Frame, area: Rect) {
    let null = Value::Null;
    let st = app.status.as_ref().unwrap_or(&null);
    let sep = Span::raw("  ");
    let mut segs: Vec<Vec<Span<'static>>> = vec![vec![Span::styled(
        " parda ",
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    )]];
    segs.push(vec![match &app.conn {
        Conn::Online => Span::styled("● online", Style::default().fg(Color::Green)),
        Conn::Connecting => Span::styled("◌ connecting…", dim()),
        Conn::Offline(_) => Span::styled(
            "○ daemon offline",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    }]);
    let compact = area.width < 120;
    // ":8788" instead of "127.0.0.1:8788" on narrow screens.
    let addr = |a: &str| -> String {
        match a.strip_prefix("127.0.0.1") {
            Some(port) if compact => port.to_string(),
            _ => a.to_string(),
        }
    };
    let badge = if app.offline() {
        Span::styled(
            " □ NOT FILTERING ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        )
    } else if app.protection_on() {
        Span::styled(
            " ■ PROTECTION ON ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " □ PROTECTION OFF ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        )
    };
    let badge_seg = segs.len();
    segs.push(vec![badge]);
    if app.connected() {
        let it = &st["intercept"];
        if it.is_object() {
            let (t, style) = match (it["listening"].as_str(), it["error"].as_str()) {
                (Some(a), _)
                    if it["pac"].is_string() && it["pac_matches"].as_bool() != Some(false) =>
                {
                    (
                        format!("intercept {}", addr(a)),
                        Style::default().fg(INTERCEPT),
                    )
                }
                (Some(a), _) => (
                    format!("intercept {} (no system proxy)", addr(a)),
                    Style::default().fg(Color::Yellow),
                ),
                (None, _) if it["enabled"].as_bool() == Some(true) => (
                    "intercept NOT LISTENING".to_string(),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                (None, _) if it["pac"].is_string() => (
                    "intercept off, system proxy set".to_string(),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                _ => ("intercept off".to_string(), dim()),
            };
            segs.push(vec![Span::styled(t, style)]);
        }
        segs.push(vec![match st["proxy"].as_str() {
            Some(a) => Span::styled(format!("proxy {}", addr(a)), Style::default().fg(ACCENT)),
            None => Span::styled("proxy off", dim()),
        }]);
        segs.push(vec![
            match (st["model"].as_str(), st["model_error"].as_str()) {
                (Some(m), _) => Span::raw(format!("model {m}")),
                (None, Some(_)) => {
                    Span::styled("model NOT LOADED", Style::default().fg(Color::Yellow))
                }
                _ => Span::styled("rules only", dim()),
            },
        ]);
        if let Some(m) = st["mode"].as_str() {
            segs.push(vec![Span::styled(m.to_string(), dim())]);
        }
    }
    let mut spans: Vec<Span> = Vec::new();
    let mut x = area.x;
    for (i, seg) in segs.into_iter().enumerate() {
        let w: u16 = seg.iter().map(|s| s.width() as u16).sum();
        let gap = if spans.is_empty() { 0 } else { 2 };
        if x + gap + w > area.right() && i > badge_seg {
            // Skip what does not fit; a shorter part later may still fit.
            continue;
        }
        if gap > 0 {
            spans.push(sep.clone());
            x += gap;
        }
        if i == badge_seg {
            hit(
                app,
                Rect::new(x, area.y, w.min(area.right().saturating_sub(x)), 1),
                Hit::Protection,
            );
        }
        x += w;
        spans.extend(seg);
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn tab_strip(app: &App, f: &mut Frame, area: Rect) {
    let short = area.width < 72;
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| {
            Line::from(format!(
                "{} {}",
                i + 1,
                if short { t.short() } else { t.title() }
            ))
        })
        .collect();
    let mut x = area.x;
    for (t, title) in Tab::ALL.iter().zip(&titles) {
        let w = title.width() as u16 + 2;
        if x >= area.right() {
            break;
        }
        hit(
            app,
            Rect::new(x, area.y, w.min(area.right() - x), 1),
            Hit::Tab(*t),
        );
        x += w + 1;
    }
    let used = x.saturating_sub(area.x);
    f.render_widget(
        Tabs::new(titles)
            .select(app.tab.index())
            .divider("│")
            .style(dim())
            .highlight_style(
                Style::default()
                    .fg(ACCENT)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ),
        area,
    );
    let hint = ": commands  ? help ";
    if area.width >= used + hint.len() as u16 + 2 {
        f.render_widget(
            Paragraph::new(Span::styled(hint, dim())).right_aligned(),
            area,
        );
    }
}

// ── footer ──────────────────────────────────────────────────────────────

/// The keys that do something right now: (key, what it does).
pub fn footer_keys(app: &App) -> Vec<(&'static str, String)> {
    let k = |key: &'static str, what: &str| (key, what.to_string());
    if app.editor.is_some() {
        return vec![
            k("Enter", "save"),
            k("Esc", "cancel"),
            k("^U", "clear"),
            k("^C", "quit"),
        ];
    }
    if app.prompt.is_some() {
        return vec![k("Enter", "add"), k("Esc", "cancel")];
    }
    if app.palette.is_some() {
        return vec![
            k("type", "filter"),
            k("↑↓", "select"),
            k("Enter", "run"),
            k("Esc", "close"),
        ];
    }
    if app.confirm.is_some() {
        return vec![k("y", "yes"), k("any other key", "cancel")];
    }
    if app.help {
        return vec![k("Esc/?", "close help"), k("^C", "quit")];
    }
    let editing_filter = match app.tab {
        Tab::Live => app.live.filter.editing,
        Tab::Rules => app.rules_filter.editing,
        Tab::Vault => app.vault_filter.editing,
        _ => false,
    };
    if editing_filter {
        return vec![k("type", "filter"), k("Enter", "keep"), k("Esc", "clear")];
    }
    if app.offline() {
        return vec![
            k("s", "start the daemon"),
            k(":", "commands"),
            k("?", "help"),
            k("q", "quit"),
        ];
    }
    if app.tab == Tab::Inspector && app.inspector.editing {
        return vec![
            k("type", "text"),
            k("Enter", "redact"),
            k("Esc", "stop typing"),
        ];
    }
    let mut v = match app.tab {
        Tab::Dashboard => vec![
            k("1-6/Tab", "tabs"),
            k("p", "protection"),
            k("r", "refresh"),
        ],
        Tab::Live => vec![
            k("↑↓", "select"),
            k(
                "space",
                if app.live.paused.is_some() {
                    "resume"
                } else {
                    "pause"
                },
            ),
            k("f", "surface"),
            k("t", "kind"),
            k("/", "filter"),
            k("Enter", "detail"),
            k("Esc", "back"),
        ],
        Tab::Inspector => vec![k("i", "type"), k("r", "restore view"), k("Esc", "clear")],
        Tab::Rules => vec![
            k("↑↓", "select"),
            k("a", "add person"),
            k("w", "allow term"),
            k("d", "delete"),
            k("/", "filter"),
            k("Enter", "detail"),
        ],
        Tab::Vault => vec![
            k("↑↓", "select"),
            k("/", "search"),
            k("Enter", "detail"),
            k("x", "forget scope"),
            k("w", "wipe all"),
        ],
        Tab::Settings => {
            let s = settings::all();
            let kind = s
                .get(app.settings_sel)
                .map(settings::edit_kind)
                .unwrap_or(Edit::Toggle);
            let mut v = vec![k("↑↓", "select")];
            match kind {
                Edit::Toggle => v.push(k("Enter/Space", "toggle")),
                Edit::Cycle => {
                    v.push(k("Enter/→", "next"));
                    v.push(k("←", "back"));
                }
                Edit::Number => {
                    v.push(k("Enter", "edit"));
                    v.push(k("←→", "step"));
                }
                Edit::Text => v.push(k("Enter", "edit")),
            }
            v.extend([k("m", "mode"), k("s", "style")]);
            v
        }
    };
    if app.tab != Tab::Dashboard {
        v.push(k("p", "protection"));
    }
    v.extend([k(":", "commands"), k("?", "help"), k("q", "quit")]);
    v
}

fn footer(app: &App, f: &mut Frame, area: Rect) {
    let mut spans = Vec::new();
    let mut w = 1usize;
    spans.push(Span::raw(" "));
    for (key, what) in footer_keys(app) {
        let need = key.chars().count() + what.chars().count() + 3;
        if w + need > area.width as usize {
            break;
        }
        spans.push(Span::styled(
            key,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(format!(" {what}  "), dim()));
        w += need;
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

// ── toasts ──────────────────────────────────────────────────────────────

fn toasts(app: &App, f: &mut Frame, body: Rect) {
    if app.toasts.is_empty() || body.width < 20 || body.height < 4 {
        return;
    }
    let max_w = body.width.saturating_sub(2).min(76);
    let longest = app
        .toasts
        .iter()
        .map(|t| t.text.chars().count() as u16 + 4)
        .max()
        .unwrap_or(20);
    let w = longest.clamp(24, max_w);
    let inner = (w - 2) as usize;
    let lines_n: u16 = app
        .toasts
        .iter()
        .map(|t| (t.text.chars().count() + 2).div_ceil(inner).max(1) as u16)
        .sum();
    let h = (lines_n + 2).min(body.height / 2 + 1);
    let r = Rect::new(body.right() - w - 1, body.bottom() - h, w, h);
    let worst = app
        .toasts
        .iter()
        .map(|t| t.level)
        .max_by_key(|l| match l {
            Level::Info => 0,
            Level::Warn => 1,
            Level::Error => 2,
        })
        .unwrap_or(Level::Info);
    let lines: Vec<Line> = app
        .toasts
        .iter()
        .map(|t| {
            let mark = match t.level {
                Level::Info => "✓ ",
                Level::Warn => "! ",
                Level::Error => "✗ ",
            };
            Line::from(vec![
                Span::styled(mark, level_style(t.level)),
                Span::raw(t.text.clone()),
            ])
        })
        .collect();
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(level_style(worst)),
        ),
        r,
    );
}

// ── overlays ────────────────────────────────────────────────────────────

fn confirm(app: &App, c: &Confirm, f: &mut Frame, area: Rect) {
    let question = match c {
        Confirm::WipeVault => {
            let total: u64 = app.vault.iter().filter_map(|r| r["count"].as_u64()).sum();
            format!(
                "Wipe ALL {total} mapping(s)? Answers that mention them can no longer be restored."
            )
        }
        Confirm::ForgetScope(s) => {
            let n: u64 = app
                .vault
                .iter()
                .filter(|r| r["scope"].as_str() == Some(s))
                .filter_map(|r| r["count"].as_u64())
                .sum();
            format!("Forget every mapping in scope '{s}' ({n})? This cannot be undone.")
        }
        Confirm::Setting(s) => match &app.config {
            Some(cfg) => format!(
                "Turn on '{}'? Logs and events will contain personal data.",
                settings::row(s, cfg).label
            ),
            None => "Change this setting?".into(),
        },
    };
    let r = centered(area, 64, 6);
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(question),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "y",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" confirm   "),
                Span::styled("any other key", bold()),
                Span::raw(" cancels"),
            ]),
        ])
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red))
                .title(" confirm "),
        ),
        r,
    );
}

fn palette_overlay(app: &App, f: &mut Frame, area: Rect) {
    let Some(p) = &app.palette else { return };
    let entries = app.palette_entries();
    let matches = palette::filter(&entries, &p.query);
    let w = area.width.saturating_sub(4).min(68);
    let h = area
        .height
        .saturating_sub(2)
        .min(matches.len() as u16 + 4)
        .max(5);
    let r = Rect::new(area.x + (area.width - w) / 2, area.y + 1, w, h);
    f.render_widget(Clear, r);
    let b = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" commands ");
    let inner = b.inner(r);
    f.render_widget(b, r);
    if inner.height == 0 {
        return;
    }
    let [input, list_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("› ", Style::default().fg(ACCENT)),
            Span::styled(format!("{}▏", p.query), bold()),
            Span::styled(format!("  {} match(es)", matches.len()), dim()),
        ])),
        input,
    );
    let height = list_area.height as usize;
    let sel = p.sel.min(matches.len().saturating_sub(1));
    let start = tabs::window_start(sel, height);
    let label_w = list_area.width.saturating_sub(8) as usize;
    let items: Vec<ListItem> = matches
        .iter()
        .enumerate()
        .skip(start)
        .take(height)
        .map(|(i, e)| {
            hit(
                app,
                Rect::new(
                    list_area.x,
                    list_area.y + (i - start) as u16,
                    list_area.width,
                    1,
                ),
                Hit::Palette(i),
            );
            let label: String = e.label.chars().take(label_w).collect();
            ListItem::new(Line::from(vec![
                Span::raw(format!(" {label:<label_w$}")),
                Span::styled(format!(" {:>5}", e.key), dim()),
            ]))
        })
        .collect();
    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(sel - start));
    }
    let list = if items.is_empty() {
        List::new(vec![ListItem::new(Span::styled(
            " no matching action",
            dim(),
        ))])
    } else {
        List::new(items)
    };
    f.render_stateful_widget(
        list.highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        list_area,
        &mut state,
    );
}

fn help(_app: &App, f: &mut Frame, area: Rect) {
    let key = |k: &'static str, what: &'static str| {
        Line::from(vec![
            Span::styled(
                format!("{k:<16}"),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(what),
        ])
    };
    let lines = vec![
        key(
            "1-6 Tab S-Tab",
            "switch tabs (h/l or ←/→ outside Settings too)",
        ),
        key(": or Ctrl-K", "command palette — every action by name"),
        key("↑↓ jk g G PgUp/Dn", "move in lists (top / bottom / page)"),
        key("Enter", "open detail · run · edit a value"),
        key("Esc", "back out one level (detail, filter, overlay)"),
        key("/", "filter rows (Live, Rules, Vault) — Esc clears"),
        key("p", "protection on / off (or click the badge)"),
        key("Live", "space pause · f surface · t kind · c clear filters"),
        key("Inspector", "i type · Enter redact · r restored view"),
        key("Rules", "a add person · w allow term · d delete"),
        key("Vault", "x forget scope · w wipe all (both ask first)"),
        key(
            "Settings",
            "Enter/Space toggle · ←→ cycle · Enter edits numbers/text",
        ),
        key("q  Ctrl-C", "quit (Ctrl-C works everywhere)"),
        Line::from(""),
        Line::from(Span::styled(
            "Mouse: click tabs, rows, the badge; wheel scrolls. Shift/Option-drag selects text.",
            dim(),
        )),
        Line::from(Span::styled(
            "Values never appear in Live or messages: kinds and counts only.",
            dim(),
        )),
    ];
    let h = lines.len() as u16 + 2;
    let r = centered(area, 78, h);
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .title(" keys — Esc or ? closes "),
        ),
        r,
    );
}

// ── offline ─────────────────────────────────────────────────────────────

fn offline(app: &App, f: &mut Frame, area: Rect) {
    let reason = match &app.conn {
        Conn::Offline(r) => r.clone(),
        _ => String::new(),
    };
    let b = block("daemon offline").border_style(Style::default().fg(Color::Red));
    let inner = b.inner(area);
    f.render_widget(b, area);
    let red = Style::default().fg(Color::Red).add_modifier(Modifier::BOLD);
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  ○ ", red),
            Span::styled("parda's daemon is not running", red),
        ]),
        Line::from(Span::styled(
            "    Agents and AI sites routed through parda cannot connect until it runs.",
            dim(),
        )),
        Line::from(""),
    ];
    let start_y = inner.y + lines.len() as u16;
    match app.starting {
        Some(t) => lines.push(Line::from(vec![
            Span::styled(
                format!("  {} ", app.theme.spinner(app.spin)),
                Style::default().fg(ACCENT),
            ),
            Span::raw(format!(
                "starting… waiting for the daemon ({} s)",
                t.elapsed().as_secs()
            )),
        ])),
        None => lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                " s ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  start it in the background"),
        ])),
    }
    if start_y < inner.bottom() {
        hit(app, Rect::new(inner.x, start_y, inner.width, 1), Hit::Start);
    }
    if let Some(h) = &app.start_hint {
        lines.push(Line::from(Span::styled(format!("       {h}"), dim())));
    }
    lines.extend([
        Line::from(""),
        Line::from(Span::styled(
            "  Retrying the connection every second; the dashboard opens by itself.",
            dim(),
        )),
        Line::from(Span::styled(format!("  last answer: {reason}"), dim())),
        Line::from(""),
        Line::from(Span::styled(
            "  Or yourself: `parda daemon` in a terminal, or `parda service install`.",
            dim(),
        )),
    ]);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}
