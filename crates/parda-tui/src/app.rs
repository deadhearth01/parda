//! Application state, keys and mouse.
//!
//! The app does no I/O: requests leave as [`Cmd`]s ([`App::take_cmds`]) for
//! the worker, results come back as [`Msg`]s ([`App::on_msg`]). Anything
//! that changes what is on screen sets the dirty flag ([`App::take_dirty`]);
//! the loop draws only then.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, VecDeque};
use std::time::{Duration, Instant, SystemTime};

use parda_core::{Config, Mode, Style};
use parda_detect::{PersonBlock, RulesFile};
use parda_ipc::Event;
use ratatui::Frame;
use ratatui::crossterm::event::{
    Event as TermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use ratatui::layout::{Position, Rect};
use serde_json::Value;

use crate::palette::{self, Action, Entry, Palette};
use crate::settings::{self, Edit, Setting};
use crate::theme::Theme;
use crate::worker::{Cmd, Down, Msg, Role};
use crate::{Backend, ui};

/// Events kept for the Live tab (oldest dropped first).
pub const MAX_EVENTS: usize = 500;
/// Minutes of history behind the dashboard sparklines.
const MINUTES: u64 = 240;
const TOAST_INFO: Duration = Duration::from_secs(4);
const TOAST_WARN: Duration = Duration::from_secs(8);
const SPIN: Duration = Duration::from_millis(120);
/// No status answer for this long: the daemon counts as unresponsive.
const WATCHDOG: Duration = Duration::from_secs(3);
/// Offline keys are ignored this long after going offline closed an input.
const INERT: Duration = Duration::from_millis(1500);
/// Longest paste taken (characters).
const MAX_PASTE: usize = 256 * 1024;
/// Give up waiting for a started daemon after this long.
const START_WAIT: Duration = Duration::from_secs(15);
/// Surfaces the Live filter cycles through (None = all).
pub const SURFACES: [Option<&str>; 4] = [None, Some("proxy"), Some("intercept"), Some("clipboard")];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Live,
    Inspector,
    Rules,
    Vault,
    Settings,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Dashboard,
        Tab::Live,
        Tab::Inspector,
        Tab::Rules,
        Tab::Vault,
        Tab::Settings,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Live => "Live",
            Tab::Inspector => "Inspector",
            Tab::Rules => "Rules",
            Tab::Vault => "Vault",
            Tab::Settings => "Settings",
        }
    }

    /// For narrow terminals.
    pub fn short(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dash",
            Tab::Live => "Live",
            Tab::Inspector => "Insp",
            Tab::Rules => "Rules",
            Tab::Vault => "Vault",
            Tab::Settings => "Set",
        }
    }

    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

/// A clickable screen region, recorded while drawing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    Tab(Tab),
    /// The protection ON/OFF badge in the status bar.
    Protection,
    /// Row `n` of the current tab's list (for Live: rows from the newest).
    Row(usize),
    /// The inspector's input box.
    Input,
    /// Entry `n` of the palette's filtered list.
    Palette(usize),
    /// The offline screen's start button.
    Start,
}

/// An action waiting for `y`.
#[derive(Debug, Clone, PartialEq)]
pub enum Confirm {
    WipeVault,
    ForgetScope(String),
    Setting(Setting),
}

/// What a line-input prompt is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompt {
    AddPerson,
    AllowTerm,
}

/// A `/` filter over a list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    pub text: String,
    pub editing: bool,
}

impl Filter {
    fn needle(&self) -> String {
        self.text.to_lowercase()
    }
    pub fn active(&self) -> bool {
        !self.text.is_empty()
    }
}

fn hay_matches(needle: &str, hay: &str) -> bool {
    needle.is_empty() || hay.to_lowercase().contains(needle)
}

#[derive(Default)]
pub struct Inspector {
    pub input: String,
    pub editing: bool,
    pub redacted: Option<String>,
    pub replaced: Vec<Value>,
    pub restored: Option<String>,
    pub show_restore: bool,
    pub error: Option<String>,
    /// A redaction is running in the worker.
    pub busy: bool,
}

/// The daemon connection as the UI knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conn {
    /// No answer yet (first second after start).
    Connecting,
    Online,
    /// Unusable, and why (only `NotRunning` offers the start key).
    Offline(Down),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub text: String,
    pub level: Level,
    until: Instant,
}

/// The Live tab's view of the event buffer.
#[derive(Debug, Default)]
pub struct LiveView {
    /// Paused: only events before this sequence number are shown.
    pub paused: Option<u64>,
    /// Index into [`SURFACES`].
    pub surface: usize,
    pub kind: Option<String>,
    pub filter: Filter,
    /// Selected row, counted from the newest shown event (0 = newest; the
    /// view follows new events while it is 0).
    pub cursor: usize,
    pub detail: bool,
    /// Sequence numbers of the matching events, oldest first.
    view: VecDeque<u64>,
}

/// Session history for one minute, for the sparklines.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Bucket {
    pub minute: u64,
    /// Values replaced (sum of event counts).
    pub values: u64,
    /// Proxy / intercept latencies (ms).
    pub latencies: Vec<u64>,
}

/// The Settings tab's inline editor.
#[derive(Debug, Clone, PartialEq)]
pub struct Editor {
    pub setting: Setting,
    pub buf: String,
    pub error: Option<String>,
}

pub struct App {
    pub tab: Tab,
    quit: bool,
    pub help: bool,
    pub theme: Theme,
    pub conn: Conn,
    pub status: Option<Value>,
    /// The offline screen's start key was pressed at this time.
    pub starting: Option<Instant>,
    /// What the start key does (from the CLI).
    pub start_hint: Option<String>,
    pub events: VecDeque<Event>,
    /// Sequence number of `events[0]`.
    first_seq: u64,
    pub live: LiveView,
    pub buckets: VecDeque<Bucket>,
    pub inspector: Inspector,
    pub rules: RulesFile,
    rules_toml: String,
    pub rules_sel: usize,
    pub rules_filter: Filter,
    pub rules_detail: bool,
    rules_view: Vec<usize>,
    pub vault: Vec<Value>,
    pub vault_sel: usize,
    pub vault_filter: Filter,
    pub vault_detail: bool,
    vault_view: Vec<usize>,
    pub prompt: Option<(Prompt, String)>,
    pub confirm: Option<Confirm>,
    pub palette: Option<Palette>,
    pub editor: Option<Editor>,
    pub toasts: Vec<Toast>,
    /// The daemon's configuration (None until read).
    pub config: Option<Config>,
    config_toml: String,
    pub settings_sel: usize,
    /// Wall clock of the last status, for the sparkline's time axis.
    pub now_ms: u64,
    pub spin: usize,
    next_spin: Option<Instant>,
    /// Going offline closed an input: offline keys do nothing until then,
    /// so the rest of a sentence being typed cannot start the daemon.
    inert_until: Option<Instant>,
    /// When the last status answer (or failure) arrived.
    last_status: Option<Instant>,
    /// Online, but no status answer for [`WATCHDOG`]: shown as unresponsive.
    pub stale: bool,
    outbox: Vec<Cmd>,
    dirty: bool,
    /// Clickable regions of the last frame (topmost last).
    pub hits: RefCell<Vec<(Rect, Hit)>>,
    /// Rows of the list drawn last (PgUp / PgDn step).
    pub page: Cell<usize>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn without_uptime(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(o) = v.as_object_mut() {
        o.remove("uptime_s");
    }
    v
}

impl App {
    pub fn new() -> Self {
        App {
            tab: Tab::Dashboard,
            quit: false,
            help: false,
            theme: Theme::default(),
            conn: Conn::Connecting,
            status: None,
            starting: None,
            start_hint: None,
            events: VecDeque::new(),
            first_seq: 0,
            live: LiveView::default(),
            buckets: VecDeque::new(),
            inspector: Inspector::default(),
            rules: RulesFile::default(),
            rules_toml: String::new(),
            rules_sel: 0,
            rules_filter: Filter::default(),
            rules_detail: false,
            rules_view: Vec::new(),
            vault: Vec::new(),
            vault_sel: 0,
            vault_filter: Filter::default(),
            vault_detail: false,
            vault_view: Vec::new(),
            prompt: None,
            confirm: None,
            palette: None,
            editor: None,
            toasts: Vec::new(),
            config: None,
            config_toml: String::new(),
            settings_sel: 0,
            now_ms: wall_ms(),
            spin: 0,
            next_spin: None,
            inert_until: None,
            last_status: None,
            stale: false,
            outbox: Vec::new(),
            dirty: true,
            hits: RefCell::new(Vec::new()),
            page: Cell::new(10),
        }
    }

    // ── plumbing ────────────────────────────────────────────────────────

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    pub fn connected(&self) -> bool {
        self.conn == Conn::Online
    }

    /// Whether the offline screen is showing.
    pub fn offline(&self) -> bool {
        matches!(self.conn, Conn::Offline(_))
    }

    /// Offline because nothing listens: the only case the start key is for.
    pub fn not_running(&self) -> bool {
        self.conn == Conn::Offline(Down::NotRunning)
    }

    /// A worker thread died (`None`: found dead when sending to it). It
    /// has been restarted; say so, and do not leave a spinner running.
    pub fn on_worker_died(&mut self, role: Option<Role>) {
        if role != Some(Role::Main) && self.inspector.busy {
            self.inspector.busy = false;
            self.inspector.error =
                Some("the redaction worker stopped — press Enter to retry".into());
        }
        self.toast(
            "a background worker stopped unexpectedly — it has been restarted",
            Level::Error,
        );
        self.request_refresh();
    }

    /// Requests for the worker, in order.
    pub fn take_cmds(&mut self) -> Vec<Cmd> {
        std::mem::take(&mut self.outbox)
    }

    /// Whether something changed since the last call (then: redraw).
    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    fn send(&mut self, c: Cmd) {
        self.outbox.push(c);
    }

    /// Run queued commands against `b` right here (tests, `--dump`).
    pub fn sync(&mut self, b: &mut dyn Backend) {
        for _ in 0..16 {
            let cmds = self.take_cmds();
            if cmds.is_empty() {
                return;
            }
            for c in cmds {
                let mut out = Vec::new();
                crate::worker::exec(c, b, &mut out);
                for m in out {
                    self.on_msg(m);
                }
            }
        }
    }

    /// Ask for a refresh of status, config and the visible tab's data.
    pub fn request_refresh(&mut self) {
        self.send(Cmd::Refresh(self.tab));
    }

    /// The newest toast's text.
    pub fn message(&self) -> Option<&str> {
        self.toasts.last().map(|t| t.text.as_str())
    }

    pub fn toast(&mut self, text: impl Into<String>, level: Level) {
        let text = text.into();
        let ttl = if level == Level::Info {
            TOAST_INFO
        } else {
            TOAST_WARN
        };
        self.toasts.retain(|t| t.text != text);
        self.toasts.push(Toast {
            text,
            level,
            until: Instant::now() + ttl,
        });
        if self.toasts.len() > 3 {
            self.toasts.remove(0);
        }
        self.dirty = true;
    }

    fn busy(&self) -> bool {
        self.inspector.busy || self.starting.is_some()
    }

    /// Time-driven changes: toast expiry, spinner, giving up on a start.
    pub fn tick(&mut self, now: Instant) {
        if self.conn == Conn::Online
            && !self.stale
            && self.last_status.is_some_and(|t| now >= t + WATCHDOG)
        {
            self.stale = true;
            self.dirty = true;
        }
        let n = self.toasts.len();
        self.toasts.retain(|t| t.until > now);
        if self.toasts.len() != n {
            self.dirty = true;
        }
        if let Some(t) = self.starting
            && now.duration_since(t) >= START_WAIT
        {
            self.starting = None;
            self.toast(
                "the daemon did not come up — check its log, or run `parda daemon` in a terminal",
                Level::Error,
            );
        }
        if self.busy() {
            match self.next_spin {
                Some(at) if now < at => {}
                _ => {
                    self.spin = self.spin.wrapping_add(1);
                    self.next_spin = Some(now + SPIN);
                    self.dirty = true;
                }
            }
        } else {
            self.next_spin = None;
        }
    }

    /// When [`App::tick`] next has something to do (None: only input or
    /// new data can change the screen, so the loop may sleep).
    pub fn next_wakeup(&self, now: Instant) -> Option<Instant> {
        let mut at = self.toasts.iter().map(|t| t.until).min();
        if self.busy() {
            let spin = self.next_spin.unwrap_or(now);
            at = Some(at.map_or(spin, |a| a.min(spin)));
        }
        if let Some(t) = self.starting {
            let give_up = t + START_WAIT;
            at = Some(at.map_or(give_up, |a| a.min(give_up)));
        }
        if self.conn == Conn::Online
            && !self.stale
            && let Some(t) = self.last_status
        {
            let watchdog = t + WATCHDOG;
            at = Some(at.map_or(watchdog, |a| a.min(watchdog)));
        }
        at
    }

    /// Whether protection is on (as far as this client knows).
    pub fn protection_on(&self) -> bool {
        match &self.config {
            Some(c) => c.protection.enabled,
            None => self
                .status
                .as_ref()
                .is_none_or(|s| s["protection"].as_bool() != Some(false)),
        }
    }

    // ── results from the worker ─────────────────────────────────────────

    pub fn on_msg(&mut self, m: Msg) {
        match m {
            Msg::Status(Ok(s)) => {
                self.last_status = Some(Instant::now());
                if std::mem::take(&mut self.stale) {
                    self.dirty = true;
                }
                if self.conn != Conn::Online {
                    self.conn = Conn::Online;
                    self.dirty = true;
                    if self.starting.take().is_some() {
                        self.toast("the daemon is running", Level::Info);
                    }
                }
                if self.events.is_empty()
                    && let Some(recent) = s["activity"]["recent"].as_array()
                {
                    for v in recent {
                        if let Ok(e) = serde_json::from_value::<Event>(v.clone()) {
                            self.on_event(e);
                        }
                    }
                }
                self.now_ms = wall_ms();
                let changed = match &self.status {
                    None => true,
                    Some(old) => {
                        without_uptime(old) != without_uptime(&s)
                            || (self.tab == Tab::Dashboard && old["uptime_s"] != s["uptime_s"])
                    }
                };
                self.dirty |= changed;
                self.status = Some(s);
            }
            Msg::Status(Err(e)) => {
                self.last_status = Some(Instant::now());
                self.stale = false;
                let next = Conn::Offline(e);
                if self.conn != next {
                    if !self.offline() && self.close_inputs() {
                        self.inert_until = Some(Instant::now() + INERT);
                    }
                    self.conn = next;
                    self.dirty = true;
                }
            }
            Msg::Config(toml) => {
                if toml != self.config_toml
                    && let Ok(c) = Config::from_toml_str(&toml)
                {
                    self.config = Some(c);
                    self.config_toml = toml;
                    self.dirty = true;
                }
            }
            Msg::Rules(toml) => {
                if toml != self.rules_toml
                    && let Ok(r) = RulesFile::from_toml_str(&toml)
                {
                    self.rules = r;
                    self.rules_toml = toml;
                    self.rebuild_rules_view();
                    self.dirty = true;
                }
            }
            Msg::Vault(rows) => {
                if rows != self.vault {
                    self.vault = rows;
                    self.rebuild_vault_view();
                    self.dirty = true;
                }
            }
            Msg::ConfigSaved {
                result,
                intercept,
                protection,
            } => {
                let (text, level) = match result {
                    Ok(v) if v["restart_required"].as_bool() == Some(true) => (
                        "saved — restart the daemon to apply (parda stop, then parda daemon / service)"
                            .to_string(),
                        Level::Warn,
                    ),
                    Ok(v) if intercept == Some(true) => {
                        let m = intercept_message(&v["intercept"]);
                        let l = if v["intercept"]["listening"].is_string()
                            && v["intercept"]["pac_matches"].as_bool() != Some(false)
                        {
                            Level::Info
                        } else {
                            Level::Warn
                        };
                        (m, l)
                    }
                    Ok(v) if intercept == Some(false) => {
                        let l = if v["intercept"]["pac"].is_string() {
                            Level::Warn
                        } else {
                            Level::Info
                        };
                        (intercept_off_message(&v["intercept"]), l)
                    }
                    Ok(_) if protection == Some(true) => (
                        "protection ON — personal data is replaced before it leaves this machine"
                            .into(),
                        Level::Info,
                    ),
                    Ok(_) if protection == Some(false) => (
                        "protection OFF — text is sent as typed until you press p again".into(),
                        Level::Warn,
                    ),
                    Ok(_) => ("saved and applied".into(), Level::Info),
                    Err(e) => (format!("update failed: {e}"), Level::Error),
                };
                self.toast(text, level);
            }
            Msg::RulesSaved(r) => match r {
                Ok(()) => self.toast("rules saved", Level::Info),
                Err(e) => {
                    self.rules_toml.clear();
                    self.toast(format!("saving rules failed: {e}"), Level::Error)
                }
            },
            Msg::VaultWiped { scope, result } => match (result, scope) {
                (Ok(v), None) => {
                    self.toast(format!("removed {} mapping(s)", v["removed"]), Level::Info)
                }
                (Ok(v), Some(s)) => self.toast(
                    format!("forgot scope '{s}': removed {} mapping(s)", v["removed"]),
                    Level::Info,
                ),
                (Err(e), _) => self.toast(format!("wipe failed: {e}"), Level::Error),
            },
            Msg::Redacted(r) => {
                let ins = &mut self.inspector;
                ins.busy = false;
                match r {
                    Ok(r) => {
                        ins.error = None;
                        ins.redacted = Some(r.text);
                        ins.replaced = r.replaced;
                        ins.restored = r.restored;
                    }
                    Err(e) => ins.error = Some(e),
                }
                self.dirty = true;
            }
            Msg::Started(r) => match r {
                Ok(s) => self.toast(s, Level::Info),
                Err(e) => {
                    self.starting = None;
                    self.toast(format!("could not start the daemon: {e}"), Level::Error);
                }
            },
            Msg::StartHint(h) => {
                if self.start_hint.as_deref() != Some(h.as_str()) {
                    self.start_hint = Some(h);
                    self.dirty = true;
                }
            }
            Msg::Event(e) => self.on_event(e),
        }
    }

    // ── events, the Live view and the sparklines ────────────────────────

    fn event_matches(&self, e: &Event, needle: &str) -> bool {
        if let Some(s) = SURFACES[self.live.surface]
            && e.surface != s
        {
            return false;
        }
        if let Some(k) = &self.live.kind
            && !e.counts.contains_key(k)
        {
            return false;
        }
        if needle.is_empty() {
            return true;
        }
        let kinds: Vec<&str> = e.counts.keys().map(String::as_str).collect();
        hay_matches(
            needle,
            &format!("{} {} {}", e.surface, e.summary, kinds.join(" ")),
        )
    }

    pub fn on_event(&mut self, ev: Event) {
        let seq = self.first_seq + self.events.len() as u64;
        self.record_minute(&ev);
        if self.event_matches(&ev, &self.live.filter.needle()) {
            self.live.view.push_back(seq);
            if self.live.cursor > 0 && self.live.paused.is_none() {
                // Keep the selected event selected as newer ones arrive.
                self.live.cursor += 1;
            }
        }
        self.events.push_back(ev);
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
            if self.live.view.front() == Some(&self.first_seq) {
                self.live.view.pop_front();
            }
            self.first_seq += 1;
        }
        self.clamp_live();
        if matches!(self.tab, Tab::Live | Tab::Dashboard) {
            self.dirty = true;
        }
    }

    fn record_minute(&mut self, e: &Event) {
        let minute = e.ts_ms / 60_000;
        let values: u64 = e.counts.values().map(|n| u64::from(*n)).sum();
        let lat = e
            .latency_ms
            .filter(|_| e.surface == "proxy" || e.surface == "intercept");
        let b = match self.buckets.iter().rposition(|b| b.minute <= minute) {
            Some(i) if self.buckets[i].minute == minute => &mut self.buckets[i],
            Some(i) => {
                self.buckets.insert(
                    i + 1,
                    Bucket {
                        minute,
                        ..Default::default()
                    },
                );
                &mut self.buckets[i + 1]
            }
            None => {
                self.buckets.push_front(Bucket {
                    minute,
                    ..Default::default()
                });
                &mut self.buckets[0]
            }
        };
        b.values += values;
        if let Some(l) = lat
            && b.latencies.len() < 2_000
        {
            b.latencies.push(l);
        }
        let last = self.buckets.back().map_or(0, |b| b.minute);
        while self
            .buckets
            .front()
            .is_some_and(|b| b.minute + MINUTES <= last)
        {
            self.buckets.pop_front();
        }
    }

    /// Events the Live tab shows (filtered, up to the pause point), oldest
    /// first, as (sequence number, event).
    pub fn live_rows(&self) -> impl DoubleEndedIterator<Item = (u64, &Event)> + ExactSizeIterator {
        let n = self.live_len();
        self.live
            .view
            .iter()
            .take(n)
            .map(|s| (*s, &self.events[(*s - self.first_seq) as usize]))
    }

    /// How many events the Live tab shows.
    pub fn live_len(&self) -> usize {
        match self.live.paused {
            Some(cut) => self.live.view.partition_point(|s| *s < cut),
            None => self.live.view.len(),
        }
    }

    /// Events that arrived (and match) since pausing.
    pub fn live_held(&self) -> usize {
        self.live.view.len() - self.live_len()
    }

    pub fn live_selected(&self) -> Option<&Event> {
        let n = self.live_len();
        if n == 0 {
            return None;
        }
        let i = n - 1 - self.live.cursor.min(n - 1);
        let seq = self.live.view[i];
        self.events.get((seq - self.first_seq) as usize)
    }

    fn clamp_live(&mut self) {
        let n = self.live_len();
        self.live.cursor = self.live.cursor.min(n.saturating_sub(1));
    }

    fn rebuild_live_view(&mut self) {
        let needle = self.live.filter.needle();
        let first = self.first_seq;
        let view: VecDeque<u64> = self
            .events
            .iter()
            .enumerate()
            .filter(|(_, e)| self.event_matches(e, &needle))
            .map(|(i, _)| first + i as u64)
            .collect();
        self.live.view = view;
        self.live.cursor = 0;
        self.dirty = true;
    }

    /// Narrow the view after the filter text grew (no full rescan).
    fn narrow_live_view(&mut self) {
        let needle = self.live.filter.needle();
        let first = self.first_seq;
        let view: VecDeque<u64> = self
            .live
            .view
            .iter()
            .copied()
            .filter(|s| self.event_matches(&self.events[(*s - first) as usize], &needle))
            .collect();
        self.live.view = view;
        self.live.cursor = 0;
        self.dirty = true;
    }

    pub fn toggle_pause(&mut self) {
        self.live.paused = match self.live.paused {
            Some(_) => None,
            None => Some(self.first_seq + self.events.len() as u64),
        };
        self.live.cursor = 0;
        self.clamp_live();
        self.toast(
            if self.live.paused.is_some() {
                "live feed paused — space resumes"
            } else {
                "live feed resumed"
            },
            Level::Info,
        );
    }

    pub fn cycle_surface(&mut self) {
        self.live.surface = (self.live.surface + 1) % SURFACES.len();
        self.rebuild_live_view();
    }

    /// Kinds seen in the buffer, sorted.
    pub fn live_kinds(&self) -> Vec<String> {
        let set: BTreeSet<&String> = self.events.iter().flat_map(|e| e.counts.keys()).collect();
        set.into_iter().cloned().collect()
    }

    pub fn cycle_kind(&mut self) {
        let kinds = self.live_kinds();
        self.live.kind = match &self.live.kind {
            None => kinds.first().cloned(),
            Some(k) => kinds
                .iter()
                .position(|x| x == k)
                .and_then(|i| kinds.get(i + 1).cloned()),
        };
        self.rebuild_live_view();
    }

    fn clear_filters(&mut self) {
        self.live.surface = 0;
        self.live.kind = None;
        self.live.filter = Filter::default();
        self.rebuild_live_view();
        self.rules_filter = Filter::default();
        self.rebuild_rules_view();
        self.vault_filter = Filter::default();
        self.rebuild_vault_view();
    }

    // ── rules and vault views ───────────────────────────────────────────

    /// Flattened rows of the rules list: (section, text).
    pub fn rule_rows(&self) -> Vec<(&'static str, String)> {
        let mut rows = Vec::new();
        for p in &self.rules.person {
            let extra = p.aliases.len() + p.emails.len() + p.handles.len();
            let suffix = if extra > 0 {
                format!("  (+{extra} aliases/ids)")
            } else {
                String::new()
            };
            rows.push(("person", format!("{}{suffix}", p.name)));
        }
        for t in &self.rules.term {
            rows.push(("term", format!("{} [{}]", t.text, t.kind)));
        }
        for a in &self.rules.allow {
            rows.push(("allow", a.clone()));
        }
        rows
    }

    /// Indices into [`App::rule_rows`] that pass the filter.
    pub fn rules_view(&self) -> &[usize] {
        &self.rules_view
    }

    fn rebuild_rules_view(&mut self) {
        let needle = self.rules_filter.needle();
        self.rules_view = self
            .rule_rows()
            .iter()
            .enumerate()
            .filter(|(_, (sec, t))| hay_matches(&needle, &format!("{sec} {t}")))
            .map(|(i, _)| i)
            .collect();
        self.rules_sel = self.rules_sel.min(self.rules_view.len().saturating_sub(1));
        self.dirty = true;
    }

    /// Indices into [`App::vault`] that pass the filter.
    pub fn vault_view(&self) -> &[usize] {
        &self.vault_view
    }

    fn vault_hay(r: &Value) -> String {
        format!(
            "{} {}",
            crate::tabs::text(&r["scope"]),
            crate::tabs::text(&r["kind"])
        )
    }

    fn rebuild_vault_view(&mut self) {
        let needle = self.vault_filter.needle();
        self.vault_view = (0..self.vault.len())
            .filter(|i| hay_matches(&needle, &Self::vault_hay(&self.vault[*i])))
            .collect();
        self.vault_sel = self.vault_sel.min(self.vault_view.len().saturating_sub(1));
        self.dirty = true;
    }

    fn narrow_vault_view(&mut self) {
        let needle = self.vault_filter.needle();
        let vault = &self.vault;
        self.vault_view
            .retain(|i| hay_matches(&needle, &Self::vault_hay(&vault[*i])));
        self.vault_sel = 0;
        self.dirty = true;
    }

    pub fn vault_selected(&self) -> Option<&Value> {
        self.vault_view
            .get(self.vault_sel)
            .and_then(|i| self.vault.get(*i))
    }

    // ── keys ────────────────────────────────────────────────────────────

    pub fn on_term(&mut self, ev: TermEvent) {
        match ev {
            TermEvent::Key(k) if k.kind == KeyEventKind::Press => self.on_key(k),
            TermEvent::Mouse(m) => self.on_mouse(m),
            TermEvent::Paste(text) => self.on_paste(&text),
            TermEvent::Resize(..) => self.dirty = true,
            _ => {}
        }
    }

    /// Close every text input (editor, filters, Inspector typing). Returns
    /// whether one was open.
    fn close_inputs(&mut self) -> bool {
        let mut was = self.editor.take().is_some();
        for f in [
            &mut self.live.filter,
            &mut self.rules_filter,
            &mut self.vault_filter,
        ] {
            was |= std::mem::take(&mut f.editing);
        }
        was |= std::mem::take(&mut self.inspector.editing);
        was
    }

    /// Bracketed paste: the text goes into the active input as text; a
    /// newline in it is never Enter. Only the Inspector keeps newlines.
    pub fn on_paste(&mut self, text: &str) {
        self.dirty = true;
        let text: String = text.chars().take(MAX_PASTE).collect();
        let one_line = || -> String {
            text.split(['\n', '\r'])
                .map(|l| {
                    l.chars()
                        .map(|c| if c.is_control() { ' ' } else { c })
                        .collect::<String>()
                })
                .filter(|l| !l.trim().is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        };
        if let Some(ed) = &mut self.editor {
            ed.buf.push_str(one_line().trim());
            ed.error = None;
        } else if let Some((_, buf)) = &mut self.prompt {
            buf.push_str(&one_line());
        } else if let Some(p) = &mut self.palette {
            p.query.push_str(&one_line());
            p.sel = 0;
        } else if self.confirm.is_some() || self.help {
            // Not an input: ignore.
        } else if self.filter_mut().is_some_and(|f| f.editing) {
            let add = one_line();
            if let Some(f) = self.filter_mut() {
                f.text.push_str(add.trim());
            }
            self.filter_changed(true);
        } else if self.tab == Tab::Inspector && !self.offline() {
            let ins = &mut self.inspector;
            ins.editing = true;
            let clean = text.replace("\r\n", "\n").replace('\r', "\n");
            ins.input.extend(
                clean
                    .chars()
                    .filter(|c| !c.is_control() || *c == '\n' || *c == '\t'),
            );
        }
        // Anywhere else pasted text is dropped: it is never read as keys.
    }

    fn switch(&mut self, tab: Tab) {
        if self.tab != tab {
            self.tab = tab;
            self.send(Cmd::Visible(tab));
        }
        self.dirty = true;
    }

    fn filter_mut(&mut self) -> Option<&mut Filter> {
        match self.tab {
            Tab::Live => Some(&mut self.live.filter),
            Tab::Rules => Some(&mut self.rules_filter),
            Tab::Vault => Some(&mut self.vault_filter),
            _ => None,
        }
    }

    fn filter_changed(&mut self, grew: bool) {
        match (self.tab, grew) {
            (Tab::Live, true) => self.narrow_live_view(),
            (Tab::Live, false) => self.rebuild_live_view(),
            (Tab::Rules, _) => self.rebuild_rules_view(),
            (Tab::Vault, true) => self.narrow_vault_view(),
            (Tab::Vault, false) => self.rebuild_vault_view(),
            _ => {}
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        self.dirty = true;
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if self.editor.is_some() {
            self.editor_key(key);
            return;
        }
        if let Some((kind, mut buf)) = self.prompt.take() {
            match key.code {
                KeyCode::Esc => {}
                KeyCode::Enter => self.finish_prompt(kind, buf.trim().to_string()),
                KeyCode::Backspace => {
                    buf.pop();
                    self.prompt = Some((kind, buf));
                }
                KeyCode::Char(c) if !ctrl => {
                    buf.push(c);
                    self.prompt = Some((kind, buf));
                }
                _ => self.prompt = Some((kind, buf)),
            }
            return;
        }
        if self.palette.is_some() {
            self.palette_key(key);
            return;
        }
        if let Some(pending) = self.confirm.take() {
            if key.code != KeyCode::Char('y') {
                self.toast("cancelled", Level::Info);
                return;
            }
            match pending {
                Confirm::WipeVault => self.send(Cmd::VaultWipe(None)),
                Confirm::ForgetScope(s) => self.send(Cmd::VaultWipe(Some(s))),
                Confirm::Setting(s) => {
                    let s2 = s.clone();
                    self.send(Cmd::SetConfig(Box::new(move |c| {
                        settings::step(&s2, c, true)
                    })))
                }
            }
            return;
        }
        if self.help {
            if matches!(
                key.code,
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') | KeyCode::Enter
            ) {
                self.help = false;
            }
            return;
        }
        if self.filter_mut().is_some_and(|f| f.editing) {
            self.filter_key(key);
            return;
        }
        if self.tab == Tab::Inspector && self.inspector.editing {
            self.inspector_edit(key);
            return;
        }
        if (ctrl && key.code == KeyCode::Char('k')) || key.code == KeyCode::Char(':') {
            self.palette = Some(Palette::default());
            return;
        }
        if self.offline() {
            if self.inert_until.is_some_and(|t| Instant::now() < t) {
                return;
            }
            match key.code {
                // Only `s` (or the button, or the palette): never Enter.
                KeyCode::Char('s') => self.start_daemon(),
                KeyCode::Char('q') => self.quit = true,
                KeyCode::Char('?') => self.help = true,
                _ => {}
            }
            return;
        }
        if ctrl && key.code == KeyCode::Char('r') {
            self.request_refresh();
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('p') => self.toggle_protection(),
            KeyCode::Char(c @ '1'..='6') => self.switch(Tab::ALL[(c as u8 - b'1') as usize]),
            KeyCode::Tab => self.switch(Tab::ALL[(self.tab.index() + 1) % 6]),
            KeyCode::BackTab => self.switch(Tab::ALL[(self.tab.index() + 5) % 6]),
            KeyCode::Char('/') if self.filter_mut().is_some() => {
                if let Some(f) = self.filter_mut() {
                    f.editing = true;
                }
            }
            _ => self.tab_key(key),
        }
    }

    fn filter_key(&mut self, key: KeyEvent) {
        let Some(f) = self.filter_mut() else { return };
        match key.code {
            KeyCode::Esc => {
                *f = Filter::default();
                self.filter_changed(false);
            }
            KeyCode::Enter | KeyCode::Down | KeyCode::Up => f.editing = false,
            KeyCode::Backspace => {
                f.text.pop();
                self.filter_changed(false);
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                f.text.push(c);
                self.filter_changed(true);
            }
            _ => {}
        }
    }

    /// Movement keys shared by every list: (delta, absolute target).
    fn motion(&self, key: &KeyEvent) -> Option<isize> {
        let page = self.page.get().max(1) as isize;
        Some(match key.code {
            KeyCode::Up | KeyCode::Char('k') => -1,
            KeyCode::Down | KeyCode::Char('j') => 1,
            KeyCode::PageUp => -page,
            KeyCode::PageDown => page,
            KeyCode::Home | KeyCode::Char('g') => isize::MIN / 2,
            KeyCode::End | KeyCode::Char('G') => isize::MAX / 2,
            _ => return None,
        })
    }

    fn tab_key(&mut self, key: KeyEvent) {
        if let Some(d) = self.motion(&key)
            && self.tab != Tab::Inspector
        {
            self.scroll(d);
            return;
        }
        // ←/→ (h/l) change a value in Settings and switch tabs elsewhere.
        if self.tab != Tab::Settings {
            match key.code {
                KeyCode::Left | KeyCode::Char('h') => {
                    return self.switch(Tab::ALL[(self.tab.index() + 5) % 6]);
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    return self.switch(Tab::ALL[(self.tab.index() + 1) % 6]);
                }
                _ => {}
            }
        }
        match self.tab {
            Tab::Dashboard => {
                if key.code == KeyCode::Char('r') {
                    self.request_refresh();
                }
            }
            Tab::Inspector => match key.code {
                KeyCode::Enter | KeyCode::Char('i') => self.inspector.editing = true,
                KeyCode::Char('r') => self.inspector.show_restore = !self.inspector.show_restore,
                KeyCode::Esc => self.inspector = Inspector::default(),
                _ => {}
            },
            Tab::Rules => match key.code {
                KeyCode::Char('a') => self.prompt = Some((Prompt::AddPerson, String::new())),
                KeyCode::Char('w') => self.prompt = Some((Prompt::AllowTerm, String::new())),
                KeyCode::Char('d') | KeyCode::Delete => self.delete_rule(),
                KeyCode::Enter => self.rules_detail = !self.rules_detail,
                KeyCode::Esc => self.back_out(),
                _ => {}
            },
            Tab::Vault => match key.code {
                KeyCode::Char('w') => self.ask_wipe(),
                KeyCode::Char('x') | KeyCode::Char('d') | KeyCode::Delete => {
                    if let Some(scope) = self.vault_selected().and_then(|r| r["scope"].as_str()) {
                        self.confirm = Some(Confirm::ForgetScope(scope.to_string()));
                    }
                }
                KeyCode::Enter => self.vault_detail = !self.vault_detail,
                KeyCode::Esc => self.back_out(),
                _ => {}
            },
            Tab::Live => match key.code {
                KeyCode::Char(' ') => self.toggle_pause(),
                KeyCode::Char('f') => self.cycle_surface(),
                KeyCode::Char('t') => self.cycle_kind(),
                KeyCode::Char('c') => self.clear_filters(),
                KeyCode::Enter => self.live.detail = !self.live.detail,
                KeyCode::Esc => self.back_out(),
                _ => {}
            },
            Tab::Settings => match key.code {
                KeyCode::Enter => self.activate_setting(self.settings_sel),
                KeyCode::Char(' ') | KeyCode::Right | KeyCode::Char('l') => {
                    self.step_setting(self.settings_sel, true)
                }
                KeyCode::Left | KeyCode::Char('h') => self.step_setting(self.settings_sel, false),
                KeyCode::Char('e') => self.open_editor(self.settings_sel),
                KeyCode::Char('m') => self.send(Cmd::SetConfig(Box::new(|c| {
                    c.detect.mode = match c.detect.mode {
                        Mode::Strict => Mode::Fast,
                        Mode::Fast => Mode::Strict,
                    }
                }))),
                KeyCode::Char('s') => self.send(Cmd::SetConfig(Box::new(|c| {
                    c.replace.style = match c.replace.style {
                        Style::Surrogate => Style::Token,
                        Style::Token => Style::Surrogate,
                    }
                }))),
                _ => {}
            },
        }
    }

    /// Esc on a list: close the detail pane, then clear the filter, then
    /// (Live) jump back to the newest event.
    fn back_out(&mut self) {
        match self.tab {
            Tab::Live if self.live.detail => self.live.detail = false,
            Tab::Live if self.live.filter.active() => {
                self.live.filter = Filter::default();
                self.rebuild_live_view();
            }
            Tab::Live => self.live.cursor = 0,
            Tab::Rules if self.rules_detail => self.rules_detail = false,
            Tab::Rules if self.rules_filter.active() => {
                self.rules_filter = Filter::default();
                self.rebuild_rules_view();
            }
            Tab::Vault if self.vault_detail => self.vault_detail = false,
            Tab::Vault if self.vault_filter.active() => {
                self.vault_filter = Filter::default();
                self.rebuild_vault_view();
            }
            _ => {}
        }
    }

    fn ask_wipe(&mut self) {
        self.confirm = Some(Confirm::WipeVault);
    }

    fn start_daemon(&mut self) {
        if self.connected() {
            self.toast("the daemon is already running", Level::Info);
        } else if !self.not_running() {
            self.toast(
                "the daemon is running but cannot be used — see the screen; start is only for a \
                 daemon that is not running",
                Level::Warn,
            );
        } else if self.starting.is_some() {
            self.toast("already starting — waiting for the daemon", Level::Info);
        } else {
            self.starting = Some(Instant::now());
            self.send(Cmd::StartDaemon);
        }
    }

    pub fn toggle_protection(&mut self) {
        self.send(Cmd::SetConfig(Box::new(|c| {
            c.protection.enabled = !c.protection.enabled
        })));
    }

    /// Enter / click on setting row `i`: flip a switch, cycle a choice, or
    /// open the editor for a number or text.
    fn activate_setting(&mut self, i: usize) {
        let Some(s) = settings::all().get(i).cloned() else {
            return;
        };
        self.settings_sel = i;
        match settings::edit_kind(&s) {
            Edit::Number | Edit::Text => self.open_editor(i),
            Edit::Toggle | Edit::Cycle => self.step_setting(i, true),
        }
    }

    /// ←/→/Space on setting row `i`: next (or previous) value.
    fn step_setting(&mut self, i: usize, forward: bool) {
        let Some(s) = settings::all().get(i).cloned() else {
            return;
        };
        self.settings_sel = i;
        if !settings::cycles(&s) {
            return self.open_editor(i);
        }
        if let Some(c) = &self.config
            && settings::needs_confirm(&s, c)
        {
            self.confirm = Some(Confirm::Setting(s));
            return;
        }
        self.send(Cmd::SetConfig(Box::new(move |c| {
            settings::step(&s, c, forward)
        })));
    }

    fn open_editor(&mut self, i: usize) {
        let Some(s) = settings::all().get(i).cloned() else {
            return;
        };
        if !matches!(settings::edit_kind(&s), Edit::Number | Edit::Text) {
            return;
        }
        let Some(c) = &self.config else {
            self.toast("configuration not loaded yet", Level::Warn);
            return;
        };
        self.settings_sel = i;
        self.editor = Some(Editor {
            buf: settings::raw_value(&s, c),
            setting: s,
            error: None,
        });
    }

    fn editor_key(&mut self, key: KeyEvent) {
        let Some(ed) = &mut self.editor else { return };
        match key.code {
            KeyCode::Esc => self.editor = None,
            KeyCode::Backspace => {
                ed.buf.pop();
                ed.error = None;
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                ed.buf.clear();
                ed.error = None;
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                ed.buf.push(c);
                ed.error = None;
            }
            KeyCode::Enter => {
                let Some(cfg) = &self.config else {
                    ed.error = Some("configuration not loaded".into());
                    return;
                };
                let mut probe = cfg.clone();
                match settings::apply_text(&ed.setting, &mut probe, &ed.buf) {
                    Err(e) => ed.error = Some(e),
                    Ok(()) => {
                        let (s, v) = (ed.setting.clone(), ed.buf.clone());
                        self.editor = None;
                        self.send(Cmd::SetConfig(Box::new(move |c| {
                            let _ = settings::apply_text(&s, c, &v);
                        })));
                    }
                }
            }
            _ => {}
        }
    }

    /// Every action, labelled for the current state.
    pub fn palette_entries(&self) -> Vec<Entry> {
        let mut v: Vec<Entry> = Tab::ALL
            .iter()
            .zip(["1", "2", "3", "4", "5", "6"])
            .map(|(t, k)| Entry::new(format!("Go to {}", t.title()), k, Action::Tab(*t)))
            .collect();
        if self.not_running() {
            v.insert(0, Entry::new("Start the daemon", "s", Action::StartDaemon));
        }
        let on = self.protection_on();
        v.push(Entry::new(
            if on {
                "Protection: turn off (send text unfiltered)"
            } else {
                "Protection: turn on"
            },
            "p",
            Action::Protection,
        ));
        if let Some(c) = &self.config {
            let flip = |b: bool| if b { "turn off" } else { "turn on" };
            v.push(Entry::new(
                format!("AI-site intercept: {}", flip(c.intercept.enabled)),
                "",
                Action::Setting(Setting::Intercept),
            ));
            v.push(Entry::new(
                format!("Agent proxy: {} (after restart)", flip(c.proxy.enabled)),
                "",
                Action::Setting(Setting::Proxy),
            ));
            v.push(Entry::new(
                format!(
                    "Clipboard & paste-safe: {} (after restart)",
                    flip(c.clipboard.enabled)
                ),
                "",
                Action::Setting(Setting::Clipboard),
            ));
            v.push(Entry::new(
                match c.detect.mode {
                    Mode::Strict => "Mode: switch to fast (rules only when the model fails)",
                    Mode::Fast => "Mode: switch to strict (refuse when the model fails)",
                },
                "",
                Action::Setting(Setting::Mode),
            ));
            v.push(Entry::new(
                match c.replace.style {
                    Style::Token => "Replacement style: realistic stand-ins",
                    Style::Surrogate => "Replacement style: tags like [NAME_1]",
                },
                "",
                Action::Setting(Setting::Style),
            ));
        }
        v.extend([
            Entry::new("Inspector: try text", "3", Action::Inspect),
            Entry::new("Rules: add a person to always mask", "a", Action::AddPerson),
            Entry::new("Rules: allow a term (never mask)", "w", Action::AllowTerm),
            Entry::new(
                "Vault: wipe every mapping (asks first)",
                "w",
                Action::WipeVault,
            ),
            Entry::new(
                if self.live.paused.is_some() {
                    "Live: resume"
                } else {
                    "Live: pause"
                },
                "space",
                Action::PauseLive,
            ),
            Entry::new("Live: filter by surface", "f", Action::LiveSurface),
            Entry::new("Live: filter by kind", "t", Action::LiveKind),
            Entry::new("Clear all filters", "c", Action::ClearFilters),
            Entry::new("Refresh now", "^R", Action::Refresh),
            Entry::new("Help: keys", "?", Action::Help),
            Entry::new("Quit", "q", Action::Quit),
        ]);
        v
    }

    fn palette_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let n = {
            let entries = self.palette_entries();
            let q = self
                .palette
                .as_ref()
                .map(|p| p.query.clone())
                .unwrap_or_default();
            palette::filter(&entries, &q).len()
        };
        let Some(p) = &mut self.palette else { return };
        match key.code {
            KeyCode::Esc => self.palette = None,
            KeyCode::Up => p.sel = p.sel.saturating_sub(1),
            KeyCode::Char('p') if ctrl => p.sel = p.sel.saturating_sub(1),
            KeyCode::Down => p.sel = (p.sel + 1).min(n.saturating_sub(1)),
            KeyCode::Char('n') if ctrl => p.sel = (p.sel + 1).min(n.saturating_sub(1)),
            KeyCode::Backspace => {
                p.query.pop();
                p.sel = 0;
            }
            KeyCode::Char(c) if !ctrl => {
                p.query.push(c);
                p.sel = 0;
            }
            KeyCode::Enter => {
                let sel = p.sel;
                self.run_palette(sel);
            }
            _ => {}
        }
    }

    fn run_palette(&mut self, i: usize) {
        let q = self.palette.take().map(|p| p.query).unwrap_or_default();
        let entries = self.palette_entries();
        let action = palette::filter(&entries, &q)
            .get(i)
            .map(|e| e.action.clone());
        if let Some(a) = action {
            self.run_action(a);
        }
    }

    pub fn run_action(&mut self, a: Action) {
        self.dirty = true;
        match a {
            Action::Tab(t) => self.switch(t),
            Action::Quit => self.quit = true,
            Action::Help => self.help = true,
            Action::StartDaemon => self.start_daemon(),
            _ if self.offline() => {
                self.toast("the daemon is offline — press s to start it", Level::Warn)
            }
            Action::Protection => self.toggle_protection(),
            Action::Setting(s) => {
                if let Some(i) = settings::all().iter().position(|x| *x == s) {
                    self.activate_setting(i);
                }
            }
            Action::Inspect => {
                self.switch(Tab::Inspector);
                self.inspector.editing = true;
            }
            Action::AddPerson => {
                self.switch(Tab::Rules);
                self.prompt = Some((Prompt::AddPerson, String::new()));
            }
            Action::AllowTerm => {
                self.switch(Tab::Rules);
                self.prompt = Some((Prompt::AllowTerm, String::new()));
            }
            Action::WipeVault => {
                self.switch(Tab::Vault);
                self.ask_wipe();
            }
            Action::PauseLive => {
                self.switch(Tab::Live);
                self.toggle_pause();
            }
            Action::LiveSurface => {
                self.switch(Tab::Live);
                self.cycle_surface();
            }
            Action::LiveKind => {
                self.switch(Tab::Live);
                self.cycle_kind();
            }
            Action::ClearFilters => self.clear_filters(),
            Action::Refresh => self.request_refresh(),
        }
    }

    /// Move the selection of the current list by `delta` rows.
    fn scroll(&mut self, delta: isize) {
        let step = |v: usize, max: usize| v.saturating_add_signed(delta).min(max);
        match self.tab {
            Tab::Rules => {
                let n = self.rules_view.len();
                self.rules_sel = step(self.rules_sel, n.saturating_sub(1));
            }
            Tab::Vault => {
                let n = self.vault_view.len();
                self.vault_sel = step(self.vault_sel, n.saturating_sub(1));
            }
            Tab::Settings => {
                let n = settings::all().len();
                self.settings_sel = step(self.settings_sel, n - 1);
            }
            Tab::Live => {
                // Up (negative) selects older events.
                let n = self.live_len();
                self.live.cursor = self
                    .live
                    .cursor
                    .saturating_add_signed(delta.saturating_neg())
                    .min(n.saturating_sub(1));
            }
            _ => {}
        }
        self.dirty = true;
    }

    pub fn on_mouse(&mut self, m: MouseEvent) {
        match m.kind {
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
                let d = if m.kind == MouseEventKind::ScrollUp {
                    -1
                } else {
                    1
                };
                if let Some(p) = &mut self.palette {
                    p.sel = p.sel.saturating_add_signed(d);
                } else if !self.help {
                    self.scroll(d);
                }
                self.dirty = true;
            }
            MouseEventKind::Down(button) => {
                self.dirty = true;
                if self.help {
                    self.help = false;
                    return;
                }
                if self.prompt.is_some() || self.confirm.is_some() || self.editor.is_some() {
                    return;
                }
                let at = Position::new(m.column, m.row);
                let hit = self
                    .hits
                    .borrow()
                    .iter()
                    .rev()
                    .find(|(r, _)| r.contains(at))
                    .map(|(_, h)| *h);
                if self.palette.is_some() {
                    match hit {
                        Some(Hit::Palette(i)) => self.run_palette(i),
                        _ => self.palette = None,
                    }
                    return;
                }
                match hit {
                    Some(Hit::Tab(t)) => self.switch(t),
                    Some(Hit::Start) => self.start_daemon(),
                    Some(_) if self.offline() => {}
                    Some(Hit::Protection) => self.toggle_protection(),
                    Some(Hit::Input) => self.inspector.editing = true,
                    Some(Hit::Palette(_)) => {}
                    Some(Hit::Row(i)) => match self.tab {
                        Tab::Rules => self.rules_sel = i,
                        Tab::Vault => {
                            if self.vault_sel == i {
                                self.vault_detail = !self.vault_detail;
                            }
                            self.vault_sel = i;
                        }
                        Tab::Live => {
                            if self.live.cursor == i {
                                self.live.detail = !self.live.detail;
                            }
                            self.live.cursor = i;
                        }
                        Tab::Settings => {
                            if button == MouseButton::Right {
                                self.step_setting(i, false)
                            } else {
                                self.activate_setting(i)
                            }
                        }
                        _ => {}
                    },
                    None => {
                        if self.tab == Tab::Inspector {
                            self.inspector.editing = false;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn inspector_edit(&mut self, key: KeyEvent) {
        let ins = &mut self.inspector;
        match key.code {
            KeyCode::Esc => ins.editing = false,
            KeyCode::Backspace => {
                ins.input.pop();
            }
            KeyCode::Enter => {
                ins.editing = false;
                ins.error = None;
                ins.busy = true;
                let text = ins.input.clone();
                self.send(Cmd::Redact(text));
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => ins.input.push(c),
            _ => {}
        }
    }

    fn rules_toml_string(&mut self) -> Option<String> {
        match self.rules.to_toml_string() {
            Ok(t) => Some(t),
            Err(e) => {
                self.toast(format!("saving rules failed: {e}"), Level::Error);
                None
            }
        }
    }

    fn save_rules(&mut self) {
        self.rebuild_rules_view();
        if let Some(t) = self.rules_toml_string() {
            // Forget what we last read: the reload that follows the save
            // always applies, so a failed save cannot leave local edits
            // showing as if they were saved.
            self.rules_toml.clear();
            self.send(Cmd::SetRules(t));
        }
    }

    fn delete_rule(&mut self) {
        let Some(&i) = self.rules_view.get(self.rules_sel) else {
            return;
        };
        let np = self.rules.person.len();
        let nt = self.rules.term.len();
        if i < np {
            self.rules.person.remove(i);
        } else if i < np + nt {
            self.rules.term.remove(i - np);
        } else if i < np + nt + self.rules.allow.len() {
            self.rules.allow.remove(i - np - nt);
        } else {
            return;
        }
        self.rules_sel = self.rules_sel.saturating_sub(1);
        self.save_rules();
    }

    fn finish_prompt(&mut self, kind: Prompt, text: String) {
        if text.is_empty() {
            return;
        }
        match kind {
            Prompt::AddPerson => self.rules.person.push(PersonBlock {
                name: text,
                ..Default::default()
            }),
            Prompt::AllowTerm => self.rules.allow.push(text),
        }
        self.save_rules();
    }

    pub fn draw(&self, f: &mut Frame) {
        ui::draw(self, f);
    }
}

/// What switching intercept on did, from the daemon's answer.
pub(crate) fn intercept_message(it: &Value) -> String {
    match (it["listening"].as_str(), it["error"].as_str()) {
        (Some(addr), _) if it["pac"].is_string() && it["pac_matches"].as_bool() == Some(false) => {
            format!(
                "intercept listening on {addr}, but the system proxy points at {} — AI sites \
                 fail to load; run `parda intercept on` again",
                it["pac"].as_str().unwrap_or_default()
            )
        }
        (Some(addr), _) if it["pac"].is_string() => format!("intercept listening on {addr}"),
        (Some(addr), _) => format!(
            "intercept listening on {addr} — run `parda intercept on` to send AI sites through it"
        ),
        (None, Some(e)) => format!("saved, but not listening — {e}"),
        (None, None) if it["enabled"].as_bool() == Some(true) => NO_PROXY.into(),
        _ => "saved and applied".into(),
    }
}

/// Intercept on, but no listener and no reason: the daemon was started
/// with `--no-proxy` (or the listener ended).
pub(crate) const NO_PROXY: &str = "NOT LISTENING — the daemon runs without its proxy services \
                                   (restart it without --no-proxy)";

/// What switching intercept off did, from the daemon's answer.
pub(crate) fn intercept_off_message(it: &Value) -> String {
    if !it.is_object() {
        return "saved and applied".into();
    }
    if it["pac"].is_string() {
        "listener stopped — the system proxy still sends AI sites to parda, so they fail to \
         load; run `parda intercept off` to restore your settings"
            .into()
    } else {
        "intercept off — listener stopped".into()
    }
}

#[cfg(test)]
mod intercept_message_tests {
    use super::{intercept_message, intercept_off_message};
    use serde_json::json;

    #[test]
    fn says_what_switching_intercept_on_did() {
        let on = json!({"listening": "127.0.0.1:8788", "pac": "http://127.0.0.1:8788/parda.pac"});
        assert_eq!(
            intercept_message(&on),
            "intercept listening on 127.0.0.1:8788"
        );
        let no_pac = json!({"listening": "127.0.0.1:8788", "pac": null});
        assert!(intercept_message(&no_pac).contains("run `parda intercept on`"));
        let failed = json!({"listening": null, "error": "intercept: no CA"});
        assert_eq!(
            intercept_message(&failed),
            "saved, but not listening — intercept: no CA"
        );
        let moved = json!({"listening": "127.0.0.1:9999", "pac": "http://127.0.0.1:8788/parda.pac",
                           "pac_matches": false});
        let m = intercept_message(&moved);
        assert!(
            m.contains("127.0.0.1:9999") && m.contains("parda intercept on"),
            "{m}"
        );
        // Switched on, but the daemon runs with --no-proxy: no listener, no error.
        let no_proxy = json!({"enabled": true, "listening": null, "error": null, "pac": null});
        let m = intercept_message(&no_proxy);
        assert!(
            m.contains("NOT LISTENING") && m.contains("--no-proxy"),
            "{m}"
        );
        // An older daemon says nothing about it.
        assert_eq!(intercept_message(&json!(null)), "saved and applied");
    }

    #[test]
    fn says_what_switching_intercept_off_did() {
        let pac_set = json!({"enabled": false, "listening": null,
                             "pac": "http://127.0.0.1:8788/parda.pac"});
        let m = intercept_off_message(&pac_set);
        assert!(
            m.contains("listener stopped")
                && m.contains("fail to load")
                && m.contains("parda intercept off"),
            "{m}"
        );
        let clean = json!({"enabled": false, "listening": null, "pac": null});
        assert_eq!(
            intercept_off_message(&clean),
            "intercept off — listener stopped"
        );
        assert_eq!(intercept_off_message(&json!(null)), "saved and applied");
    }
}
