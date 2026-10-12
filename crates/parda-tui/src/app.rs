//! Application state and key handling.

use std::collections::VecDeque;

use parda_core::{Config, Mode, Style};
use parda_detect::{PersonBlock, RulesFile};
use parda_ipc::{Event, Request};
use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::Value;

use crate::Backend;
use crate::tabs;

const MAX_EVENTS: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Live,
    Inspector,
    Rules,
    Vault,
    Setup,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Dashboard,
        Tab::Live,
        Tab::Inspector,
        Tab::Rules,
        Tab::Vault,
        Tab::Setup,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Live => "Live",
            Tab::Inspector => "Inspector",
            Tab::Rules => "Rules",
            Tab::Vault => "Vault",
            Tab::Setup => "Setup",
        }
    }

    fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

/// What a line-input prompt is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompt {
    AddPerson,
    AllowTerm,
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
}

pub struct App {
    pub tab: Tab,
    quit: bool,
    pub help: bool,
    pub status: Option<Value>,
    pub connected: bool,
    pub events: VecDeque<Event>,
    pub inspector: Inspector,
    pub rules: RulesFile,
    pub rules_sel: usize,
    pub vault: Vec<Value>,
    pub prompt: Option<(Prompt, String)>,
    pub confirm_wipe: bool,
    pub message: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        App {
            tab: Tab::Dashboard,
            quit: false,
            help: false,
            status: None,
            connected: false,
            events: VecDeque::new(),
            inspector: Inspector::default(),
            rules: RulesFile::default(),
            rules_sel: 0,
            vault: Vec::new(),
            prompt: None,
            confirm_wipe: false,
            message: None,
        }
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// Re-read status (and the data of the visible tab).
    pub fn refresh(&mut self, b: &mut dyn Backend) {
        match b.call(Request::Status) {
            Ok(s) => {
                // A fresh dashboard starts with the daemon's recent history.
                if self.events.is_empty()
                    && let Some(recent) = s["activity"]["recent"].as_array()
                {
                    for v in recent {
                        if let Ok(e) = serde_json::from_value::<Event>(v.clone()) {
                            self.on_event(e);
                        }
                    }
                }
                self.status = Some(s);
                self.connected = true;
            }
            Err(e) => {
                self.connected = false;
                self.message = Some(format!("daemon unreachable: {e}"));
            }
        }
        match self.tab {
            Tab::Rules => self.load_rules(b),
            Tab::Vault => self.load_vault(b),
            _ => {}
        }
    }

    fn load_rules(&mut self, b: &mut dyn Backend) {
        if let Ok(v) = b.call(Request::RulesGet)
            && let Some(t) = v["toml"].as_str()
            && let Ok(r) = RulesFile::from_toml_str(t)
        {
            self.rules = r;
        }
    }

    fn load_vault(&mut self, b: &mut dyn Backend) {
        if let Ok(v) = b.call(Request::VaultStats) {
            self.vault = v["stats"].as_array().cloned().unwrap_or_default();
        }
    }

    fn save_rules(&mut self, b: &mut dyn Backend) {
        match self
            .rules
            .to_toml_string()
            .map_err(anyhow::Error::from)
            .and_then(|t| b.call(Request::RulesSet { rules_toml: t }))
        {
            Ok(_) => self.message = Some("rules saved".into()),
            Err(e) => self.message = Some(format!("saving rules failed: {e}")),
        }
    }

    pub fn on_event(&mut self, ev: Event) {
        self.events.push_back(ev);
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }

    fn switch(&mut self, tab: Tab, b: &mut dyn Backend) {
        self.tab = tab;
        self.message = None;
        self.refresh(b);
    }

    pub fn on_key(&mut self, key: KeyEvent, b: &mut dyn Backend) {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return;
        }
        if let Some((kind, mut buf)) = self.prompt.take() {
            match key.code {
                KeyCode::Esc => {}
                KeyCode::Enter => self.finish_prompt(kind, buf.trim().to_string(), b),
                KeyCode::Backspace => {
                    buf.pop();
                    self.prompt = Some((kind, buf));
                }
                KeyCode::Char(c) => {
                    buf.push(c);
                    self.prompt = Some((kind, buf));
                }
                _ => self.prompt = Some((kind, buf)),
            }
            return;
        }
        if self.tab == Tab::Inspector && self.inspector.editing {
            self.inspector_edit(key, b);
            return;
        }
        if self.confirm_wipe {
            self.confirm_wipe = false;
            if key.code == KeyCode::Char('y') {
                match b.call(Request::VaultWipe { scope: None }) {
                    Ok(v) => self.message = Some(format!("removed {} mapping(s)", v["removed"])),
                    Err(e) => self.message = Some(format!("wipe failed: {e}")),
                }
                self.load_vault(b);
            } else {
                self.message = Some("wipe cancelled".into());
            }
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.help = !self.help,
            KeyCode::Char(c @ '1'..='6') => {
                let i = (c as u8 - b'1') as usize;
                self.switch(Tab::ALL[i], b);
            }
            KeyCode::Tab => self.switch(Tab::ALL[(self.tab.index() + 1) % 6], b),
            KeyCode::BackTab => self.switch(Tab::ALL[(self.tab.index() + 5) % 6], b),
            _ => self.tab_key(key, b),
        }
    }

    fn tab_key(&mut self, key: KeyEvent, b: &mut dyn Backend) {
        match self.tab {
            Tab::Inspector => match key.code {
                KeyCode::Enter | KeyCode::Char('i') => self.inspector.editing = true,
                KeyCode::Char('r') => self.inspector.show_restore = !self.inspector.show_restore,
                KeyCode::Esc => self.inspector = Inspector::default(),
                _ => {}
            },
            Tab::Rules => {
                let n = self.rule_rows().len();
                match key.code {
                    KeyCode::Up => self.rules_sel = self.rules_sel.saturating_sub(1),
                    KeyCode::Down => self.rules_sel = (self.rules_sel + 1).min(n.saturating_sub(1)),
                    KeyCode::Char('a') => self.prompt = Some((Prompt::AddPerson, String::new())),
                    KeyCode::Char('w') => self.prompt = Some((Prompt::AllowTerm, String::new())),
                    KeyCode::Char('d') | KeyCode::Delete => self.delete_rule(b),
                    _ => {}
                }
            }
            Tab::Vault => {
                if key.code == KeyCode::Char('w') {
                    self.confirm_wipe = true;
                    self.message = Some("wipe ALL mappings? press y to confirm".into());
                }
            }
            Tab::Setup => match key.code {
                KeyCode::Char('m') => self.toggle_config(b, |c| {
                    c.detect.mode = match c.detect.mode {
                        Mode::Strict => Mode::Fast,
                        Mode::Fast => Mode::Strict,
                    }
                }),
                KeyCode::Char('s') => self.toggle_config(b, |c| {
                    c.replace.style = match c.replace.style {
                        Style::Surrogate => Style::Token,
                        Style::Token => Style::Surrogate,
                    }
                }),
                _ => {}
            },
            _ => {}
        }
    }

    fn toggle_config(&mut self, b: &mut dyn Backend, f: impl FnOnce(&mut Config)) {
        let current = b
            .call(Request::ConfigGet)
            .ok()
            .and_then(|v| v["toml"].as_str().map(str::to_string))
            .and_then(|t| Config::from_toml_str(&t).ok());
        let Some(mut c) = current else {
            self.message = Some("cannot read the configuration".into());
            return;
        };
        f(&mut c);
        let res = c
            .to_toml_string()
            .map_err(anyhow::Error::from)
            .and_then(|toml| b.call(Request::ConfigSet { toml }));
        self.message = Some(match res {
            Ok(_) => "configuration updated".into(),
            Err(e) => format!("update failed: {e}"),
        });
        self.refresh(b);
    }

    fn inspector_edit(&mut self, key: KeyEvent, b: &mut dyn Backend) {
        let ins = &mut self.inspector;
        match key.code {
            KeyCode::Esc => ins.editing = false,
            KeyCode::Backspace => {
                ins.input.pop();
            }
            KeyCode::Enter => {
                ins.editing = false;
                ins.error = None;
                match b.call(Request::Redact {
                    text: ins.input.clone(),
                    scope: None,
                }) {
                    Ok(v) => {
                        let red = v["text"].as_str().unwrap_or_default().to_string();
                        ins.replaced = v["replaced"].as_array().cloned().unwrap_or_default();
                        ins.restored = b
                            .call(Request::Restore {
                                text: red.clone(),
                                scope: None,
                            })
                            .ok()
                            .and_then(|r| r["text"].as_str().map(str::to_string));
                        ins.redacted = Some(red);
                    }
                    Err(e) => ins.error = Some(e.to_string()),
                }
            }
            KeyCode::Char(c) => ins.input.push(c),
            _ => {}
        }
    }

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

    fn delete_rule(&mut self, b: &mut dyn Backend) {
        let np = self.rules.person.len();
        let nt = self.rules.term.len();
        let i = self.rules_sel;
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
        self.save_rules(b);
    }

    fn finish_prompt(&mut self, kind: Prompt, text: String, b: &mut dyn Backend) {
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
        self.save_rules(b);
    }

    pub fn draw(&self, f: &mut Frame) {
        tabs::draw(self, f);
    }
}
