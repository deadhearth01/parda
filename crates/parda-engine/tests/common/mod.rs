#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parda_core::{Config, Detection, MlDetector};
use parda_detect::{PersonBlock, RulesFile};
use parda_engine::{Engine, EngineOptions};

pub fn rules() -> RulesFile {
    RulesFile {
        person: vec![PersonBlock {
            name: "Ravi Kumar".into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

pub fn rules_only_config() -> Config {
    let mut c = Config::default();
    c.detect.model = "none".into();
    c
}

pub fn engine_with(config: Config, ml: Option<Arc<dyn MlDetector>>) -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let e = Engine::open(
        EngineOptions {
            config,
            rules: rules(),
            data_dir: dir.path().join("data"),
            use_keyring: false,
        },
        ml,
    )
    .unwrap();
    (dir, e)
}

pub fn engine() -> (tempfile::TempDir, Engine) {
    engine_with(rules_only_config(), None)
}

/// ML stub: optional delay, optional failure, counts calls, finds nothing.
pub struct StubMl {
    pub delay: Duration,
    pub fail: bool,
    pub calls: AtomicUsize,
}

impl StubMl {
    pub fn new(delay_ms: u64, fail: bool) -> Arc<Self> {
        Arc::new(StubMl {
            delay: Duration::from_millis(delay_ms),
            fail,
            calls: AtomicUsize::new(0),
        })
    }
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl MlDetector for StubMl {
    fn name(&self) -> &str {
        "stub"
    }
    fn detect_batch(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<Detection>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        if self.fail {
            anyhow::bail!("stub failure");
        }
        Ok(vec![Vec::new(); texts.len()])
    }
}

pub fn ml_config(mode: parda_core::Mode, timeout_ms: u64) -> Config {
    let mut c = Config::default();
    c.detect.model = "stub".into();
    c.detect.mode = mode;
    c.detect.ml_timeout_ms = timeout_ms;
    c
}

/// ML stub that "finds" fixed names: every occurrence in its input window
/// is reported as a Person, with an optional score.
pub struct NameMl {
    pub names: std::sync::Mutex<Vec<String>>,
    pub score: f32,
}

impl NameMl {
    pub fn new(names: &[&str]) -> Arc<Self> {
        Arc::new(NameMl {
            names: std::sync::Mutex::new(names.iter().map(|s| s.to_string()).collect()),
            score: 0.9,
        })
    }
    pub fn set(&self, names: &[&str]) {
        *self.names.lock().unwrap() = names.iter().map(|s| s.to_string()).collect();
    }
}

impl MlDetector for NameMl {
    fn name(&self) -> &str {
        "names"
    }
    fn detect_batch(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<Detection>>> {
        Ok(texts
            .iter()
            .map(|t| {
                let mut v = Vec::new();
                for n in self.names.lock().unwrap().iter() {
                    for (i, _) in t.match_indices(n.as_str()) {
                        v.push(Detection {
                            span: parda_core::Span::new(i, i + n.len()),
                            kind: parda_core::EntityKind::Person,
                            score: self.score,
                            source: parda_core::Source::Ml,
                        });
                    }
                }
                v
            })
            .collect())
    }
}

/// ML stub returning nonsense spans (out of bounds, reversed, mid-character).
pub struct BadSpanMl;

impl MlDetector for BadSpanMl {
    fn name(&self) -> &str {
        "bad-spans"
    }
    fn detect_batch(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<Detection>>> {
        Ok(texts
            .iter()
            .map(|t| {
                [(0, t.len() + 10), (5, 2), (1, 2), (3, 3)]
                    .into_iter()
                    .map(|(s, e)| Detection {
                        span: parda_core::Span { start: s, end: e },
                        kind: parda_core::EntityKind::Person,
                        score: 0.99,
                        source: parda_core::Source::Ml,
                    })
                    .collect()
            })
            .collect())
    }
}

/// Open an engine over an existing data directory (rules-only unless
/// `config` says otherwise).
pub fn engine_at(dir: &std::path::Path, config: Config, ml: Option<Arc<dyn MlDetector>>) -> Engine {
    Engine::open(
        EngineOptions {
            config,
            rules: rules(),
            data_dir: dir.to_path_buf(),
            use_keyring: false,
        },
        ml,
    )
    .unwrap()
}

/// Shift every vault row's timestamps by `days` (negative: into the past).
pub fn age_vault(dir: &std::path::Path, days: i64) {
    let c = rusqlite::Connection::open(dir.join("vault.db")).unwrap();
    c.execute(
        "UPDATE mappings SET created_at = created_at + ?1, last_used_at = last_used_at + ?1",
        [days * 86_400],
    )
    .unwrap();
}
