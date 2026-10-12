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
