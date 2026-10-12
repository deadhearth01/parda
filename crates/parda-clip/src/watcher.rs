//! The clipboard service: change detection, restore-on-copy, scan-on-copy
//! and paste-safe, plus the background thread that drives it.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crossbeam_channel::{RecvTimeoutError, Sender};
use parda_core::{ClipboardConfig, EntityKind};
use parda_engine::{Engine, EngineError};
use serde::Serialize;

use crate::paste::{EnigoPaster, Paster};

pub trait ClipboardBackend: Send {
    /// Current text, or `None` for empty / non-text content.
    fn get_text(&mut self) -> Option<String>;
    fn set_text(&mut self, s: &str) -> anyhow::Result<()>;
}

pub struct ArboardBackend(arboard::Clipboard);

impl ArboardBackend {
    pub fn new() -> anyhow::Result<Self> {
        Ok(ArboardBackend(arboard::Clipboard::new().map_err(|e| {
            anyhow::anyhow!("clipboard unavailable: {e}")
        })?))
    }
}

impl ClipboardBackend for ArboardBackend {
    fn get_text(&mut self) -> Option<String> {
        self.0.get_text().ok()
    }

    fn set_text(&mut self, s: &str) -> anyhow::Result<()> {
        self.0
            .set_text(s.to_string())
            .map_err(|e| anyhow::anyhow!("cannot write the clipboard: {e}"))
    }
}

/// What happened, for the event feed. Never carries clipboard text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ClipEvent {
    /// New clipboard text holds personal data.
    Scanned { counts: BTreeMap<String, u32> },
    /// Surrogates on the clipboard were swapped for real values.
    Restored,
    /// A redacted version was pasted and the original put back.
    Pasted { counts: BTreeMap<String, u32> },
    /// Nothing to redact; the original was pasted.
    PastedOriginal,
    /// Protection is switched off; the original was pasted unfiltered.
    PastedUnfiltered,
    /// The keystroke failed; the redacted text stays on the clipboard.
    PasteFailed { reason: String },
    /// Paste refused: the text holds blocked kinds.
    Blocked { kinds: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum PasteOutcome {
    PastedRedacted {
        replaced: usize,
    },
    PastedOriginal,
    /// Paste could not be synthesised: the redacted text is on the
    /// clipboard for the user to paste by hand.
    LeftOnClipboard {
        reason: String,
    },
}

fn hash(s: &str) -> [u8; 32] {
    *blake3::hash(s.as_bytes()).as_bytes()
}

fn counts_of(kinds: impl Iterator<Item = EntityKind>) -> BTreeMap<String, u32> {
    let mut m = BTreeMap::new();
    for k in kinds {
        *m.entry(k.to_string()).or_insert(0) += 1;
    }
    m
}

pub struct ClipService<B, P> {
    engine: Engine,
    cfg: ClipboardConfig,
    backend: B,
    paster: P,
    on_event: Box<dyn Fn(ClipEvent) + Send>,
    last: Option<[u8; 32]>,
    /// Hashes of text parda itself wrote, so it is not re-processed.
    own: VecDeque<[u8; 32]>,
    settle: Duration,
    restore_delay: Duration,
}

impl<B: ClipboardBackend, P: Paster> ClipService<B, P> {
    pub fn new(
        engine: Engine,
        cfg: ClipboardConfig,
        backend: B,
        paster: P,
        on_event: Box<dyn Fn(ClipEvent) + Send>,
    ) -> Self {
        ClipService {
            engine,
            cfg,
            backend,
            paster,
            on_event,
            last: None,
            own: VecDeque::new(),
            settle: Duration::from_millis(80),
            restore_delay: Duration::from_millis(400),
        }
    }

    /// Pauses around the synthetic paste (tests use zero).
    pub fn with_delays(mut self, settle: Duration, restore_delay: Duration) -> Self {
        self.settle = settle;
        self.restore_delay = restore_delay;
        self
    }

    fn wrote(&mut self, text: &str) {
        let h = hash(text);
        self.own.push_back(h);
        if self.own.len() > 8 {
            self.own.pop_front();
        }
        self.last = Some(h);
    }

    fn write(&mut self, text: &str) -> anyhow::Result<()> {
        self.backend.set_text(text)?;
        self.wrote(text);
        Ok(())
    }

    /// One poll: react to new clipboard text.
    pub fn tick(&mut self) {
        let Some(text) = self.backend.get_text() else {
            return;
        };
        if text.is_empty() {
            return;
        }
        let h = hash(&text);
        if self.last == Some(h) {
            return;
        }
        self.last = Some(h);
        if self.own.contains(&h) {
            return;
        }
        if self.cfg.restore_on_copy {
            let restored = self.engine.restore(&text, &self.cfg.scope);
            if restored != text {
                match self.write(&restored) {
                    Ok(()) => (self.on_event)(ClipEvent::Restored),
                    Err(e) => tracing::warn!(error = %e, "restore-on-copy failed"),
                }
                return;
            }
        }
        match self.engine.scan(&text) {
            Ok(dets) if !dets.is_empty() => (self.on_event)(ClipEvent::Scanned {
                counts: counts_of(dets.into_iter().map(|d| d.kind)),
            }),
            Ok(_) => {}
            Err(e) => tracing::debug!(error = %e, "clipboard scan failed"),
        }
    }

    /// Paste a redacted version of the clipboard into the focused app.
    pub fn paste_safe(&mut self) -> anyhow::Result<PasteOutcome> {
        let original = self
            .backend
            .get_text()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| anyhow::anyhow!("the clipboard holds no text"))?;
        let red = match self.engine.redact(&original, &self.cfg.scope) {
            Ok(r) => r,
            Err(EngineError::Blocked(kinds)) => {
                let kinds: Vec<String> = kinds.iter().map(ToString::to_string).collect();
                (self.on_event)(ClipEvent::Blocked {
                    kinds: kinds.clone(),
                });
                anyhow::bail!("paste blocked by policy (contains: {})", kinds.join(", "));
            }
            Err(e) => return Err(e.into()),
        };
        if red.paused {
            self.paster.paste()?;
            (self.on_event)(ClipEvent::PastedUnfiltered);
            return Ok(PasteOutcome::PastedOriginal);
        }
        if red.replaced.is_empty() {
            self.paster.paste()?;
            (self.on_event)(ClipEvent::PastedOriginal);
            return Ok(PasteOutcome::PastedOriginal);
        }
        self.write(&red.text)?;
        std::thread::sleep(self.settle);
        if let Err(e) = self.paster.paste() {
            let reason = e.to_string();
            (self.on_event)(ClipEvent::PasteFailed {
                reason: reason.clone(),
            });
            return Ok(PasteOutcome::LeftOnClipboard { reason });
        }
        std::thread::sleep(self.restore_delay);
        self.write(&original)?;
        let counts = counts_of(red.replaced.iter().map(|r| r.kind.clone()));
        (self.on_event)(ClipEvent::Pasted { counts });
        Ok(PasteOutcome::PastedRedacted {
            replaced: red.replaced.len(),
        })
    }
}

type PasteReply = Sender<Result<PasteOutcome, String>>;

/// Control handle for the clipboard thread.
#[derive(Clone)]
pub struct ClipHandle {
    tx: Sender<PasteReply>,
    stop: Arc<AtomicBool>,
}

impl ClipHandle {
    /// Run paste-safe on the clipboard thread and wait for the outcome.
    pub fn paste_safe(&self) -> anyhow::Result<PasteOutcome> {
        let (reply, rx) = crossbeam_channel::bounded(1);
        self.tx
            .send(reply)
            .map_err(|_| anyhow::anyhow!("the clipboard service has stopped"))?;
        rx.recv_timeout(Duration::from_secs(15))
            .map_err(|_| anyhow::anyhow!("the clipboard service did not answer"))?
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

/// Start the clipboard thread (system clipboard, real keystrokes).
pub fn spawn(
    engine: Engine,
    cfg: ClipboardConfig,
    on_event: Box<dyn Fn(ClipEvent) + Send>,
) -> anyhow::Result<ClipHandle> {
    let (tx, rx) = crossbeam_channel::unbounded::<PasteReply>();
    let stop = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = crossbeam_channel::bounded::<Result<(), String>>(1);
    let poll = Duration::from_millis(cfg.poll_ms.max(50));
    let stop2 = stop.clone();
    std::thread::Builder::new()
        .name("parda-clipboard".into())
        .spawn(move || {
            // The clipboard handle is created on the thread that uses it.
            let backend = match ArboardBackend::new() {
                Ok(b) => {
                    let _ = ready_tx.send(Ok(()));
                    b
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e.to_string()));
                    return;
                }
            };
            let mut svc = ClipService::new(engine, cfg, backend, EnigoPaster, on_event);
            while !stop2.load(Ordering::SeqCst) {
                match rx.recv_timeout(poll) {
                    Ok(reply) => {
                        let _ = reply.send(svc.paste_safe().map_err(|e| e.to_string()));
                    }
                    Err(RecvTimeoutError::Timeout) => svc.tick(),
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        })?;
    match ready_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(())) => Ok(ClipHandle { tx, stop }),
        Ok(Err(e)) => anyhow::bail!(e),
        Err(_) => anyhow::bail!("the clipboard did not initialise"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use parda_core::Config;
    use parda_detect::{PersonBlock, RulesFile};
    use parda_engine::EngineOptions;

    #[derive(Clone, Default)]
    struct Shared {
        clip: Arc<Mutex<Option<String>>>,
        pasted: Arc<Mutex<Vec<Option<String>>>>,
        events: Arc<Mutex<Vec<ClipEvent>>>,
    }

    struct FakeClip(Shared);
    impl ClipboardBackend for FakeClip {
        fn get_text(&mut self) -> Option<String> {
            self.0.clip.lock().unwrap().clone()
        }
        fn set_text(&mut self, s: &str) -> anyhow::Result<()> {
            *self.0.clip.lock().unwrap() = Some(s.to_string());
            Ok(())
        }
    }

    struct FakePaster(Shared, bool);
    impl Paster for FakePaster {
        fn paste(&mut self) -> anyhow::Result<()> {
            if self.1 {
                anyhow::bail!("no accessibility permission");
            }
            let now = self.0.clip.lock().unwrap().clone();
            self.0.pasted.lock().unwrap().push(now);
            Ok(())
        }
    }

    fn service(
        fail_paste: bool,
    ) -> (
        tempfile::TempDir,
        Engine,
        Shared,
        ClipService<FakeClip, FakePaster>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.detect.model = "none".into();
        let engine = Engine::open(
            EngineOptions {
                config: config.clone(),
                rules: RulesFile {
                    person: vec![PersonBlock {
                        name: "Ravi Kumar".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                data_dir: dir.path().to_path_buf(),
                use_keyring: false,
            },
            None,
        )
        .unwrap();
        let shared = Shared::default();
        let ev = shared.events.clone();
        let svc = ClipService::new(
            engine.clone(),
            config.clipboard,
            FakeClip(shared.clone()),
            FakePaster(shared.clone(), fail_paste),
            Box::new(move |e| ev.lock().unwrap().push(e)),
        )
        .with_delays(Duration::ZERO, Duration::ZERO);
        (dir, engine, shared, svc)
    }

    fn set(shared: &Shared, s: &str) {
        *shared.clip.lock().unwrap() = Some(s.to_string());
    }

    #[test]
    fn paste_safe_pastes_redacted_then_restores_original() {
        let (_d, _e, shared, mut svc) = service(false);
        set(&shared, "Call Ravi Kumar");
        let out = svc.paste_safe().unwrap();
        assert_eq!(out, PasteOutcome::PastedRedacted { replaced: 1 });
        let pasted = shared.pasted.lock().unwrap().clone();
        assert_eq!(pasted.len(), 1);
        let p = pasted[0].clone().unwrap();
        assert!(p.starts_with("Call ") && !p.contains("Ravi"), "{p}");
        assert_eq!(
            shared.clip.lock().unwrap().as_deref(),
            Some("Call Ravi Kumar")
        );
        assert!(matches!(
            shared.events.lock().unwrap().last(),
            Some(ClipEvent::Pasted { .. })
        ));
    }

    #[test]
    fn restore_on_copy_replaces_surrogates() {
        let (_d, engine, shared, mut svc) = service(false);
        let sur = engine.redact("Ravi Kumar", "global").unwrap().text;
        set(&shared, &format!("Thanks {sur}!"));
        svc.tick();
        assert_eq!(
            shared.clip.lock().unwrap().as_deref(),
            Some("Thanks Ravi Kumar!")
        );
        assert_eq!(
            shared.events.lock().unwrap().as_slice(),
            &[ClipEvent::Restored]
        );
        // The restored text is parda's own write: not processed again.
        svc.tick();
        assert_eq!(shared.events.lock().unwrap().len(), 1);
    }

    #[test]
    fn self_writes_ignored() {
        let (_d, _e, shared, mut svc) = service(false);
        set(&shared, "Call Ravi Kumar");
        svc.tick();
        let scanned = |s: &Shared| {
            s.events
                .lock()
                .unwrap()
                .iter()
                .filter(|e| matches!(e, ClipEvent::Scanned { .. }))
                .count()
        };
        assert_eq!(scanned(&shared), 1);
        svc.paste_safe().unwrap();
        svc.tick();
        svc.tick();
        assert_eq!(scanned(&shared), 1);
        // A genuinely new copy is processed.
        set(&shared, "mail ravi.k@gmail.com");
        svc.tick();
        assert_eq!(scanned(&shared), 2);
    }

    #[test]
    fn nothing_to_redact_pastes_original() {
        let (_d, _e, shared, mut svc) = service(false);
        set(&shared, "hello world");
        assert_eq!(svc.paste_safe().unwrap(), PasteOutcome::PastedOriginal);
        assert_eq!(
            shared.pasted.lock().unwrap().as_slice(),
            &[Some("hello world".to_string())]
        );
    }

    #[test]
    fn non_text_clipboard_ignored() {
        let (_d, _e, shared, mut svc) = service(false);
        svc.tick();
        assert!(shared.events.lock().unwrap().is_empty());
        assert!(svc.paste_safe().is_err());
    }

    #[test]
    fn failed_keystroke_leaves_redacted_text() {
        let (_d, _e, shared, mut svc) = service(true);
        set(&shared, "Call Ravi Kumar");
        let out = svc.paste_safe().unwrap();
        assert!(matches!(out, PasteOutcome::LeftOnClipboard { .. }));
        let now = shared.clip.lock().unwrap().clone().unwrap();
        assert!(!now.contains("Ravi"), "{now}");
    }
}
