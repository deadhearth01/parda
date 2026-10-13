//! The clipboard service: change detection, restore-on-copy, scan-on-copy
//! and paste-safe, plus the background thread that drives it.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
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
    /// After a paste, the original text could not be put back on the
    /// clipboard: the redacted version is still there.
    OriginalNotRestored { reason: String },
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
    /// A paste-safe request older than this is never pasted: the user has
    /// likely moved on to another window.
    max_age: Duration,
}

/// How long paste-safe may take from the hotkey to the keystroke.
pub const PASTE_MAX_AGE: Duration = Duration::from_secs(2);
/// How long the redacted text stays on the clipboard after the keystroke,
/// so a slow target app reads it rather than the original.
pub const RESTORE_DELAY: Duration = Duration::from_millis(1000);

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
            restore_delay: RESTORE_DELAY,
            max_age: PASTE_MAX_AGE,
        }
    }

    /// Apply new clipboard settings (`restore_on_copy`, `scope`, `poll_ms`).
    pub fn set_config(&mut self, cfg: ClipboardConfig) {
        self.cfg = cfg;
    }

    pub fn config(&self) -> &ClipboardConfig {
        &self.cfg
    }

    /// Pauses around the synthetic paste (tests use zero).
    pub fn with_delays(mut self, settle: Duration, restore_delay: Duration) -> Self {
        self.settle = settle;
        self.restore_delay = restore_delay;
        self
    }

    /// Oldest paste-safe request still pasted (default [`PASTE_MAX_AGE`]).
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
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
        self.paste_safe_at(Instant::now())
    }

    fn expired(&self, requested: Instant) -> bool {
        requested.elapsed() > self.max_age
    }

    /// Paste-safe for a request made at `requested`: if the keystroke could
    /// not be sent within `max_age`, nothing is pasted.
    fn paste_safe_at(&mut self, requested: Instant) -> anyhow::Result<PasteOutcome> {
        if self.expired(requested) {
            anyhow::bail!("paste-safe request expired before it could run; press the hotkey again");
        }
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
        if red.paused || red.replaced.is_empty() {
            // Nothing changes on the clipboard: never paste into whatever
            // window has the focus by now.
            if self.expired(requested) {
                anyhow::bail!("paste-safe took too long; nothing was pasted");
            }
            self.paster.paste()?;
            (self.on_event)(if red.paused {
                ClipEvent::PastedUnfiltered
            } else {
                ClipEvent::PastedOriginal
            });
            return Ok(PasteOutcome::PastedOriginal);
        }
        self.write(&red.text)?;
        std::thread::sleep(self.settle);
        if self.expired(requested) {
            let reason = "paste-safe took too long, so nothing was pasted; the redacted text \
                          is on the clipboard: paste it yourself"
                .to_string();
            (self.on_event)(ClipEvent::PasteFailed {
                reason: reason.clone(),
            });
            return Ok(PasteOutcome::LeftOnClipboard { reason });
        }
        if let Err(e) = self.paster.paste() {
            let reason = e.to_string();
            (self.on_event)(ClipEvent::PasteFailed {
                reason: reason.clone(),
            });
            return Ok(PasteOutcome::LeftOnClipboard { reason });
        }
        std::thread::sleep(self.restore_delay);
        self.put_back(&original, &red.text);
        let counts = counts_of(red.replaced.iter().map(|r| r.kind.clone()));
        (self.on_event)(ClipEvent::Pasted { counts });
        Ok(PasteOutcome::PastedRedacted {
            replaced: red.replaced.len(),
        })
    }

    /// Put the original back unless the user copied something else since.
    fn put_back(&mut self, original: &str, redacted: &str) {
        if self.backend.get_text().as_deref() != Some(redacted) {
            return;
        }
        let mut last = None;
        for _ in 0..2 {
            match self.write(original) {
                Ok(()) => return,
                Err(e) => {
                    last = Some(e);
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        let reason = last.map(|e| e.to_string()).unwrap_or_default();
        tracing::warn!(error = %reason, "could not put the original back on the clipboard");
        (self.on_event)(ClipEvent::OriginalNotRestored { reason });
    }
}

type PasteReply = Sender<Result<PasteOutcome, String>>;

/// A paste-safe request, stamped when the user asked for it.
struct PasteRequest {
    reply: PasteReply,
    at: Instant,
}

/// A request for the clipboard thread.
enum Msg {
    Paste(PasteRequest),
    Config(ClipboardConfig),
}

impl<B: ClipboardBackend, P: Paster> ClipService<B, P> {
    fn handle(&mut self, msg: Msg) {
        match msg {
            Msg::Paste(req) => {
                let _ = req
                    .reply
                    .send(self.paste_safe_at(req.at).map_err(|e| e.to_string()));
            }
            Msg::Config(cfg) => self.set_config(cfg),
        }
    }

    /// Handle `first`; paste requests that piled up behind it (repeated
    /// presses while busy) are answered without pasting again.
    fn process(&mut self, first: Msg, queue: &Receiver<Msg>) {
        let pasting = matches!(first, Msg::Paste(_));
        self.handle(first);
        if !pasting {
            return;
        }
        while let Ok(next) = queue.try_recv() {
            match next {
                Msg::Paste(req) => {
                    let _ = req.reply.send(Err(
                        "ignored: paste-safe was pressed again while it was running".into(),
                    ));
                }
                other => self.handle(other),
            }
        }
    }
}

/// Control handle for the clipboard thread.
#[derive(Clone)]
pub struct ClipHandle {
    tx: Sender<Msg>,
    stop: Arc<AtomicBool>,
}

impl ClipHandle {
    /// Run paste-safe on the clipboard thread and wait for the outcome.
    pub fn paste_safe(&self) -> anyhow::Result<PasteOutcome> {
        let (reply, rx) = crossbeam_channel::bounded(1);
        self.tx
            .send(Msg::Paste(PasteRequest {
                reply,
                at: Instant::now(),
            }))
            .map_err(|_| anyhow::anyhow!("the clipboard service has stopped"))?;
        rx.recv_timeout(Duration::from_secs(15))
            .map_err(|_| anyhow::anyhow!("the clipboard service did not answer"))?
            .map_err(|e| anyhow::anyhow!(e))
    }

    /// Apply new settings to the running clipboard service (`enabled` and
    /// `hotkey` need a restart).
    pub fn set_config(&self, cfg: ClipboardConfig) {
        let _ = self.tx.send(Msg::Config(cfg));
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
    let (tx, rx) = crossbeam_channel::unbounded::<Msg>();
    let stop = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = crossbeam_channel::bounded::<Result<(), String>>(1);
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
                let poll = Duration::from_millis(svc.config().poll_ms.max(50));
                match rx.recv_timeout(poll) {
                    Ok(msg) => svc.process(msg, &rx),
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
        /// Writes after this many succeed fail.
        writes_ok: Arc<Mutex<Option<usize>>>,
        writes: Arc<Mutex<usize>>,
        /// The user copies this while the paste is happening.
        copy_during_paste: Arc<Mutex<Option<String>>>,
    }

    struct FakeClip(Shared);
    impl ClipboardBackend for FakeClip {
        fn get_text(&mut self) -> Option<String> {
            self.0.clip.lock().unwrap().clone()
        }
        fn set_text(&mut self, s: &str) -> anyhow::Result<()> {
            let mut n = self.0.writes.lock().unwrap();
            *n += 1;
            if self.0.writes_ok.lock().unwrap().is_some_and(|ok| *n > ok) {
                anyhow::bail!("clipboard is locked by another app");
            }
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
            if let Some(copy) = self.0.copy_during_paste.lock().unwrap().clone() {
                *self.0.clip.lock().unwrap() = Some(copy);
            }
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
    fn settings_apply_to_the_running_service() {
        let (_d, engine, shared, mut svc) = service(false);
        let sur = engine.redact("Ravi Kumar", "global").unwrap().text;
        let mut cfg = svc.config().clone();
        cfg.restore_on_copy = false;
        svc.handle(Msg::Config(cfg));
        set(&shared, &format!("Thanks {sur}!"));
        svc.tick();
        assert_eq!(
            shared.clip.lock().unwrap().as_deref(),
            Some(format!("Thanks {sur}!").as_str())
        );
    }

    #[test]
    fn a_new_copy_during_the_paste_is_not_overwritten() {
        let (_d, _e, shared, mut svc) = service(false);
        set(&shared, "Call Ravi Kumar");
        *shared.copy_during_paste.lock().unwrap() = Some("something new".into());
        svc.paste_safe().unwrap();
        assert_eq!(
            shared.clip.lock().unwrap().as_deref(),
            Some("something new")
        );
    }

    fn req(
        at: Instant,
    ) -> (
        Msg,
        crossbeam_channel::Receiver<Result<PasteOutcome, String>>,
    ) {
        let (reply, rx) = crossbeam_channel::bounded(1);
        (Msg::Paste(PasteRequest { reply, at }), rx)
    }

    #[test]
    fn stale_paste_requests_are_dropped() {
        let (_d, _e, shared, mut svc) = service(false);
        set(&shared, "Call Ravi Kumar");
        let (msg, rx) = req(Instant::now() - Duration::from_secs(5));
        let (_tx, queue) = crossbeam_channel::unbounded();
        svc.process(msg, &queue);
        let err = rx.recv().unwrap().unwrap_err();
        assert!(err.contains("expired"), "{err}");
        assert!(shared.pasted.lock().unwrap().is_empty());
        assert_eq!(
            shared.clip.lock().unwrap().as_deref(),
            Some("Call Ravi Kumar")
        );
    }

    #[test]
    fn queued_repeats_are_coalesced() {
        let (_d, _e, shared, mut svc) = service(false);
        set(&shared, "Call Ravi Kumar");
        let (tx, queue) = crossbeam_channel::unbounded();
        let (first, rx1) = req(Instant::now());
        let (second, rx2) = req(Instant::now());
        let (third, rx3) = req(Instant::now());
        tx.send(second).unwrap();
        tx.send(third).unwrap();
        svc.process(first, &queue);
        assert!(rx1.recv().unwrap().is_ok());
        assert!(rx2.recv().unwrap().is_err());
        assert!(rx3.recv().unwrap().is_err());
        assert_eq!(shared.pasted.lock().unwrap().len(), 1);
    }

    #[test]
    fn deadline_is_rechecked_right_before_the_keystroke() {
        let (_d, _e, shared, svc) = service(false);
        let mut svc = svc
            .with_delays(Duration::from_millis(120), Duration::ZERO)
            .with_max_age(Duration::from_millis(50));
        set(&shared, "Call Ravi Kumar");
        let (msg, rx) = req(Instant::now());
        let (_tx, queue) = crossbeam_channel::unbounded();
        svc.process(msg, &queue);
        let out = rx.recv().unwrap().unwrap();
        assert!(
            matches!(out, PasteOutcome::LeftOnClipboard { .. }),
            "{out:?}"
        );
        assert!(shared.pasted.lock().unwrap().is_empty());
        let now = shared.clip.lock().unwrap().clone().unwrap();
        assert!(!now.contains("Ravi"), "{now}");
    }

    #[test]
    fn failing_to_put_the_original_back_is_reported() {
        let (_d, _e, shared, mut svc) = service(false);
        set(&shared, "Call Ravi Kumar");
        // The redacted text is written; putting the original back fails.
        *shared.writes_ok.lock().unwrap() = Some(1);
        let out = svc.paste_safe().unwrap();
        assert_eq!(out, PasteOutcome::PastedRedacted { replaced: 1 });
        assert!(
            shared
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, ClipEvent::OriginalNotRestored { .. }))
        );
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
