//! The engine: detection tiers, policy, surrogate assignment, restore.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parda_core::{
    Action, Config, Detection, EntityKind, MlDetector, Mode, Source, Span, Style, merge,
};
use parda_detect::{AllowList, Detector, DictionaryDetector, RuleDetector, RulesFile};
use parda_vault::surrogate::{SurrogateGen, apply_case, token};
use parda_vault::{Store, load_or_create_key};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;

use crate::cache::{self, DetCache};
use crate::fragment::{DEFAULT_MAX_FRAGMENT_BYTES, split_fragments};
use crate::index::ScopeIndex;
use crate::ml::MlWorker;
use crate::restore::{Entry, RestoreTable, case_insensitive};
use crate::stream::StreamRestorer;

/// Entries in each detection cache (spec: 50k).
const CACHE_CAPACITY: usize = 50_000;
/// The ML budget (`detect.ml_timeout_ms`) is granted per this many bytes of
/// text the model has not seen before, so a long first request is not
/// refused for being long. Capped at [`MAX_ML_BUDGET`].
const ML_BUDGET_UNIT_BYTES: usize = 4096;
const MAX_ML_BUDGET: Duration = Duration::from_secs(30);
/// Surrogate generation attempts before falling back to a typed token.
const MAX_ATTEMPTS: u32 = 64;
/// Vault `last_used_at` is refreshed at most this often per mapping.
const TOUCH_INTERVAL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone)]
pub struct EngineOptions {
    pub config: Config,
    pub rules: RulesFile,
    /// Holds `vault.db` (and `vault.key` without a keyring).
    pub data_dir: PathBuf,
    pub use_keyring: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The ML tier failed or ran out of time in strict mode.
    #[error("ML detector unavailable: {0}")]
    MlUnavailable(String),
    /// The text contains kinds whose action is `block`.
    #[error("blocked by policy: {}", kinds_list(.0))]
    Blocked(Vec<EntityKind>),
    #[error("vault: {0}")]
    Vault(#[from] parda_vault::Error),
    #[error("{0}")]
    Other(String),
}

fn kinds_list(kinds: &[EntityKind]) -> String {
    kinds
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

pub type Result<T, E = EngineError> = std::result::Result<T, E>;

/// One replaced value. The real value is deliberately absent.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Replacement {
    pub kind: EntityKind,
    pub source: Source,
    /// Span of the real value in the input text.
    pub original_span: Span,
    pub surrogate: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Redaction {
    pub text: String,
    pub replaced: Vec<Replacement>,
    /// Kinds found whose action is `block` (non-empty only from `scan`-like
    /// callers; `redact` returns [`EngineError::Blocked`] instead).
    pub blocked: Vec<EntityKind>,
    /// Kinds found whose action is `warn` (left in place).
    pub warned: Vec<EntityKind>,
    pub ml_ms: u64,
    /// The ML tier did not run (fast mode after a failure, or no model).
    pub ml_skipped: bool,
}

impl Redaction {
    /// Replacement counts by kind name.
    pub fn counts(&self) -> BTreeMap<String, u32> {
        let mut m = BTreeMap::new();
        for r in &self.replaced {
            *m.entry(r.kind.to_string()).or_insert(0) += 1;
        }
        m
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct EngineStats {
    pub redactions: u64,
    pub fragments: u64,
    pub cache_hits: u64,
    pub ml_calls: u64,
    pub ml_failures: u64,
    pub ml_skipped: u64,
    pub ml_ms_total: u64,
    pub entities: BTreeMap<String, u64>,
    /// Replacements by the tier that found them: `dictionary`,
    /// `rules (checksum)`, `rules`, `model`.
    pub by_source: BTreeMap<String, u64>,
    pub model: Option<String>,
    pub cache_entries: usize,
}

/// Detector configuration; replaced wholesale on reload.
struct Detectors {
    config: Config,
    rules_file: RulesFile,
    dict: DictionaryDetector,
    rules: RuleDetector,
    allow: AllowList,
    /// Bumped on every reload; part of the detection cache key.
    epoch: u64,
}

impl Detectors {
    fn new(config: Config, rules_file: RulesFile, epoch: u64) -> Self {
        Detectors {
            dict: DictionaryDetector::new(&rules_file),
            rules: RuleDetector::new(&config.detect.packs, config.detect.dates),
            allow: AllowList::new(&rules_file.allow),
            config,
            rules_file,
            epoch,
        }
    }

    fn ml_required(&self) -> bool {
        self.config.detect.model != "none"
    }
}

pub(crate) struct Inner {
    store: Store,
    surrogates: SurrogateGen,
    detectors: RwLock<Arc<Detectors>>,
    indexes: Mutex<HashMap<String, ScopeIndex>>,
    cache: DetCache,
    ml_cache: Arc<DetCache>,
    ml: Option<MlWorker>,
    stats: Mutex<EngineStats>,
    touched: Mutex<HashMap<[u8; 32], Instant>>,
}

/// Cheap to clone; clones share everything.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

impl Engine {
    /// Open the vault under `opts.data_dir` and set up the tiers. `ml` is the
    /// loaded model, if any; with `detect.model != "none"` and no model,
    /// strict mode refuses to redact.
    pub fn open(opts: EngineOptions, ml: Option<Arc<dyn MlDetector>>) -> Result<Engine> {
        create_private_dir(&opts.data_dir)?;
        let (key, _source) = load_or_create_key(&opts.data_dir, opts.use_keyring)?;
        let store = Store::open(&opts.data_dir.join("vault.db"), key)?;
        let pruned = store.prune(opts.config.vault.ttl_days)?;
        if pruned > 0 {
            tracing::info!(pruned, "expired vault mappings removed");
        }
        let ml_cache = Arc::new(DetCache::new(CACHE_CAPACITY));
        let ml = match ml {
            Some(det) => Some(
                MlWorker::spawn(det, ml_cache.clone())
                    .map_err(|e| EngineError::Other(format!("starting ML worker: {e}")))?,
            ),
            None => None,
        };
        let stats = EngineStats {
            model: ml.as_ref().map(|m| m.name().to_string()),
            ..Default::default()
        };
        Ok(Engine {
            inner: Arc::new(Inner {
                store,
                surrogates: SurrogateGen::new(),
                detectors: RwLock::new(Arc::new(Detectors::new(opts.config, opts.rules, 1))),
                indexes: Mutex::new(HashMap::new()),
                cache: DetCache::new(CACHE_CAPACITY),
                ml_cache,
                ml,
                stats: Mutex::new(stats),
                touched: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub fn vault(&self) -> &Store {
        &self.inner.store
    }

    pub fn config(&self) -> Config {
        self.inner.detectors.read().config.clone()
    }

    pub fn rules(&self) -> RulesFile {
        self.inner.detectors.read().rules_file.clone()
    }

    /// Name of the loaded ML model, if any.
    pub fn model_name(&self) -> Option<String> {
        self.inner.ml.as_ref().map(|m| m.name().to_string())
    }

    /// Replace the user dictionary / allow-list. Cached detections are dropped.
    pub fn reload_rules(&self, rules: RulesFile) {
        let mut d = self.inner.detectors.write();
        let next = Detectors::new(d.config.clone(), rules, d.epoch + 1);
        *d = Arc::new(next);
        self.inner.cache.clear();
    }

    /// Apply a new configuration (packs, actions, mode, style, budgets). The
    /// ML model itself is not reloaded.
    pub fn set_config(&self, config: Config) {
        let mut d = self.inner.detectors.write();
        let next = Detectors::new(config, d.rules_file.clone(), d.epoch + 1);
        *d = Arc::new(next);
        self.inner.cache.clear();
    }

    pub fn stats(&self) -> EngineStats {
        let mut s = self.inner.stats.lock().clone();
        s.cache_entries = self.inner.cache.len();
        s
    }

    /// Find entities without replacing anything.
    pub fn scan(&self, text: &str) -> Result<Vec<Detection>> {
        let det = self.inner.detectors.read().clone();
        let (mut per_text, _, _) = self.inner.detect(&det, &[text])?;
        Ok(per_text.pop().unwrap_or_default())
    }

    pub fn redact(&self, text: &str, scope: &str) -> Result<Redaction> {
        let mut v = self.redact_many(&[text], scope)?;
        Ok(v.pop().expect("one result per input"))
    }

    /// Redact several texts (e.g. every string of one API request) with one
    /// ML batch. Fails as a whole if any text holds a blocked kind.
    pub fn redact_many(&self, texts: &[&str], scope: &str) -> Result<Vec<Redaction>> {
        self.inner.redact_many(texts, scope)
    }

    pub fn restore(&self, text: &str, scope: &str) -> String {
        match self.inner.table(scope) {
            Some(t) => t.apply(text, None),
            None => text.to_string(),
        }
    }

    pub fn stream_restorer(&self, scope: &str) -> StreamRestorer {
        StreamRestorer::new(self.inner.clone(), scope)
    }

    /// Drop the in-memory view of a scope (or all) so it is re-read from the
    /// vault; call after wiping the vault.
    pub fn forget_scopes(&self) {
        self.inner.indexes.lock().clear();
    }
}

fn create_private_dir(dir: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(parda_vault::Error::from)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(parda_vault::Error::from)?;
    }
    Ok(())
}

/// Built-in words the model mistakes for people (see `data/not_names.txt`).
struct NotNames {
    words: std::collections::HashSet<String>,
    phrases: std::collections::HashSet<String>,
}

fn not_names() -> &'static NotNames {
    static LIST: std::sync::OnceLock<NotNames> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut words = std::collections::HashSet::new();
        let mut phrases = std::collections::HashSet::new();
        for line in include_str!("../data/not_names.txt").lines() {
            let line = line.split('#').next().unwrap_or("");
            for w in line.split_whitespace() {
                if w.contains('-') {
                    phrases.insert(w.replace('-', " "));
                } else {
                    words.insert(w.to_string());
                }
            }
        }
        NotNames { words, phrases }
    })
}

/// A model Person detection that is only festival / food / place /
/// identifier words ("Aadhaar", "Durga Puja", "Tata Nexon").
fn not_a_name(text: &str, d: &Detection) -> bool {
    if d.source != Source::Ml || d.kind != EntityKind::Person {
        return false;
    }
    let Some(t) = text.get(d.span.start..d.span.end) else {
        return false;
    };
    let lower = t.to_lowercase();
    let words: Vec<&str> = lower
        .split_whitespace()
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|w| !w.is_empty())
        .collect();
    let list = not_names();
    !words.is_empty()
        && (list.phrases.contains(&words.join(" "))
            || words.iter().all(|w| list.words.contains(*w)))
}

/// Human label of a detection tier, for statistics.
pub fn source_label(source: &Source) -> &'static str {
    match source {
        Source::Dictionary => "dictionary",
        Source::Rule { validated: true } => "rules (checksum)",
        Source::Rule { validated: false } => "rules",
        Source::Ml => "model",
    }
}

fn strictly_inside(inner: &Span, outer: &Span) -> bool {
    outer.start <= inner.start && inner.end <= outer.end && outer.len() > inner.len()
}

/// Resolve tier conflicts before the rank-based merge:
///
/// * anything strictly inside a format match (an e-mail, URL, UPI id, …) is
///   part of it: "ravi" inside "ravi.k@gmail.com", or a phone number inside
///   "9876543210@ybl", must not split it;
/// * a model guess never overrides a format match it does not fully cover:
///   the model calling a Voter ID a passport number, or an API key an
///   e-mail, loses to the rule. A model span that strictly contains a rule
///   match (an address around a PIN code) still competes in the merge.
fn absorb_contained(mut dets: Vec<Detection>) -> Vec<Detection> {
    let rules: Vec<(Span, bool)> = dets
        .iter()
        .filter(|d| matches!(d.source, Source::Rule { .. }))
        .map(|d| {
            let structured = !matches!(
                d.kind,
                EntityKind::Person
                    | EntityKind::Address
                    | EntityKind::Organization
                    | EntityKind::Custom(_)
            );
            (d.span, structured)
        })
        .collect();
    dets.retain(|d| {
        if rules
            .iter()
            .any(|(s, structured)| *structured && strictly_inside(&d.span, s))
        {
            return false;
        }
        if d.source == Source::Ml {
            return !rules
                .iter()
                .any(|(s, _)| s.overlaps(&d.span) && !strictly_inside(s, &d.span));
        }
        true
    });
    dets
}

fn token_parts(s: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in s.char_indices() {
        match (c.is_whitespace(), start) {
            (true, Some(st)) => {
                out.push((st, i));
                start = None;
            }
            (false, None) => start = Some(i),
            _ => {}
        }
    }
    if let Some(st) = start {
        out.push((st, s.len()));
    }
    out
}

/// The letters-and-digits core of a token: `"Ravi,"` → `"Ravi"`.
fn core_range(tok: &str) -> (usize, usize) {
    let start = tok.find(|c: char| c.is_alphanumeric()).unwrap_or(tok.len());
    let end = tok
        .char_indices()
        .rev()
        .find(|(_, c)| c.is_alphanumeric())
        .map_or(start, |(i, c)| i + c.len_utf8());
    (start, end.max(start))
}

fn core(tok: &str) -> &str {
    let (a, b) = core_range(tok);
    &tok[a..b]
}

impl Inner {
    pub(crate) fn table(&self, scope: &str) -> Option<Arc<RestoreTable>> {
        let mut indexes = self.indexes.lock();
        let idx = match self.index_mut(&mut indexes, scope) {
            Ok(idx) => idx,
            Err(e) => {
                tracing::error!(error = %e, "cannot read vault for restore");
                return None;
            }
        };
        let t = idx.table();
        (!t.is_empty()).then_some(t)
    }

    fn index_mut<'a>(
        &self,
        indexes: &'a mut HashMap<String, ScopeIndex>,
        scope: &str,
    ) -> Result<&'a mut ScopeIndex> {
        if !indexes.contains_key(scope) {
            let entries = self
                .store
                .reverse_map(scope)?
                .into_iter()
                .map(|(surrogate, real, kind)| Entry {
                    surrogate,
                    real,
                    kind,
                })
                .collect();
            indexes.insert(scope.to_string(), ScopeIndex::from_entries(entries));
        }
        Ok(indexes.get_mut(scope).expect("inserted above"))
    }

    /// Run the tiers over `texts`. Returns per-text detections (merged,
    /// allow-listed, sorted), ML milliseconds and whether ML was skipped.
    fn detect(&self, det: &Detectors, texts: &[&str]) -> Result<(Vec<Vec<Detection>>, u64, bool)> {
        struct Frag<'a> {
            text_idx: usize,
            span: Span,
            body: &'a str,
            key: cache::Key,
        }
        let mut frags = Vec::new();
        for (ti, text) in texts.iter().enumerate() {
            for span in split_fragments(text, DEFAULT_MAX_FRAGMENT_BYTES) {
                let body = &text[span.start..span.end];
                frags.push(Frag {
                    text_idx: ti,
                    span,
                    body,
                    key: cache::key("final", det.epoch, body),
                });
            }
        }

        let mut results: Vec<Option<Arc<Vec<Detection>>>> =
            frags.iter().map(|f| self.cache.get(&f.key)).collect();
        let hits = results.iter().filter(|r| r.is_some()).count() as u64;

        // ML for fragments not in the final cache.
        let ml_required = det.ml_required();
        let strict = det.config.detect.mode == Mode::Strict;
        let mut ml_ms = 0;
        let mut ml_skipped = false;
        let mut ml_dets: HashMap<cache::Key, Arc<Vec<Detection>>> = HashMap::new();
        let misses: Vec<usize> = (0..frags.len()).filter(|&i| results[i].is_none()).collect();
        if ml_required && !misses.is_empty() {
            match &self.ml {
                None => {
                    if strict {
                        return Err(EngineError::MlUnavailable("no model is loaded".into()));
                    }
                    ml_skipped = true;
                }
                Some(worker) => {
                    // Unique fragments that the model has not seen.
                    let mut texts_for_ml = Vec::new();
                    let mut keys_for_ml = Vec::new();
                    for &i in &misses {
                        let mk = cache::key("ml", 0, frags[i].body);
                        if ml_dets.contains_key(&mk) || keys_for_ml.contains(&mk) {
                            continue;
                        }
                        if let Some(d) = self.ml_cache.get(&mk) {
                            ml_dets.insert(mk, d);
                        } else if frags[i].body.chars().any(char::is_alphabetic) {
                            texts_for_ml.push(frags[i].body.to_string());
                            keys_for_ml.push(mk);
                        } else {
                            ml_dets.insert(mk, Arc::new(Vec::new()));
                        }
                    }
                    if !texts_for_ml.is_empty() {
                        let new_bytes: usize = texts_for_ml.iter().map(String::len).sum();
                        let units = new_bytes.div_ceil(ML_BUDGET_UNIT_BYTES).max(1) as u32;
                        let budget = Duration::from_millis(det.config.detect.ml_timeout_ms)
                            .saturating_mul(units)
                            .min(MAX_ML_BUDGET);
                        let started = Instant::now();
                        let res = worker.detect(texts_for_ml, keys_for_ml.clone(), budget);
                        ml_ms = started.elapsed().as_millis() as u64;
                        {
                            let mut s = self.stats.lock();
                            s.ml_calls += 1;
                            s.ml_ms_total += ml_ms;
                        }
                        match res {
                            Ok(d) => {
                                for (k, v) in keys_for_ml.into_iter().zip(d) {
                                    ml_dets.insert(k, Arc::new(v));
                                }
                            }
                            Err(msg) => {
                                self.stats.lock().ml_failures += 1;
                                if strict {
                                    return Err(EngineError::MlUnavailable(msg));
                                }
                                tracing::warn!(error = %msg, "ML tier skipped (fast mode)");
                                ml_skipped = true;
                                ml_dets.clear();
                            }
                        }
                    }
                }
            }
        }
        if ml_skipped {
            self.stats.lock().ml_skipped += 1;
        }

        for &i in &misses {
            let f = &frags[i];
            let mut dets = det.dict.detect(f.body);
            dets.extend(det.rules.detect(f.body));
            let ml_ok = !ml_required || !ml_skipped;
            if ml_required && !ml_skipped {
                let mk = cache::key("ml", 0, f.body);
                if let Some(m) = ml_dets.get(&mk) {
                    dets.extend(m.iter().filter(|d| !not_a_name(f.body, d)).cloned());
                }
            }
            let dets = det.allow.filter(f.body, merge(absorb_contained(dets)));
            let dets = Arc::new(dets);
            if ml_ok {
                self.cache.put(f.key, dets.clone());
            }
            results[i] = Some(dets);
        }

        let mut per_text: Vec<Vec<Detection>> = vec![Vec::new(); texts.len()];
        for (f, r) in frags.iter().zip(results) {
            for d in r.expect("filled above").iter() {
                let mut d = d.clone();
                d.span = d.span.shifted(f.span.start);
                per_text[f.text_idx].push(d);
            }
        }
        {
            let mut s = self.stats.lock();
            s.fragments += frags.len() as u64;
            s.cache_hits += hits;
        }
        Ok((per_text, ml_ms, ml_skipped))
    }

    fn redact_many(&self, texts: &[&str], scope: &str) -> Result<Vec<Redaction>> {
        let det = self.detectors.read().clone();
        let (per_text, ml_ms, ml_skipped) = self.detect(&det, texts)?;

        let mut indexes = self.indexes.lock();
        let idx = self.index_mut(&mut indexes, scope)?;

        // Surrogate-echo guard: a surrogate string already present in the
        // input (a different, undetected value that happens to look like
        // one) gets its own mapping, so restore cannot confuse the two.
        let table = idx.table();
        let mut plans: Vec<(Vec<Detection>, Vec<EntityKind>, Vec<EntityKind>)> = Vec::new();
        let mut blocked_all: Vec<EntityKind> = Vec::new();
        for (text, mut dets) in texts.iter().zip(per_text) {
            if !table.is_empty() {
                for f in table.find(text, None) {
                    let span = Span::new(f.start, f.end);
                    if !dets.iter().any(|d| d.span.overlaps(&span)) {
                        dets.push(Detection {
                            span,
                            kind: table.kind(f.pattern).clone(),
                            score: 1.0,
                            source: Source::Dictionary,
                        });
                    }
                }
                dets.sort_by_key(|d| (d.span.start, d.span.end));
            }
            let mut keep = Vec::with_capacity(dets.len());
            let (mut blocked, mut warned) = (Vec::new(), Vec::new());
            for d in dets {
                match det.config.action_for(&d.kind) {
                    Action::Redact => keep.push(d),
                    Action::Block => {
                        if !blocked.contains(&d.kind) {
                            blocked.push(d.kind.clone());
                        }
                    }
                    Action::Warn => {
                        if !warned.contains(&d.kind) {
                            warned.push(d.kind.clone());
                        }
                    }
                    Action::Ignore => {}
                }
            }
            for k in &blocked {
                if !blocked_all.contains(k) {
                    blocked_all.push(k.clone());
                }
            }
            plans.push((keep, blocked, warned));
        }
        if !blocked_all.is_empty() {
            return Err(EngineError::Blocked(blocked_all));
        }

        let style = det.config.replace.style;
        let mut out = Vec::with_capacity(texts.len());
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut sources: BTreeMap<String, u64> = BTreeMap::new();
        for (text, (dets, blocked, warned)) in texts.iter().zip(plans) {
            let mut new = String::with_capacity(text.len() + 16);
            let mut replaced = Vec::with_capacity(dets.len());
            let mut pos = 0;
            for d in dets {
                let real = &text[d.span.start..d.span.end];
                let sur = self.surrogate_for(idx, scope, &d.kind, real, style)?;
                new.push_str(&text[pos..d.span.start]);
                new.push_str(&sur);
                pos = d.span.end;
                *counts.entry(d.kind.to_string()).or_insert(0) += 1;
                *sources
                    .entry(source_label(&d.source).to_string())
                    .or_insert(0) += 1;
                replaced.push(Replacement {
                    kind: d.kind,
                    source: d.source,
                    original_span: d.span,
                    surrogate: sur,
                });
            }
            new.push_str(&text[pos..]);
            out.push(Redaction {
                text: new,
                replaced,
                blocked,
                warned,
                ml_ms,
                ml_skipped,
            });
        }
        drop(indexes);
        let mut s = self.stats.lock();
        s.redactions += texts.len() as u64;
        for (k, n) in sources {
            *s.by_source.entry(k).or_insert(0) += n;
        }
        for (k, n) in counts {
            *s.entities.entry(k).or_insert(0) += n;
        }
        Ok(out)
    }

    fn seed(&self, scope: &str, kind: &EntityKind, real: &str) -> [u8; 32] {
        let norm = if case_insensitive(kind) {
            real.to_lowercase()
        } else {
            real.to_string()
        };
        self.store
            .seed(format!("{scope}\u{0}{kind}\u{0}{norm}").as_bytes())
    }

    fn touch(&self, scope: &str, real: &str) {
        let mut h = blake3::Hasher::new();
        h.update(scope.as_bytes());
        h.update(&[0]);
        h.update(real.as_bytes());
        let k = *h.finalize().as_bytes();
        let now = Instant::now();
        let mut t = self.touched.lock();
        if t.get(&k)
            .is_some_and(|at| now.duration_since(*at) < TOUCH_INTERVAL)
        {
            return;
        }
        t.insert(k, now);
        drop(t);
        if let Err(e) = self.store.touch(scope, real) {
            tracing::warn!(error = %e, "vault touch failed");
        }
    }

    /// The surrogate for `real`: an existing mapping, else a fresh one that
    /// is stored before it is returned.
    fn surrogate_for(
        &self,
        idx: &mut ScopeIndex,
        scope: &str,
        kind: &EntityKind,
        real: &str,
        style: Style,
    ) -> Result<String> {
        if let Some(e) = idx.exact(real) {
            let s = e.surrogate.clone();
            self.touch(scope, real);
            return Ok(s);
        }
        let ci = case_insensitive(kind);
        let seed = self.seed(scope, kind, real);
        for attempt in 0..MAX_ATTEMPTS {
            let candidate = match style {
                Style::Token => token(kind, idx.next_token_number(kind) + attempt),
                Style::Surrogate => {
                    let variant = (attempt == 0 && ci)
                        .then(|| idx.variant(real))
                        .flatten()
                        .map(|v| apply_case(real, &v.surrogate));
                    match variant {
                        Some(v) => v,
                        None if *kind == EntityKind::Person => {
                            self.person_candidate(idx, real, seed, attempt)
                        }
                        None => self.surrogates.generate(kind, real, seed, attempt),
                    }
                }
            };
            if candidate.is_empty()
                || candidate.eq_ignore_ascii_case(real)
                || idx.conflicts(&candidate, real)
                || (style == Style::Surrogate
                    && *kind == EntityKind::Person
                    && self.person_tokens_conflict(idx, real, &candidate))
            {
                continue;
            }
            match self.store.insert(scope, kind, real, &candidate) {
                Ok(()) => {
                    idx.add(Entry {
                        surrogate: candidate.clone(),
                        real: real.to_string(),
                        kind: kind.clone(),
                    });
                    if style == Style::Surrogate && *kind == EntityKind::Person {
                        self.add_name_parts(idx, scope, real, &candidate);
                    }
                    return Ok(candidate);
                }
                Err(parda_vault::Error::SurrogateTaken) => continue,
                Err(parda_vault::Error::AlreadyMapped) => {
                    if let Some(s) = self.store.get_surrogate(scope, real)? {
                        idx.add(Entry {
                            surrogate: s.clone(),
                            real: real.to_string(),
                            kind: kind.clone(),
                        });
                        return Ok(s);
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        // Give up on realistic stand-ins; a numbered token never collides.
        for extra in 0..MAX_ATTEMPTS {
            let candidate = token(kind, idx.next_token_number(kind) + extra);
            if idx.conflicts(&candidate, real) {
                continue;
            }
            match self.store.insert(scope, kind, real, &candidate) {
                Ok(()) => {
                    idx.add(Entry {
                        surrogate: candidate.clone(),
                        real: real.to_string(),
                        kind: kind.clone(),
                    });
                    return Ok(candidate);
                }
                Err(parda_vault::Error::SurrogateTaken) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(EngineError::Other("could not allocate a surrogate".into()))
    }

    /// A generated name, with every word whose real counterpart already has
    /// a mapping replaced by that mapping (so "Ravi" stays "Arjun" in
    /// "Ravi Kumar" and "Ravi Verma").
    fn person_candidate(
        &self,
        idx: &ScopeIndex,
        real: &str,
        seed: [u8; 32],
        attempt: u32,
    ) -> String {
        let base = self
            .surrogates
            .generate(&EntityKind::Person, real, seed, attempt);
        let rt = token_parts(real);
        let st = token_parts(&base);
        if rt.len() != st.len() || rt.len() < 2 {
            return base;
        }
        let mut out = String::with_capacity(base.len());
        let mut pos = 0;
        for (&(ra, rb), &(sa, sb)) in rt.iter().zip(&st) {
            let r_core = core(&real[ra..rb]);
            let s_tok = &base[sa..sb];
            out.push_str(&base[pos..sa]);
            let mapped = (r_core.chars().count() >= 3)
                .then(|| idx.exact(r_core).or_else(|| idx.variant(r_core)))
                .flatten()
                .filter(|e| {
                    e.kind == EntityKind::Person && !e.surrogate.contains(char::is_whitespace)
                });
            match mapped {
                Some(e) => {
                    let (ca, cb) = core_range(s_tok);
                    out.push_str(&s_tok[..ca]);
                    out.push_str(&apply_case(r_core, &e.surrogate));
                    out.push_str(&s_tok[cb..]);
                }
                None => out.push_str(s_tok),
            }
            pos = sb;
        }
        out.push_str(&base[pos..]);
        out
    }

    /// Does any new word of the candidate clash with an existing mapping?
    fn person_tokens_conflict(&self, idx: &ScopeIndex, real: &str, candidate: &str) -> bool {
        let rt = token_parts(real);
        let st = token_parts(candidate);
        if rt.len() != st.len() {
            return false;
        }
        rt.iter().zip(&st).any(|(&(ra, rb), &(sa, sb))| {
            let r = core(&real[ra..rb]);
            let s = core(&candidate[sa..sb]);
            s.chars().count() >= 3 && !s.eq_ignore_ascii_case(r) && idx.conflicts(s, r)
        })
    }

    /// Register each name word as its own mapping ("Ravi" → "Arjun") so a
    /// model mentioning only the first or last name still restores.
    fn add_name_parts(&self, idx: &mut ScopeIndex, scope: &str, real: &str, sur: &str) {
        let rt = token_parts(real);
        let st = token_parts(sur);
        if rt.len() < 2 || rt.len() != st.len() {
            return;
        }
        for (&(ra, rb), &(sa, sb)) in rt.iter().zip(&st) {
            let r = core(&real[ra..rb]);
            let s = core(&sur[sa..sb]);
            if r.chars().count() < 3
                || s.chars().count() < 3
                || s.eq_ignore_ascii_case(r)
                || idx.variant(r).is_some()
                || idx.conflicts(s, r)
            {
                continue;
            }
            match self.store.insert(scope, &EntityKind::Person, r, s) {
                Ok(()) => idx.add(Entry {
                    surrogate: s.to_string(),
                    real: r.to_string(),
                    kind: EntityKind::Person,
                }),
                Err(e) => tracing::debug!(error = %e, "name part mapping skipped"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_parts_and_core() {
        assert_eq!(
            token_parts(" Dr.  Ravi Kumar,"),
            vec![(1, 4), (6, 10), (11, 17)]
        );
        assert_eq!(core("Kumar,"), "Kumar");
        assert_eq!(core("(R.)"), "R");
        assert_eq!(core("..."), "");
    }

    #[test]
    fn absorb_drops_name_inside_email() {
        let dets = vec![
            Detection {
                span: Span::new(0, 4),
                kind: EntityKind::Person,
                score: 1.0,
                source: Source::Dictionary,
            },
            Detection {
                span: Span::new(0, 16),
                kind: EntityKind::Email,
                score: 0.9,
                source: Source::Rule { validated: false },
            },
        ];
        let out = merge(absorb_contained(dets));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, EntityKind::Email);
    }

    fn d(s: usize, e: usize, kind: EntityKind, source: Source) -> Detection {
        Detection {
            span: Span::new(s, e),
            kind,
            score: 0.9,
            source,
        }
    }

    #[test]
    fn model_person_guesses_on_common_words_are_dropped() {
        let t = "Aadhaar card for Durga Puja, Durga Prasad, Tata Nexon, Jaipur";
        let at = |w: &str| {
            let s = t.find(w).unwrap();
            d(s, s + w.len(), EntityKind::Person, Source::Ml)
        };
        assert!(not_a_name(t, &at("Aadhaar")));
        assert!(not_a_name(t, &at("Durga Puja")));
        assert!(not_a_name(t, &at("Tata Nexon")));
        assert!(not_a_name(t, &at("Jaipur")));
        assert!(!not_a_name(t, &at("Durga Prasad")));
        // Words that are also names are never on the list (a miss is a leak).
        let t2 = "Ask Claude, Pan and Ola";
        for w in ["Claude", "Pan", "Ola"] {
            let s = t2.find(w).unwrap();
            assert!(!not_a_name(t2, &d(s, s + w.len(), EntityKind::Person, Source::Ml)), "{w}");
        }
        // Only model guesses are filtered; the user's dictionary always wins.
        let mut dict = at("Jaipur");
        dict.source = Source::Dictionary;
        assert!(!not_a_name(t, &dict));
    }

    #[test]
    fn longer_format_match_wins_over_validated_inner_match() {
        // "9876543210@ybl": a validated phone inside an (unvalidated) UPI id.
        let out = merge(absorb_contained(vec![
            d(0, 10, EntityKind::Phone, Source::Rule { validated: true }),
            d(0, 14, EntityKind::Upi, Source::Rule { validated: false }),
        ]));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, EntityKind::Upi);
    }

    #[test]
    fn model_does_not_relabel_a_format_match() {
        let out = merge(absorb_contained(vec![
            d(7, 17, EntityKind::Passport, Source::Ml),
            d(
                7,
                17,
                EntityKind::VoterId,
                Source::Rule { validated: false },
            ),
        ]));
        assert_eq!(out[0].kind, EntityKind::VoterId);
        // …but a model address that covers a PIN code still wins.
        let out = merge(absorb_contained(vec![
            d(0, 40, EntityKind::Address, Source::Ml),
            d(
                34,
                40,
                EntityKind::Custom("Pin".into()),
                Source::Rule { validated: false },
            ),
        ]));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, EntityKind::Address);
    }
}
