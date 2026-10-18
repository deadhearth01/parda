//! Restoring text that arrives in chunks (SSE deltas).
//!
//! Each push emits as much restored text as is already decided and holds back
//! only the longest tail that could still grow into a surrogate. For any
//! chunking, the concatenated output equals `Engine::restore` of the
//! concatenated input.

use std::sync::Arc;

use crate::engine::Inner;
use crate::restore::{UrlRun, not_url_like};

pub struct StreamRestorer {
    inner: Arc<Inner>,
    scope: String,
    pending: String,
    /// Last character already emitted (for the word-boundary test).
    prev: Option<char>,
    /// Url-safe mode: the URL rule's run state before `pending`.
    url_safe: Option<UrlRun>,
}

impl StreamRestorer {
    pub(crate) fn new(inner: Arc<Inner>, scope: &str) -> Self {
        StreamRestorer {
            inner,
            scope: scope.to_string(),
            pending: String::new(),
            prev: None,
            url_safe: None,
        }
    }

    /// Never restore a surrogate that follows a URL-like run of text (see
    /// [`crate::Engine::restore_url_safe`]).
    pub fn url_safe(mut self) -> Self {
        self.url_safe = Some(UrlRun::default());
        self
    }

    /// Text that went out around this restorer (left as it was): it counts
    /// as context for what comes next. Call it with nothing held back (after
    /// [`StreamRestorer::finish`]).
    pub fn skip(&mut self, text: &str) {
        if let Some(c) = text.chars().next_back() {
            self.prev = Some(c);
        }
        if let Some(run) = &mut self.url_safe {
            run.advance(text);
        }
    }

    /// Feed a chunk; returns the restored text that is safe to emit now.
    pub fn push(&mut self, chunk: &str) -> String {
        self.pending.push_str(chunk);
        let Some(table) = self.inner.table(&self.scope) else {
            return self.emit_all_raw();
        };
        let mut cut = table.hold_start(&self.pending);
        let mut found = table.find(&self.pending, self.prev);
        if let Some(run) = &self.url_safe {
            found = not_url_like(&self.pending, &found, run);
        }
        // Never cut through a complete match.
        if let Some(f) = found.iter().find(|f| f.start < cut && f.end > cut) {
            cut = f.start;
        }
        let out = table.apply_found(&self.pending[..cut], found.iter().filter(|f| f.end <= cut));
        if let Some(c) = self.pending[..cut].chars().next_back() {
            self.prev = Some(c);
        }
        if let Some(run) = &mut self.url_safe {
            run.advance(&self.pending[..cut]);
        }
        self.pending.drain(..cut);
        out
    }

    /// Flush everything still held back.
    pub fn finish(&mut self) -> String {
        let Some(table) = self.inner.table(&self.scope) else {
            return self.emit_all_raw();
        };
        let out = match &mut self.url_safe {
            Some(run) => table.apply_url_safe(&self.pending, self.prev, run),
            None => table.apply(&self.pending, self.prev),
        };
        if let Some(c) = self.pending.chars().next_back() {
            self.prev = Some(c);
        }
        self.pending.clear();
        out
    }

    /// Bytes currently held back.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    fn emit_all_raw(&mut self) -> String {
        if let Some(c) = self.pending.chars().next_back() {
            self.prev = Some(c);
        }
        if let Some(run) = &mut self.url_safe {
            run.advance(&self.pending);
        }
        std::mem::take(&mut self.pending)
    }
}
