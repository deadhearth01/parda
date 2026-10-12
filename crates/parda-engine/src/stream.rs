//! Restoring text that arrives in chunks (SSE deltas).
//!
//! Each push emits as much restored text as is already decided and holds back
//! only the longest tail that could still grow into a surrogate. For any
//! chunking, the concatenated output equals `Engine::restore` of the
//! concatenated input.

use std::sync::Arc;

use crate::engine::Inner;

pub struct StreamRestorer {
    inner: Arc<Inner>,
    scope: String,
    pending: String,
    /// Last character already emitted (for the word-boundary test).
    prev: Option<char>,
}

impl StreamRestorer {
    pub(crate) fn new(inner: Arc<Inner>, scope: &str) -> Self {
        StreamRestorer {
            inner,
            scope: scope.to_string(),
            pending: String::new(),
            prev: None,
        }
    }

    /// Feed a chunk; returns the restored text that is safe to emit now.
    pub fn push(&mut self, chunk: &str) -> String {
        self.pending.push_str(chunk);
        let Some(table) = self.inner.table(&self.scope) else {
            return self.emit_all_raw();
        };
        let mut cut = table.hold_start(&self.pending);
        let found = table.find(&self.pending, self.prev);
        // Never cut through a complete match.
        if let Some(f) = found.iter().find(|f| f.start < cut && f.end > cut) {
            cut = f.start;
        }
        let out = table.apply_found(&self.pending[..cut], found.iter().filter(|f| f.end <= cut));
        if let Some(c) = self.pending[..cut].chars().next_back() {
            self.prev = Some(c);
        }
        self.pending.drain(..cut);
        out
    }

    /// Flush everything still held back.
    pub fn finish(&mut self) -> String {
        let Some(table) = self.inner.table(&self.scope) else {
            return self.emit_all_raw();
        };
        let out = table.apply(&self.pending, self.prev);
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
        std::mem::take(&mut self.pending)
    }
}
