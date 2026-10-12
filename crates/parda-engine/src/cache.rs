//! Content-hash LRU cache of per-fragment detections.

use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;
use parda_core::Detection;
use parking_lot::Mutex;

pub(crate) type Key = [u8; 32];

/// Detections are stored relative to the fragment they were found in.
pub(crate) struct DetCache {
    inner: Mutex<LruCache<Key, Arc<Vec<Detection>>>>,
}

impl DetCache {
    pub(crate) fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap_or(NonZeroUsize::MIN);
        DetCache {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    pub(crate) fn get(&self, key: &Key) -> Option<Arc<Vec<Detection>>> {
        self.inner.lock().get(key).cloned()
    }

    pub(crate) fn put(&self, key: Key, dets: Arc<Vec<Detection>>) {
        self.inner.lock().put(key, dets);
    }

    pub(crate) fn clear(&self) {
        self.inner.lock().clear();
    }

    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

/// Cache key: the fragment's BLAKE3 hash, salted with a domain string and the
/// detector configuration epoch so a rules change never serves stale results.
pub(crate) fn key(domain: &str, epoch: u64, fragment: &str) -> Key {
    let mut h = blake3::Hasher::new();
    h.update(domain.as_bytes());
    h.update(&epoch.to_le_bytes());
    h.update(fragment.as_bytes());
    *h.finalize().as_bytes()
}
