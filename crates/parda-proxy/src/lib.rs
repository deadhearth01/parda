//! The agent proxy: a loopback HTTP server that sits between AI agents / SDKs
//! and the Anthropic or OpenAI APIs. Request text is redacted before it is
//! forwarded; answers (JSON or SSE streams) get real values back.
//!
//! ```text
//! client ──► guard (Host / Origin) ──► route ──► redact JSON text ──► upstream
//! client ◄── restore JSON / rewrite SSE deltas ◄────────────────────── upstream
//! ```
//!
//! Point clients at it with `ANTHROPIC_BASE_URL=http://127.0.0.1:8787` or
//! `OPENAI_BASE_URL=http://127.0.0.1:8787/v1`. Credentials pass through
//! untouched and are never stored.

mod anthropic;
mod body;
mod error;
mod guard;
mod jsonfrag;
mod legacy;
mod openai_chat;
mod openai_responses;
mod route;
mod server;
mod sse;
mod walk;

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use parda_core::ProxyConfig;
use parda_engine::Engine;
use serde::Serialize;
use tokio::sync::broadcast;

pub use route::{Provider, normalize_path};
pub use server::{SCOPE_HEADER, bind, router, serve, serve_with_shutdown};
pub use sse::{SseEvent, SseParser, parse_sse, serialize};

/// One proxied request, for the event feed. Never holds raw values.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProxyEvent {
    pub provider: &'static str,
    pub path: String,
    /// Replacements by kind in the request.
    pub counts: BTreeMap<String, u32>,
    pub ml_ms: u64,
    /// Time parda itself added (redaction + restore of a JSON body).
    pub added_ms: u64,
    /// Images / binary documents / token ids forwarded without scanning.
    pub unscanned_media: u32,
    /// Blocks, parts or items of a type parda does not know, forwarded
    /// without scanning (a warning).
    pub unknown_parts: u32,
    pub status: u16,
    pub streaming: bool,
    /// Protection was switched off: the request went upstream unfiltered.
    pub paused: bool,
    pub error: Option<String>,
}

/// Distinct vault scopes (`x-parda-scope`) one proxy accepts: each one
/// keeps an in-memory restore index for the life of the daemon.
pub const MAX_SCOPES: usize = 256;

pub struct ProxyState {
    pub engine: Engine,
    cfg: RwLock<Arc<ProxyConfig>>,
    scopes: Mutex<HashSet<String>>,
    pub events: broadcast::Sender<ProxyEvent>,
    pub http: reqwest::Client,
}

impl ProxyState {
    /// State with a default upstream HTTP client.
    pub fn new(
        engine: Engine,
        cfg: ProxyConfig,
        events: broadcast::Sender<ProxyEvent>,
    ) -> anyhow::Result<Arc<Self>> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(90))
            .user_agent(concat!("parda/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Arc::new(ProxyState {
            engine,
            cfg: RwLock::new(Arc::new(cfg)),
            scopes: Mutex::new(HashSet::new()),
            events,
            http,
        }))
    }

    /// The settings in force; each request uses one snapshot.
    pub fn config(&self) -> Arc<ProxyConfig> {
        self.cfg.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Admit a scope unless [`MAX_SCOPES`] others are already in use.
    pub(crate) fn admit_scope(&self, scope: &str) -> bool {
        let mut seen = self.scopes.lock().unwrap_or_else(|e| e.into_inner());
        if seen.contains(scope) {
            return true;
        }
        if seen.len() >= MAX_SCOPES {
            return false;
        }
        seen.insert(scope.to_string());
        true
    }

    /// Apply new settings to the running proxy. `listen` and `enabled` only
    /// take effect on restart; everything else applies to the next request.
    pub fn set_config(&self, cfg: ProxyConfig) {
        *self.cfg.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(cfg);
    }
}
