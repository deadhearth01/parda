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
mod error;
mod guard;
mod openai_chat;
mod openai_responses;
mod route;
mod server;
mod sse;
mod walk;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use parda_core::ProxyConfig;
use parda_engine::Engine;
use serde::Serialize;
use tokio::sync::broadcast;

pub use route::Provider;
pub use server::{SCOPE_HEADER, router, serve, serve_with_shutdown};
pub use sse::{SseEvent, parse_sse, serialize};

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
    /// Images / binary documents forwarded without scanning.
    pub unscanned_media: u32,
    pub status: u16,
    pub streaming: bool,
    /// Protection was switched off: the request went upstream unfiltered.
    pub paused: bool,
    pub error: Option<String>,
}

pub struct ProxyState {
    pub engine: Engine,
    pub cfg: ProxyConfig,
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
            cfg,
            events,
            http,
        }))
    }
}
