//! The pump that rewrites an upstream event stream on its way to the
//! client. The SSE parser and serialiser live in `parda-wire`.

use std::collections::HashMap;

use bytes::Bytes;
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use parda_engine::{Engine, StreamRestorer};
use parda_wire::JsonFragRestorer;
pub use parda_wire::sse::{SseEvent, SseParser, parse_sse, serialize};

/// Per-provider stream rewriting.
pub(crate) trait StreamRewriter: Send {
    fn on_event(&mut self, ev: SseEvent, out: &mut Vec<SseEvent>);
    /// The upstream ended; flush anything held back.
    fn on_end(&mut self, out: &mut Vec<SseEvent>);
}

/// One stream's restorer: plain text, or JSON text (tool-call arguments).
enum KeyRestorer {
    Text(StreamRestorer),
    Json(JsonFragRestorer),
}

/// Stream restorers keyed by content block / choice / output item.
pub(crate) struct Restorers {
    engine: Engine,
    scope: String,
    map: HashMap<String, KeyRestorer>,
    order: Vec<String>,
}

impl Restorers {
    pub(crate) fn new(engine: Engine, scope: &str) -> Self {
        Restorers {
            engine,
            scope: scope.to_string(),
            map: HashMap::new(),
            order: Vec::new(),
        }
    }

    fn entry(&mut self, key: &str, json: bool) -> &mut KeyRestorer {
        if !self.map.contains_key(key) {
            let r = if json {
                KeyRestorer::Json(JsonFragRestorer::new(self.engine.clone(), &self.scope))
            } else {
                KeyRestorer::Text(self.engine.stream_restorer(&self.scope))
            };
            self.map.insert(key.to_string(), r);
            self.order.push(key.to_string());
        }
        self.map.get_mut(key).expect("just inserted")
    }

    /// Restore a chunk of plain text.
    pub(crate) fn push(&mut self, key: &str, text: &str) -> String {
        match self.entry(key, false) {
            KeyRestorer::Text(r) => r.push(text),
            KeyRestorer::Json(r) => r.push(text),
        }
    }

    /// Restore a chunk of a JSON document (real values are JSON-escaped).
    pub(crate) fn push_json(&mut self, key: &str, fragment: &str) -> String {
        match self.entry(key, true) {
            KeyRestorer::Text(r) => r.push(fragment),
            KeyRestorer::Json(r) => r.push(fragment),
        }
    }

    /// Flush and forget one key.
    pub(crate) fn finish(&mut self, key: &str) -> String {
        self.order.retain(|k| k != key);
        match self.map.remove(key) {
            Some(KeyRestorer::Text(mut r)) => r.finish(),
            Some(KeyRestorer::Json(mut r)) => r.finish(),
            None => String::new(),
        }
    }

    /// Keys still open, oldest first.
    pub(crate) fn open_keys(&self) -> Vec<String> {
        self.order.clone()
    }

    pub(crate) fn restore(&self, text: &str) -> String {
        self.engine.restore(text, &self.scope)
    }
}

/// Run the rewriter off the async workers: restoring may wait on the
/// engine's index lock, read the vault (SQLite) or rebuild an automaton.
async fn rewrite(
    mut rw: Box<dyn StreamRewriter>,
    events: Vec<SseEvent>,
    end: bool,
) -> Option<(Box<dyn StreamRewriter>, Vec<SseEvent>)> {
    tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        for ev in events {
            rw.on_event(ev, &mut out);
        }
        if end {
            rw.on_end(&mut out);
        }
        (rw, out)
    })
    .await
    .ok()
}

/// Read the upstream body, rewrite events and send them to the client as
/// soon as they are complete.
pub(crate) async fn pump(
    upstream: reqwest::Response,
    mut rw: Box<dyn StreamRewriter>,
    mut tx: mpsc::Sender<Result<Bytes, std::io::Error>>,
) {
    let mut stream = upstream.bytes_stream();
    let mut parser = SseParser::default();
    let failed = || Err(std::io::Error::other("parda failed to rewrite the stream"));
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(b) => {
                let events = parser.feed(&b);
                if events.is_empty() {
                    continue;
                }
                let Some((back, out)) = rewrite(rw, events, false).await else {
                    let _ = tx.send(failed()).await;
                    return;
                };
                rw = back;
                for ev in out {
                    if tx.send(Ok(serialize(&ev))).await.is_err() {
                        return; // client went away
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "upstream stream failed");
                let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                return;
            }
        }
    }
    let rest: Vec<SseEvent> = parser.finish().into_iter().collect();
    let Some((_, out)) = rewrite(rw, rest, true).await else {
        let _ = tx.send(failed()).await;
        return;
    };
    for ev in out {
        if tx.send(Ok(serialize(&ev))).await.is_err() {
            return;
        }
    }
}
