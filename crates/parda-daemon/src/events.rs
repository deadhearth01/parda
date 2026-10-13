//! Turning proxy and clipboard happenings into IPC events for the TUI, and
//! keeping running totals of them for `parda status` and the dashboard.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use parda_clip::ClipEvent;
use parda_ipc::Event;
use parda_proxy::ProxyEvent;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;

/// Latency samples kept for percentiles.
const LATENCY_SAMPLES: usize = 2000;
/// Recent events kept for clients that connect later (no values in them).
const RECENT_EVENTS: usize = 200;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SurfaceStats {
    /// Events (requests, pastes, copies, CLI calls).
    pub events: u64,
    /// Values replaced.
    pub redacted: u64,
    /// Warnings and errors.
    pub warnings: u64,
    /// Replacements by kind on this surface.
    pub kinds: BTreeMap<String, u64>,
}

#[derive(Default)]
struct ActivityInner {
    surfaces: BTreeMap<String, SurfaceStats>,
    latencies: VecDeque<u64>,
    recent: VecDeque<Event>,
    last_event_ms: Option<u64>,
}

/// Running totals per surface (proxy, clipboard, cli) since the daemon
/// started. Values are never recorded, only kinds and counts.
#[derive(Default)]
pub struct Activity {
    inner: Mutex<ActivityInner>,
}

fn percentile(sorted: &[u64], p: f64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let i = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted.get(i).copied()
}

impl Activity {
    pub fn record(&self, e: &Event) {
        let mut a = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let s = a.surfaces.entry(e.surface.clone()).or_default();
        s.events += 1;
        for (k, n) in &e.counts {
            s.redacted += u64::from(*n);
            *s.kinds.entry(k.clone()).or_insert(0) += u64::from(*n);
        }
        if e.level != "info" {
            s.warnings += 1;
        }
        if let Some(ms) = e.latency_ms {
            a.latencies.push_back(ms);
            while a.latencies.len() > LATENCY_SAMPLES {
                a.latencies.pop_front();
            }
        }
        a.recent.push_back(e.clone());
        while a.recent.len() > RECENT_EVENTS {
            a.recent.pop_front();
        }
        a.last_event_ms = Some(e.ts_ms);
    }

    pub fn snapshot(&self) -> Value {
        let a = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut lat: Vec<u64> = a.latencies.iter().copied().collect();
        lat.sort_unstable();
        json!({
            "surfaces": a.surfaces,
            "redacted_total": a.surfaces.values().map(|s| s.redacted).sum::<u64>(),
            "latency_ms": {
                "samples": lat.len(),
                "p50": percentile(&lat, 0.5),
                "p95": percentile(&lat, 0.95),
                "max": lat.last(),
            },
            "last_event_ms": a.last_event_ms,
            "recent": a.recent,
        })
    }
}

/// Record an event and broadcast it to subscribers.
pub fn emit(tx: &broadcast::Sender<Event>, activity: &Activity, e: Event) {
    activity.record(&e);
    let _ = tx.send(e);
}

pub fn from_proxy(ev: &ProxyEvent) -> Event {
    let total: u32 = ev.counts.values().sum();
    let mut summary = format!("{} {} → {}", ev.provider, ev.path, ev.status);
    match &ev.error {
        Some(code) => summary.push_str(&format!(" ({code})")),
        None if ev.paused => summary.push_str(" · PAUSED, sent unfiltered"),
        None => {
            summary.push_str(&format!(" · {total} redacted"));
            if ev.unscanned_media > 0 {
                summary.push_str(&format!(" · {} unscanned media", ev.unscanned_media));
            }
            if ev.unknown_parts > 0 {
                summary.push_str(&format!(
                    " · {} part(s) of unknown type sent unscanned",
                    ev.unknown_parts
                ));
            }
            if ev.streaming {
                summary.push_str(" · stream");
            }
        }
    }
    if ev.passthrough {
        summary.push_str(" · passed through unfiltered (proxy.passthrough_paths)");
    }
    let mut e = Event::now("proxy", summary);
    e.counts = ev.counts.clone();
    e.latency_ms = Some(ev.added_ms);
    if ev.error.is_some() || ev.status >= 400 || ev.paused || ev.passthrough || ev.unknown_parts > 0
    {
        e.level = "warn".into();
    }
    e
}

pub fn from_clip(ev: &ClipEvent) -> Event {
    let (summary, counts, warn) = match ev {
        ClipEvent::Scanned { counts } => (
            format!(
                "copied text holds {} sensitive value(s)",
                counts.values().sum::<u32>()
            ),
            counts.clone(),
            false,
        ),
        ClipEvent::Restored => (
            "restored real values on the clipboard".to_string(),
            Default::default(),
            false,
        ),
        ClipEvent::Pasted { counts } => (
            format!(
                "pasted with {} value(s) redacted",
                counts.values().sum::<u32>()
            ),
            counts.clone(),
            false,
        ),
        ClipEvent::PastedOriginal => (
            "pasted (nothing to redact)".to_string(),
            Default::default(),
            false,
        ),
        ClipEvent::PastedUnfiltered => (
            "PAUSED — pasted unfiltered (protection is off)".to_string(),
            Default::default(),
            true,
        ),
        ClipEvent::PasteFailed { reason } => (
            format!(
                "paste keystroke failed — redacted text is on the clipboard, paste manually ({reason})"
            ),
            Default::default(),
            true,
        ),
        ClipEvent::Blocked { kinds } => (
            format!("paste blocked by policy ({})", kinds.join(", ")),
            Default::default(),
            true,
        ),
        ClipEvent::OriginalNotRestored { reason } => (
            format!(
                "pasted, but the original could not be put back — the redacted text is still \
                 on the clipboard ({reason})"
            ),
            Default::default(),
            true,
        ),
    };
    let mut e = Event::now("clipboard", summary);
    e.counts = counts;
    if warn {
        e.level = "warn".into();
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn activity_totals_and_percentiles() {
        let a = Activity::default();
        for ms in [5u64, 7, 9, 100] {
            let mut e = Event::now("proxy", "x");
            e.counts.insert("Person".into(), 2);
            e.latency_ms = Some(ms);
            a.record(&e);
        }
        let mut w = Event::now("clipboard", "y");
        w.level = "warn".into();
        a.record(&w);
        let s = a.snapshot();
        assert_eq!(s["surfaces"]["proxy"]["events"], 4);
        assert_eq!(s["surfaces"]["proxy"]["redacted"], 8);
        assert_eq!(s["surfaces"]["proxy"]["kinds"]["Person"], 8);
        assert_eq!(s["surfaces"]["clipboard"]["warnings"], 1);
        assert_eq!(s["redacted_total"], 8);
        assert_eq!(s["latency_ms"]["p50"], 9);
        assert_eq!(s["latency_ms"]["max"], 100);
        assert_eq!(s["recent"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn proxy_summary() {
        let ev = ProxyEvent {
            provider: "anthropic",
            path: "/v1/messages".into(),
            counts: BTreeMap::from([("Person".into(), 2), ("Email".into(), 1)]),
            ml_ms: 12,
            added_ms: 15,
            unscanned_media: 1,
            unknown_parts: 0,
            status: 200,
            streaming: true,
            paused: false,
            passthrough: false,
            error: None,
        };
        let e = from_proxy(&ev);
        assert_eq!(e.surface, "proxy");
        assert_eq!(
            e.summary,
            "anthropic /v1/messages → 200 · 3 redacted · 1 unscanned media · stream"
        );
        assert_eq!(e.latency_ms, Some(15));
        assert_eq!(e.level, "info");
        let unknown = from_proxy(&ProxyEvent {
            unknown_parts: 2,
            ..ev.clone()
        });
        assert!(
            unknown
                .summary
                .contains("2 part(s) of unknown type sent unscanned")
        );
        assert_eq!(unknown.level, "warn");
        let passed = from_proxy(&ProxyEvent {
            passthrough: true,
            counts: BTreeMap::new(),
            ..ev.clone()
        });
        assert!(
            passed
                .summary
                .contains("passed through unfiltered (proxy.passthrough_paths)"),
            "{}",
            passed.summary
        );
        assert_eq!(passed.level, "warn");
        let paused = from_proxy(&ProxyEvent {
            paused: true,
            counts: BTreeMap::new(),
            ..ev
        });
        assert!(paused.summary.contains("PAUSED"), "{}", paused.summary);
        assert_eq!(paused.level, "warn");
    }
}
