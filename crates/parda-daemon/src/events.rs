//! Turning proxy and clipboard happenings into IPC events for the TUI.

use parda_clip::ClipEvent;
use parda_ipc::Event;
use parda_proxy::ProxyEvent;

pub fn from_proxy(ev: &ProxyEvent) -> Event {
    let total: u32 = ev.counts.values().sum();
    let mut summary = format!("{} {} → {}", ev.provider, ev.path, ev.status);
    match &ev.error {
        Some(code) => summary.push_str(&format!(" ({code})")),
        None => {
            summary.push_str(&format!(" · {total} redacted"));
            if ev.unscanned_media > 0 {
                summary.push_str(&format!(" · {} unscanned media", ev.unscanned_media));
            }
            if ev.streaming {
                summary.push_str(" · stream");
            }
        }
    }
    let mut e = Event::now("proxy", summary);
    e.counts = ev.counts.clone();
    e.latency_ms = Some(ev.added_ms);
    if ev.error.is_some() || ev.status >= 400 {
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
    fn proxy_summary() {
        let ev = ProxyEvent {
            provider: "anthropic",
            path: "/v1/messages".into(),
            counts: BTreeMap::from([("Person".into(), 2), ("Email".into(), 1)]),
            ml_ms: 12,
            added_ms: 15,
            unscanned_media: 1,
            status: 200,
            streaming: true,
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
    }
}
