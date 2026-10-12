//! Anthropic Messages API: which strings to redact / restore, and the SSE
//! rewriter.
//!
//! `thinking` / `redacted_thinking` blocks are signed and never touched in
//! either direction; unknown block types pass through unchanged.

use serde_json::{Value, json};

use crate::sse::{Restorers, SseEvent, StreamRewriter};
use crate::walk::{Visit, leaves, str_field, type_of};

/// Visit the request's text; returns how many media blocks go unscanned.
pub(crate) fn walk_request(v: &mut Value, f: Visit<'_>) -> u32 {
    let mut unscanned = 0;
    match v.get_mut("system") {
        Some(Value::String(s)) => f(s),
        Some(Value::Array(blocks)) => {
            for b in blocks {
                unscanned += request_block(b, f);
            }
        }
        _ => {}
    }
    if let Some(Value::Array(msgs)) = v.get_mut("messages") {
        for m in msgs {
            match m.get_mut("content") {
                Some(Value::String(s)) => f(s),
                Some(Value::Array(blocks)) => {
                    for b in blocks {
                        unscanned += request_block(b, f);
                    }
                }
                _ => {}
            }
        }
    }
    unscanned
}

#[cfg(test)]
pub(crate) fn count_unscanned(v: &mut Value) -> u32 {
    walk_request(v, &mut |_| {})
}

fn request_block(b: &mut Value, f: Visit<'_>) -> u32 {
    match type_of(b) {
        "text" => {
            str_field(b, "text", f);
            0
        }
        "tool_result" => match b.get_mut("content") {
            Some(Value::String(s)) => {
                f(s);
                0
            }
            Some(Value::Array(inner)) => inner.iter_mut().map(|x| request_block(x, f)).sum(),
            _ => 0,
        },
        "tool_use" => {
            if let Some(input) = b.get_mut("input") {
                leaves(input, f);
            }
            0
        }
        "document" => {
            let source_type = b.get("source").map(type_of).unwrap_or_default().to_string();
            match source_type.as_str() {
                "text" => {
                    if let Some(src) = b.get_mut("source") {
                        str_field(src, "data", f);
                    }
                    0
                }
                "content" => match b.get_mut("source").and_then(|s| s.get_mut("content")) {
                    Some(Value::String(s)) => {
                        f(s);
                        0
                    }
                    Some(Value::Array(inner)) => {
                        inner.iter_mut().map(|x| request_block(x, f)).sum()
                    }
                    _ => 0,
                },
                _ => 1,
            }
        }
        "search_result" => match b.get_mut("content") {
            Some(Value::Array(inner)) => inner.iter_mut().map(|x| request_block(x, f)).sum(),
            _ => 0,
        },
        "image" => 1,
        // thinking, redacted_thinking, server tool blocks, future types.
        _ => 0,
    }
}

/// Visit the text of a (non-streaming) response.
pub(crate) fn walk_response(v: &mut Value, f: Visit<'_>) {
    if let Some(Value::Array(blocks)) = v.get_mut("content") {
        for b in blocks {
            match type_of(b) {
                "text" => str_field(b, "text", f),
                "tool_use" => {
                    if let Some(input) = b.get_mut("input") {
                        leaves(input, f);
                    }
                }
                _ => {}
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    Text,
    Json,
    Other,
}

pub(crate) struct AnthropicStream {
    restorers: Restorers,
    blocks: std::collections::HashMap<u64, BlockKind>,
}

impl AnthropicStream {
    pub(crate) fn new(restorers: Restorers) -> Self {
        AnthropicStream {
            restorers,
            blocks: Default::default(),
        }
    }

    fn key(index: u64, kind: BlockKind) -> String {
        match kind {
            BlockKind::Json => format!("json:{index}"),
            _ => format!("text:{index}"),
        }
    }

    fn flush(&mut self, index: u64, out: &mut Vec<SseEvent>) {
        let kind = self.blocks.get(&index).copied().unwrap_or(BlockKind::Text);
        let rest = self.restorers.finish(&Self::key(index, kind));
        if rest.is_empty() {
            return;
        }
        let delta = match kind {
            BlockKind::Json => json!({"type": "input_json_delta", "partial_json": rest}),
            _ => json!({"type": "text_delta", "text": rest}),
        };
        let data = json!({"type": "content_block_delta", "index": index, "delta": delta});
        out.push(SseEvent::new(Some("content_block_delta"), data.to_string()));
    }

    fn flush_all(&mut self, out: &mut Vec<SseEvent>) {
        let open: Vec<u64> = self
            .restorers
            .open_keys()
            .iter()
            .filter_map(|k| k.split_once(':')?.1.parse().ok())
            .collect();
        for index in open {
            self.flush(index, out);
        }
    }
}

impl StreamRewriter for AnthropicStream {
    fn on_event(&mut self, mut ev: SseEvent, out: &mut Vec<SseEvent>) {
        let Ok(mut v) = serde_json::from_str::<Value>(&ev.data) else {
            out.push(ev);
            return;
        };
        let index = v.get("index").and_then(Value::as_u64).unwrap_or(0);
        match type_of(&v) {
            "content_block_start" => {
                let block = v.get("content_block").map(type_of).unwrap_or_default();
                let kind = match block {
                    "text" => BlockKind::Text,
                    "tool_use" => BlockKind::Json,
                    _ => BlockKind::Other,
                };
                self.blocks.insert(index, kind);
                if kind == BlockKind::Text
                    && let Some(Value::String(t)) =
                        v.get_mut("content_block").and_then(|b| b.get_mut("text"))
                    && !t.is_empty()
                {
                    let key = Self::key(index, kind);
                    *t = self.restorers.push(&key, t);
                    ev.set_data(v.to_string());
                }
                out.push(ev);
            }
            "content_block_delta" => {
                let delta_type = v.get("delta").map(type_of).unwrap_or_default().to_string();
                let (field, kind) = match delta_type.as_str() {
                    "text_delta" => ("text", BlockKind::Text),
                    "input_json_delta" => ("partial_json", BlockKind::Json),
                    // thinking_delta, signature_delta, citations_delta, …
                    _ => {
                        out.push(ev);
                        return;
                    }
                };
                self.blocks.entry(index).or_insert(kind);
                let key = Self::key(index, kind);
                let Some(Value::String(t)) = v.get_mut("delta").and_then(|d| d.get_mut(field))
                else {
                    out.push(ev);
                    return;
                };
                let restored = self.restorers.push(&key, t);
                if restored.is_empty() {
                    return; // everything held back for now
                }
                *t = restored;
                ev.set_data(v.to_string());
                out.push(ev);
            }
            "content_block_stop" => {
                self.flush(index, out);
                out.push(ev);
            }
            "message_delta" | "message_stop" => {
                self.flush_all(out);
                out.push(ev);
            }
            _ => out.push(ev),
        }
    }

    fn on_end(&mut self, out: &mut Vec<SseEvent>) {
        self.flush_all(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walk::collect;

    #[test]
    fn request_walk_covers_text_tools_and_skips_thinking() {
        let mut v = json!({
            "system": [{"type": "text", "text": "S"}],
            "messages": [
                {"role": "user", "content": "U"},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "T", "signature": "sig"},
                    {"type": "tool_use", "id": "1", "name": "n", "input": {"to": "I", "n": 1}},
                    {"type": "future_block", "x": "F"}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "1", "content": [{"type": "text", "text": "R"}]},
                    {"type": "image", "source": {"type": "base64", "data": "AAAA"}},
                    {"type": "document", "source": {"type": "text", "data": "D"}}
                ]}
            ]
        });
        let texts = collect(&mut v, |v, f| {
            walk_request(v, f);
        });
        assert_eq!(texts, ["S", "U", "I", "R", "D"]);
        assert_eq!(count_unscanned(&mut v), 1);
    }
}
