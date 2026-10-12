//! Anthropic Messages API: which strings to redact / restore, and the SSE
//! rewriter.
//!
//! `thinking` / `redacted_thinking` blocks are signed and never touched in
//! either direction; unknown block types pass through unchanged.

use serde_json::{Value, json};

use crate::sse::{Restorers, SseEvent, StreamRewriter};
use crate::walk::{Unscanned, Visit, leaves, str_field, type_of};

/// Visit the request's text; returns what had to go unscanned.
pub(crate) fn walk_request(v: &mut Value, f: Visit<'_>) -> Unscanned {
    let mut unscanned = Unscanned::NONE;
    tool_descriptions(v, f);
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

/// `tools[].description` (custom tools; server tools have none).
fn tool_descriptions(v: &mut Value, f: Visit<'_>) {
    if let Some(Value::Array(tools)) = v.get_mut("tools") {
        for t in tools {
            str_field(t, "description", f);
        }
    }
}

#[cfg(test)]
pub(crate) fn count_unscanned(v: &mut Value) -> u32 {
    walk_request(v, &mut |_| {}).total()
}

fn blocks(content: Option<&mut Value>, f: Visit<'_>) -> Unscanned {
    match content {
        Some(Value::String(s)) => {
            f(s);
            Unscanned::NONE
        }
        Some(Value::Array(inner)) => inner.iter_mut().map(|x| request_block(x, f)).sum(),
        _ => Unscanned::NONE,
    }
}

fn request_block(b: &mut Value, f: Visit<'_>) -> Unscanned {
    match type_of(b) {
        "text" => {
            str_field(b, "text", f);
            Unscanned::NONE
        }
        "tool_result" => blocks(b.get_mut("content"), f),
        // Tool calls the model made. Their inputs are restored in answers,
        // so the client's copy holds real values: redact them again.
        "tool_use" | "server_tool_use" | "mcp_tool_use" => {
            if let Some(input) = b.get_mut("input") {
                leaves(input, f);
            }
            Unscanned::NONE
        }
        "document" => {
            str_field(b, "title", f);
            str_field(b, "context", f);
            let source_type = b.get("source").map(type_of).unwrap_or_default().to_string();
            match source_type.as_str() {
                "text" => {
                    if let Some(src) = b.get_mut("source") {
                        str_field(src, "data", f);
                    }
                    Unscanned::NONE
                }
                "content" => blocks(b.get_mut("source").and_then(|s| s.get_mut("content")), f),
                // base64 / url / file: binary or remote documents.
                _ => Unscanned::MEDIA,
            }
        }
        "search_result" => {
            str_field(b, "title", f);
            blocks(b.get_mut("content"), f)
        }
        "image" => Unscanned::MEDIA,
        // Signed reasoning, and results of tools that ran on the provider's
        // side (it produced them, so it already has them): left as is.
        "thinking"
        | "redacted_thinking"
        | "mcp_tool_result"
        | "web_search_tool_result"
        | "web_fetch_tool_result"
        | "code_execution_tool_result"
        | "bash_code_execution_tool_result"
        | "text_editor_code_execution_tool_result"
        | "tool_search_tool_result"
        | "container_upload" => Unscanned::NONE,
        // A type parda does not know: forwarded unscanned, with a warning.
        _ => Unscanned::UNKNOWN,
    }
}

/// Visit the text of a (non-streaming) response.
pub(crate) fn walk_response(v: &mut Value, f: Visit<'_>) {
    if let Some(Value::Array(blocks)) = v.get_mut("content") {
        for b in blocks {
            match type_of(b) {
                "text" => str_field(b, "text", f),
                // Must match the request walker: whatever is restored here
                // comes back in the next request and is redacted there.
                "tool_use" | "server_tool_use" | "mcp_tool_use" => {
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
    /// `text`: `text_delta.text` is restored.
    Text,
    /// A tool call (`tool_use`, `server_tool_use`, `mcp_tool_use`):
    /// `input_json_delta.partial_json` is restored.
    Json,
    /// Anything else (thinking, tool results, future types): untouched.
    Other,
}

impl BlockKind {
    fn of_block(block_type: &str) -> Self {
        match block_type {
            "text" => BlockKind::Text,
            "tool_use" | "server_tool_use" | "mcp_tool_use" => BlockKind::Json,
            _ => BlockKind::Other,
        }
    }
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

    /// Flush one restorer key; the delta type follows the key it was pushed
    /// under, never the block's recorded kind.
    fn flush_key(&mut self, key: &str, out: &mut Vec<SseEvent>) {
        let Some((prefix, index)) = key.split_once(':') else {
            return;
        };
        let Ok(index) = index.parse::<u64>() else {
            return;
        };
        let rest = self.restorers.finish(key);
        if rest.is_empty() {
            return;
        }
        let delta = if prefix == "json" {
            json!({"type": "input_json_delta", "partial_json": rest})
        } else {
            json!({"type": "text_delta", "text": rest})
        };
        let data = json!({"type": "content_block_delta", "index": index, "delta": delta});
        out.push(SseEvent::new(Some("content_block_delta"), data.to_string()));
    }

    fn flush(&mut self, index: u64, out: &mut Vec<SseEvent>) {
        for kind in [BlockKind::Text, BlockKind::Json] {
            self.flush_key(&Self::key(index, kind), out);
        }
    }

    fn flush_all(&mut self, out: &mut Vec<SseEvent>) {
        for key in self.restorers.open_keys() {
            self.flush_key(&key, out);
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
                let kind = BlockKind::of_block(block);
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
                // Only restore deltas of blocks whose type says so (a block
                // never announced is judged by its delta).
                if *self.blocks.entry(index).or_insert(kind) != kind {
                    out.push(ev);
                    return;
                }
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
        // The image, and the unknown future block.
        assert_eq!(count_unscanned(&mut v), 2);
    }

    #[test]
    fn request_walk_covers_titles_contexts_and_tool_descriptions() {
        let mut v = json!({
            "tools": [{"name": "crm", "description": "Look up Ravi", "input_schema": {}},
                      {"type": "web_search_20250305", "name": "web_search"}],
            "messages": [{"role": "user", "content": [
                {"type": "document", "title": "T", "context": "C", "source": {"type": "text", "data": "D"}},
                {"type": "search_result", "title": "ST", "source": "https://x", "content": [{"type": "text", "text": "SR"}]},
                {"type": "mcp_tool_result", "tool_use_id": "m", "content": [{"type": "text", "text": "from server"}]}
            ]}]
        });
        let texts = collect(&mut v, |v, f| {
            walk_request(v, f);
        });
        assert_eq!(texts, ["Look up Ravi", "T", "C", "D", "ST", "SR"]);
    }
}
