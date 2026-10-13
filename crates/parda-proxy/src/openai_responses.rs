//! OpenAI Responses API: request/response walkers and the SSE rewriter.

use std::collections::HashMap;

use serde_json::{Map, Value, json};

use crate::sse::{Restorers, SseEvent, StreamRewriter};
use crate::walk::{Unscanned, Visit, json_string, str_field, type_of};

pub(crate) fn walk_request(v: &mut Value, f: Visit<'_>) -> Unscanned {
    let mut unscanned = Unscanned::NONE;
    if let Some(Value::Array(tools)) = v.get_mut("tools") {
        for t in tools {
            str_field(t, "description", f);
        }
    }
    if let Some(Value::Object(vars)) = v.get_mut("prompt").and_then(|p| p.get_mut("variables")) {
        for var in vars.values_mut() {
            unscanned += match var {
                Value::String(s) => {
                    f(s);
                    Unscanned::NONE
                }
                part => content_part(part, f),
            };
        }
    }
    unscanned += items(v.get_mut("instructions"), f);
    unscanned += items(v.get_mut("input"), f);
    unscanned
}

/// `instructions` / `input`: a string or a list of input items.
fn items(v: Option<&mut Value>, f: Visit<'_>) -> Unscanned {
    match v {
        Some(Value::String(s)) => {
            f(s);
            Unscanned::NONE
        }
        Some(Value::Array(items)) => items.iter_mut().map(|item| input_item(item, f)).sum(),
        _ => Unscanned::NONE,
    }
}

/// `POST /v1/conversations` and `POST /v1/conversations/{id}/items`: the
/// `items` are Responses input items.
pub(crate) fn walk_conversation_request(v: &mut Value, f: Visit<'_>) -> Unscanned {
    items(v.get_mut("items"), f)
}

#[cfg(test)]
pub(crate) fn count_unscanned(v: &mut Value) -> u32 {
    walk_request(v, &mut |_| {}).total()
}

fn content_part(p: &mut Value, f: Visit<'_>) -> Unscanned {
    match type_of(p) {
        "input_text" | "output_text" | "text" => {
            str_field(p, "text", f);
            Unscanned::NONE
        }
        "refusal" => {
            str_field(p, "refusal", f);
            Unscanned::NONE
        }
        "input_image" | "input_file" | "input_audio" | "computer_screenshot" => Unscanned::MEDIA,
        _ => Unscanned::UNKNOWN,
    }
}

fn content_parts(content: &mut Value, f: Visit<'_>) -> Unscanned {
    match content {
        Value::String(s) => {
            f(s);
            Unscanned::NONE
        }
        Value::Array(parts) => parts.iter_mut().map(|p| content_part(p, f)).sum(),
        Value::Null => Unscanned::NONE,
        _ => Unscanned::UNKNOWN,
    }
}

fn input_item(item: &mut Value, f: Visit<'_>) -> Unscanned {
    let ty = type_of(item).to_string();
    match ty.as_str() {
        "message" | "" if item.get("content").is_some() => item
            .get_mut("content")
            .map_or(Unscanned::NONE, |c| content_parts(c, f)),
        "function_call" => {
            if let Some(Value::String(a)) = item.get_mut("arguments") {
                json_string(a, f);
            }
            Unscanned::NONE
        }
        "function_call_output" | "custom_tool_call_output" => item
            .get_mut("output")
            .map_or(Unscanned::NONE, |o| content_parts(o, f)),
        "custom_tool_call" => {
            str_field(item, "input", f);
            Unscanned::NONE
        }
        "local_shell_call_output" | "apply_patch_call_output" => {
            str_field(item, "output", f);
            Unscanned::NONE
        }
        "shell_call_output" => {
            match item.get_mut("output") {
                Some(Value::Array(chunks)) => {
                    for c in chunks {
                        str_field(c, "stdout", f);
                        str_field(c, "stderr", f);
                    }
                }
                Some(Value::String(s)) => f(s),
                _ => {}
            }
            Unscanned::NONE
        }
        "mcp_call" => {
            if let Some(Value::String(a)) = item.get_mut("arguments") {
                json_string(a, f);
            }
            str_field(item, "output", f);
            str_field(item, "error", f);
            Unscanned::NONE
        }
        "mcp_approval_response" => {
            str_field(item, "reason", f);
            Unscanned::NONE
        }
        "computer_call_output" => Unscanned::MEDIA,
        // Encrypted reasoning, references, and calls / results of tools the
        // provider ran itself (it produced them): untouched.
        "reasoning"
        | "item_reference"
        | "compaction"
        | "web_search_call"
        | "file_search_call"
        | "image_generation_call"
        | "code_interpreter_call"
        | "computer_call"
        | "local_shell_call"
        | "shell_call"
        | "apply_patch_call"
        | "mcp_list_tools"
        | "mcp_approval_request" => Unscanned::NONE,
        // A type parda does not know: forwarded unscanned, with a warning.
        _ => Unscanned::UNKNOWN,
    }
}

/// Visit the text of a response object (also used for `response.completed`).
pub(crate) fn walk_response(v: &mut Value, f: Visit<'_>) {
    str_field(v, "output_text", f);
    if let Some(Value::Array(items)) = v.get_mut("output") {
        for item in items {
            output_item(item, f);
        }
    }
}

fn output_item(item: &mut Value, f: Visit<'_>) {
    match type_of(item) {
        "message" => {
            if let Some(Value::Array(parts)) = item.get_mut("content") {
                for p in parts {
                    match type_of(p) {
                        "output_text" => str_field(p, "text", f),
                        "refusal" => str_field(p, "refusal", f),
                        _ => {}
                    }
                }
            }
        }
        "function_call" => {
            if let Some(Value::String(a)) = item.get_mut("arguments") {
                json_string(a, f);
            }
        }
        "custom_tool_call" => str_field(item, "input", f),
        _ => {}
    }
}

pub(crate) struct ResponsesStream {
    restorers: Restorers,
    /// item_id / output_index / content_index of each open restorer key,
    /// for synthetic deltas flushed after the item's own events.
    meta: HashMap<String, Map<String, Value>>,
    /// Next `sequence_number` to send: events are renumbered so synthetic
    /// deltas and held-back ones leave neither duplicates nor gaps.
    next_seq: Option<u64>,
}

/// The streamed fields parda restores, by restorer key prefix.
const DELTAS: [(&str, &str); 4] = [
    ("text:", "response.output_text.delta"),
    ("args:", "response.function_call_arguments.delta"),
    ("custom:", "response.custom_tool_call_input.delta"),
    ("refusal:", "response.refusal.delta"),
];

impl ResponsesStream {
    pub(crate) fn new(restorers: Restorers) -> Self {
        ResponsesStream {
            restorers,
            meta: HashMap::new(),
            next_seq: None,
        }
    }

    fn id(v: &Value) -> &str {
        v.get("item_id").and_then(Value::as_str).unwrap_or("")
    }

    fn content_index(v: &Value) -> u64 {
        v.get("content_index").and_then(Value::as_u64).unwrap_or(0)
    }

    /// The restorer key for a delta / done event, and whether it is JSON.
    fn key_of(ty: &str, v: &Value) -> Option<(String, bool)> {
        let key = match ty {
            "response.output_text.delta" | "response.output_text.done" => {
                format!("text:{}:{}", Self::id(v), Self::content_index(v))
            }
            "response.function_call_arguments.delta" | "response.function_call_arguments.done" => {
                return Some((format!("args:{}", Self::id(v)), true));
            }
            "response.custom_tool_call_input.delta" | "response.custom_tool_call_input.done" => {
                format!("custom:{}", Self::id(v))
            }
            "response.refusal.delta" | "response.refusal.done" => {
                format!("refusal:{}:{}", Self::id(v), Self::content_index(v))
            }
            _ => return None,
        };
        Some((key, false))
    }

    fn delta_type(key: &str) -> &'static str {
        DELTAS
            .iter()
            .find(|(prefix, _)| key.starts_with(prefix))
            .map_or("response.output_text.delta", |(_, t)| t)
    }

    /// A synthetic delta carrying the held-back text of `key`.
    fn flush(&mut self, key: &str, out: &mut Vec<SseEvent>) {
        let meta = self.meta.remove(key).unwrap_or_default();
        let rest = self.restorers.finish(key);
        if rest.is_empty() {
            return;
        }
        let delta_type = Self::delta_type(key);
        let mut d = meta;
        d.insert("type".into(), json!(delta_type));
        d.insert("delta".into(), json!(rest));
        // Renumbered by `emit`.
        d.insert("sequence_number".into(), json!(0));
        self.emit(
            SseEvent::new(Some(delta_type), Value::Object(d).to_string()),
            out,
        );
    }

    fn flush_all(&mut self, out: &mut Vec<SseEvent>) {
        for key in self.restorers.open_keys() {
            self.flush(&key, out);
        }
    }

    /// Send an event, renumbering its `sequence_number`.
    fn emit(&mut self, mut ev: SseEvent, out: &mut Vec<SseEvent>) {
        if let Ok(mut v) = serde_json::from_str::<Value>(&ev.data)
            && let Some(n) = v.get("sequence_number").and_then(Value::as_u64)
        {
            let next = *self.next_seq.get_or_insert(n);
            if n != next {
                v["sequence_number"] = json!(next);
                ev.set_data(v.to_string());
            }
            self.next_seq = Some(next + 1);
        }
        out.push(ev);
    }

    fn restore_all(&self, v: &mut Value, walk: impl Fn(&mut Value, Visit<'_>)) {
        let r = &self.restorers;
        walk(v, &mut |s: &mut String| *s = r.restore(s));
    }
}

impl StreamRewriter for ResponsesStream {
    fn on_event(&mut self, mut ev: SseEvent, out: &mut Vec<SseEvent>) {
        let Ok(mut v) = serde_json::from_str::<Value>(&ev.data) else {
            out.push(ev);
            return;
        };
        let ty = type_of(&v).to_string();
        match ty.as_str() {
            "response.output_text.delta"
            | "response.function_call_arguments.delta"
            | "response.custom_tool_call_input.delta"
            | "response.refusal.delta" => {
                let Some((key, json_mode)) = Self::key_of(&ty, &v) else {
                    self.emit(ev, out);
                    return;
                };
                self.meta.entry(key.clone()).or_insert_with(|| {
                    ["item_id", "output_index", "content_index"]
                        .into_iter()
                        .filter_map(|k| Some((k.to_string(), v.get(k)?.clone())))
                        .collect()
                });
                if let Some(Value::String(d)) = v.get_mut("delta") {
                    let restored = if json_mode {
                        self.restorers.push_json(&key, d)
                    } else {
                        self.restorers.push(&key, d)
                    };
                    if restored.is_empty() {
                        return; // held back; `emit` keeps the numbering dense
                    }
                    *d = restored;
                    ev.set_data(v.to_string());
                }
            }
            "response.output_text.done"
            | "response.function_call_arguments.done"
            | "response.custom_tool_call_input.done"
            | "response.refusal.done" => {
                if let Some((key, _)) = Self::key_of(&ty, &v) {
                    self.flush(&key, out);
                }
                self.restore_all(&mut v, |v, f| match type_of(v) {
                    "response.output_text.done" => str_field(v, "text", f),
                    "response.custom_tool_call_input.done" => str_field(v, "input", f),
                    "response.refusal.done" => str_field(v, "refusal", f),
                    _ => {
                        if let Some(Value::String(a)) = v.get_mut("arguments") {
                            json_string(a, f);
                        }
                    }
                });
                ev.set_data(v.to_string());
            }
            "response.content_part.done" => {
                self.restore_all(&mut v, |v, f| {
                    if let Some(p) = v.get_mut("part") {
                        str_field(p, "text", f);
                        str_field(p, "refusal", f);
                    }
                });
                ev.set_data(v.to_string());
            }
            "response.output_item.done" => {
                self.restore_all(&mut v, |v, f| {
                    if let Some(item) = v.get_mut("item") {
                        output_item(item, f);
                    }
                });
                ev.set_data(v.to_string());
            }
            "response.completed" | "response.incomplete" | "response.failed" => {
                self.flush_all(out);
                self.restore_all(&mut v, |v, f| {
                    if let Some(r) = v.get_mut("response") {
                        walk_response(r, f);
                    }
                });
                ev.set_data(v.to_string());
            }
            _ => {}
        }
        self.emit(ev, out);
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
    fn request_walk() {
        let mut v = json!({
            "instructions": "I",
            "input": [
                {"role": "user", "content": "U"},
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "T"}, {"type": "input_image", "image_url": "x"}]},
                {"type": "function_call", "call_id": "c", "name": "n", "arguments": "{\"q\":\"A\"}"},
                {"type": "function_call_output", "call_id": "c", "output": "O"},
                {"type": "reasoning", "encrypted_content": "E"}
            ]
        });
        let texts = collect(&mut v, |v, f| {
            walk_request(v, f);
        });
        assert_eq!(texts, ["I", "U", "T", "A", "O"]);
        assert_eq!(count_unscanned(&mut v), 1);
        let mut s = json!({"input": "plain"});
        assert_eq!(
            collect(&mut s, |v, f| {
                walk_request(v, f);
            }),
            ["plain"]
        );
    }

    #[test]
    fn request_walk_covers_tool_outputs_prompt_variables_and_tools() {
        let mut v = json!({
            "tools": [{"type": "function", "name": "f", "description": "FD", "parameters": {}}],
            "prompt": {"id": "p", "variables": {"name": "PV", "doc": {"type": "input_text", "text": "PT"},
                       "pic": {"type": "input_image", "image_url": "x"}}},
            "input": [
                {"type": "local_shell_call_output", "call_id": "1", "output": "LS"},
                {"type": "shell_call_output", "call_id": "2", "output": [{"stdout": "SO", "stderr": "SE", "outcome": {"type": "exit", "exit_code": 0}}]},
                {"type": "apply_patch_call_output", "call_id": "3", "status": "completed", "output": "AP"},
                {"type": "mcp_call", "id": "4", "server_label": "s", "name": "n", "arguments": "{\"q\":\"MA\"}", "output": "MO"},
                {"type": "mcp_approval_response", "approval_request_id": "5", "approve": false, "reason": "MR"},
                {"type": "custom_tool_call_output", "call_id": "6", "output": [{"type": "input_text", "text": "CO"}]},
                {"type": "message", "role": "assistant", "content": [{"type": "refusal", "refusal": "RF"}]},
                {"type": "computer_call_output", "call_id": "7", "output": {"type": "computer_screenshot", "image_url": "x"}}
            ]
        });
        let texts = collect(&mut v, |v, f| {
            walk_request(v, f);
        });
        assert_eq!(
            texts,
            [
                "FD", "PV", "PT", "LS", "SO", "SE", "AP", "MA", "MO", "MR", "CO", "RF"
            ]
        );
    }
}
