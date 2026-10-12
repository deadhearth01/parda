//! OpenAI Responses API: request/response walkers and the SSE rewriter.

use serde_json::{Value, json};

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
}

impl ResponsesStream {
    pub(crate) fn new(restorers: Restorers) -> Self {
        ResponsesStream { restorers }
    }

    fn text_key(v: &Value) -> String {
        format!(
            "text:{}:{}",
            v.get("item_id").and_then(Value::as_str).unwrap_or(""),
            v.get("content_index").and_then(Value::as_u64).unwrap_or(0)
        )
    }

    fn args_key(v: &Value) -> String {
        format!(
            "args:{}",
            v.get("item_id").and_then(Value::as_str).unwrap_or("")
        )
    }

    /// A synthetic `*.delta` event carrying held-back text, modelled on the
    /// `*.done` event `v` that is about to be forwarded.
    fn flush(&mut self, key: &str, delta_type: &str, v: &Value, out: &mut Vec<SseEvent>) {
        let rest = self.restorers.finish(key);
        if rest.is_empty() {
            return;
        }
        let mut d = json!({"type": delta_type, "delta": rest});
        for k in [
            "item_id",
            "output_index",
            "content_index",
            "sequence_number",
        ] {
            if let Some(x) = v.get(k) {
                d[k] = x.clone();
            }
        }
        out.push(SseEvent::new(Some(delta_type), d.to_string()));
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
            "response.output_text.delta" => {
                let key = Self::text_key(&v);
                if let Some(Value::String(d)) = v.get_mut("delta") {
                    let restored = self.restorers.push(&key, d);
                    if restored.is_empty() {
                        return;
                    }
                    *d = restored;
                    ev.set_data(v.to_string());
                }
            }
            "response.function_call_arguments.delta" => {
                let key = Self::args_key(&v);
                if let Some(Value::String(d)) = v.get_mut("delta") {
                    let restored = self.restorers.push_json(&key, d);
                    if restored.is_empty() {
                        return;
                    }
                    *d = restored;
                    ev.set_data(v.to_string());
                }
            }
            "response.output_text.done" => {
                let key = Self::text_key(&v);
                self.flush(&key, "response.output_text.delta", &v, out);
                self.restore_all(&mut v, |v, f| str_field(v, "text", f));
                ev.set_data(v.to_string());
            }
            "response.function_call_arguments.done" => {
                let key = Self::args_key(&v);
                self.flush(&key, "response.function_call_arguments.delta", &v, out);
                self.restore_all(&mut v, |v, f| {
                    if let Some(Value::String(a)) = v.get_mut("arguments") {
                        json_string(a, f);
                    }
                });
                ev.set_data(v.to_string());
            }
            "response.content_part.done" => {
                self.restore_all(&mut v, |v, f| {
                    if let Some(p) = v.get_mut("part") {
                        str_field(p, "text", f);
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
                for key in self.restorers.open_keys() {
                    let delta_type = if key.starts_with("args:") {
                        "response.function_call_arguments.delta"
                    } else {
                        "response.output_text.delta"
                    };
                    self.flush(&key, delta_type, &json!({}), out);
                }
                self.restore_all(&mut v, |v, f| {
                    if let Some(r) = v.get_mut("response") {
                        walk_response(r, f);
                    }
                });
                ev.set_data(v.to_string());
            }
            _ => {}
        }
        out.push(ev);
    }

    fn on_end(&mut self, out: &mut Vec<SseEvent>) {
        for key in self.restorers.open_keys() {
            let delta_type = if key.starts_with("args:") {
                "response.function_call_arguments.delta"
            } else {
                "response.output_text.delta"
            };
            self.flush(&key, delta_type, &json!({}), out);
        }
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
