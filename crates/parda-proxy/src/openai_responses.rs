//! OpenAI Responses API: request/response walkers and the SSE rewriter.

use serde_json::{Value, json};

use crate::sse::{Restorers, SseEvent, StreamRewriter};
use crate::walk::{Visit, json_string, str_field, type_of};

pub(crate) fn walk_request(v: &mut Value, f: Visit<'_>) -> u32 {
    let mut unscanned = 0;
    str_field(v, "instructions", f);
    match v.get_mut("input") {
        Some(Value::String(s)) => f(s),
        Some(Value::Array(items)) => {
            for item in items {
                unscanned += input_item(item, f);
            }
        }
        _ => {}
    }
    unscanned
}

#[cfg(test)]
pub(crate) fn count_unscanned(v: &mut Value) -> u32 {
    walk_request(v, &mut |_| {})
}

fn content_parts(content: &mut Value, f: Visit<'_>) -> u32 {
    match content {
        Value::String(s) => {
            f(s);
            0
        }
        Value::Array(parts) => {
            let mut unscanned = 0;
            for p in parts {
                match type_of(p) {
                    "input_text" | "output_text" | "text" => str_field(p, "text", f),
                    "input_image" | "input_file" | "input_audio" => unscanned += 1,
                    _ => {}
                }
            }
            unscanned
        }
        _ => 0,
    }
}

fn input_item(item: &mut Value, f: Visit<'_>) -> u32 {
    let ty = type_of(item).to_string();
    match ty.as_str() {
        "message" | "" if item.get("content").is_some() => {
            item.get_mut("content").map_or(0, |c| content_parts(c, f))
        }
        "function_call" => {
            if let Some(Value::String(a)) = item.get_mut("arguments") {
                json_string(a, f);
            }
            0
        }
        "function_call_output" => match item.get_mut("output") {
            Some(Value::String(s)) => {
                f(s);
                0
            }
            Some(other) => content_parts(other, f),
            None => 0,
        },
        "custom_tool_call" => {
            str_field(item, "input", f);
            0
        }
        "custom_tool_call_output" => {
            str_field(item, "output", f);
            0
        }
        // reasoning (encrypted), item references, future types: untouched.
        _ => 0,
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
                    if type_of(p) == "output_text" {
                        str_field(p, "text", f);
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
                    let restored = self.restorers.push(&key, d);
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
}
