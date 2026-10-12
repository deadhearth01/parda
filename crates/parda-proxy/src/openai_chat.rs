//! OpenAI Chat Completions: request/response walkers and the SSE rewriter.

use serde_json::{Map, Value, json};

use crate::sse::{Restorers, SseEvent, StreamRewriter};
use crate::walk::{Visit, json_string, str_field, type_of};

pub(crate) fn walk_request(v: &mut Value, f: Visit<'_>) -> u32 {
    let mut unscanned = 0;
    let Some(Value::Array(msgs)) = v.get_mut("messages") else {
        return 0;
    };
    for m in msgs {
        match m.get_mut("content") {
            Some(Value::String(s)) => f(s),
            Some(Value::Array(parts)) => {
                for p in parts {
                    match type_of(p) {
                        "text" => str_field(p, "text", f),
                        "image_url" | "input_audio" | "file" => unscanned += 1,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        tool_calls(m, f);
    }
    unscanned
}

#[cfg(test)]
pub(crate) fn count_unscanned(v: &mut Value) -> u32 {
    walk_request(v, &mut |_| {})
}

fn tool_calls(m: &mut Value, f: Visit<'_>) {
    if let Some(Value::Array(calls)) = m.get_mut("tool_calls") {
        for c in calls {
            if let Some(Value::String(args)) =
                c.get_mut("function").and_then(|x| x.get_mut("arguments"))
            {
                json_string(args, f);
            }
        }
    }
    if let Some(Value::String(args)) = m
        .get_mut("function_call")
        .and_then(|x| x.get_mut("arguments"))
    {
        json_string(args, f);
    }
}

pub(crate) fn walk_response(v: &mut Value, f: Visit<'_>) {
    if let Some(Value::Array(choices)) = v.get_mut("choices") {
        for c in choices {
            if let Some(m) = c.get_mut("message") {
                str_field(m, "content", f);
                tool_calls(m, f);
            }
        }
    }
}

pub(crate) struct ChatStream {
    restorers: Restorers,
    /// The last chunk seen, used as the envelope of synthetic chunks.
    template: Option<Map<String, Value>>,
}

impl ChatStream {
    pub(crate) fn new(restorers: Restorers) -> Self {
        ChatStream {
            restorers,
            template: None,
        }
    }

    fn content_key(choice: u64) -> String {
        format!("c:{choice}")
    }

    fn tool_key(choice: u64, tool: u64) -> String {
        format!("t:{choice}:{tool}")
    }

    /// A chunk carrying the held-back text of `choice`, if any.
    fn flush_choice(&mut self, choice: u64) -> Option<SseEvent> {
        let content = self.restorers.finish(&Self::content_key(choice));
        let prefix = format!("t:{choice}:");
        let mut tools = Vec::new();
        for key in self.restorers.open_keys() {
            if let Some(tool) = key
                .strip_prefix(&prefix)
                .and_then(|t| t.parse::<u64>().ok())
            {
                let rest = self.restorers.finish(&key);
                if !rest.is_empty() {
                    tools.push(json!({"index": tool, "function": {"arguments": rest}}));
                }
            }
        }
        if content.is_empty() && tools.is_empty() {
            return None;
        }
        let mut delta = Map::new();
        if !content.is_empty() {
            delta.insert("content".into(), Value::String(content));
        }
        if !tools.is_empty() {
            delta.insert("tool_calls".into(), Value::Array(tools));
        }
        let mut chunk = self.template.clone().unwrap_or_default();
        chunk.insert(
            "choices".into(),
            json!([{"index": choice, "delta": Value::Object(delta), "finish_reason": null}]),
        );
        chunk.remove("usage");
        Some(SseEvent::new(None, Value::Object(chunk).to_string()))
    }

    fn open_choices(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .restorers
            .open_keys()
            .iter()
            .filter_map(|k| k.split(':').nth(1)?.parse().ok())
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

impl StreamRewriter for ChatStream {
    fn on_event(&mut self, mut ev: SseEvent, out: &mut Vec<SseEvent>) {
        if ev.data.trim() == "[DONE]" {
            for c in self.open_choices() {
                out.extend(self.flush_choice(c));
            }
            out.push(ev);
            return;
        }
        let Ok(mut v) = serde_json::from_str::<Value>(&ev.data) else {
            out.push(ev);
            return;
        };
        if let Value::Object(m) = &v {
            let mut t = m.clone();
            t.remove("choices");
            self.template = Some(t);
        }
        let mut finished = Vec::new();
        let mut changed = false;
        if let Some(Value::Array(choices)) = v.get_mut("choices") {
            for c in choices.iter_mut() {
                let index = c.get("index").and_then(Value::as_u64).unwrap_or(0);
                if let Some(delta) = c.get_mut("delta") {
                    if let Some(Value::String(s)) = delta.get_mut("content") {
                        *s = self.restorers.push(&Self::content_key(index), s);
                        changed = true;
                    }
                    if let Some(Value::Array(calls)) = delta.get_mut("tool_calls") {
                        for call in calls {
                            let tool = call.get("index").and_then(Value::as_u64).unwrap_or(0);
                            if let Some(Value::String(a)) = call
                                .get_mut("function")
                                .and_then(|x| x.get_mut("arguments"))
                            {
                                *a = self.restorers.push(&Self::tool_key(index, tool), a);
                                changed = true;
                            }
                        }
                    }
                }
                if c.get("finish_reason").is_some_and(|r| !r.is_null()) {
                    finished.push(index);
                }
            }
        }
        for index in finished {
            out.extend(self.flush_choice(index));
        }
        if changed {
            ev.set_data(v.to_string());
        }
        out.push(ev);
    }

    fn on_end(&mut self, out: &mut Vec<SseEvent>) {
        for c in self.open_choices() {
            out.extend(self.flush_choice(c));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walk::collect;

    #[test]
    fn request_walk() {
        let mut v = json!({"messages": [
            {"role": "system", "content": "S"},
            {"role": "user", "content": [{"type": "text", "text": "U"}, {"type": "image_url", "image_url": {"url": "x"}}]},
            {"role": "assistant", "content": null, "tool_calls": [{"id": "1", "type": "function", "function": {"name": "f", "arguments": "{\"to\":\"A\"}"}}]},
            {"role": "tool", "tool_call_id": "1", "content": "R"}
        ]});
        let texts = collect(&mut v, |v, f| {
            walk_request(v, f);
        });
        assert_eq!(texts, ["S", "U", "A", "R"]);
        assert_eq!(count_unscanned(&mut v), 1);
    }
}
