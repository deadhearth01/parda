//! The smaller text endpoints: Anthropic Message Batches and legacy Text
//! Completions, OpenAI legacy Completions (incl. fill-in-the-middle) and
//! Embeddings.

use serde_json::{Map, Value, json};

use crate::anthropic;
use crate::sse::{Restorers, SseEvent, StreamRewriter};
use crate::walk::{Unscanned, Visit, str_field};

/// `POST /v1/messages/batches`: each `requests[].params` is a Messages request.
pub(crate) fn walk_batch_request(v: &mut Value, f: Visit<'_>) -> Unscanned {
    let mut unscanned = Unscanned::NONE;
    if let Some(Value::Array(reqs)) = v.get_mut("requests") {
        for r in reqs {
            if let Some(params) = r.get_mut("params") {
                unscanned += anthropic::walk_request(params, f);
            }
        }
    }
    unscanned
}

/// `POST /v1/complete`: the `prompt`.
pub(crate) fn walk_complete_request(v: &mut Value, f: Visit<'_>) -> Unscanned {
    str_field(v, "prompt", f);
    Unscanned::NONE
}

pub(crate) fn walk_complete_response(v: &mut Value, f: Visit<'_>) {
    str_field(v, "completion", f);
}

/// A completions `prompt` / embeddings `input`: a string, an array of
/// strings, or token ids. Token ids cannot be scanned and are counted.
fn text_or_tokens(v: Option<&mut Value>, f: Visit<'_>) -> Unscanned {
    match v {
        Some(Value::String(s)) => {
            f(s);
            Unscanned::NONE
        }
        Some(Value::Array(items)) => {
            let mut tokens = false;
            for item in items {
                match item {
                    Value::String(s) => f(s),
                    Value::Null => {}
                    _ => tokens = true,
                }
            }
            if tokens {
                Unscanned::MEDIA
            } else {
                Unscanned::NONE
            }
        }
        Some(Value::Null) | None => Unscanned::NONE,
        Some(_) => Unscanned::UNKNOWN,
    }
}

/// `POST /v1/completions`: `prompt` and the fill-in-the-middle `suffix`.
pub(crate) fn walk_completions_request(v: &mut Value, f: Visit<'_>) -> Unscanned {
    let unscanned = text_or_tokens(v.get_mut("prompt"), f);
    str_field(v, "suffix", f);
    unscanned
}

pub(crate) fn walk_completions_response(v: &mut Value, f: Visit<'_>) {
    if let Some(Value::Array(choices)) = v.get_mut("choices") {
        for c in choices {
            str_field(c, "text", f);
        }
    }
}

/// `POST /v1/embeddings`: the `input`.
pub(crate) fn walk_embeddings_request(v: &mut Value, f: Visit<'_>) -> Unscanned {
    text_or_tokens(v.get_mut("input"), f)
}

/// Anthropic `/v1/complete` streams: `completion` events carry text.
pub(crate) struct CompleteStream {
    restorers: Restorers,
}

impl CompleteStream {
    const KEY: &'static str = "completion";

    pub(crate) fn new(restorers: Restorers) -> Self {
        CompleteStream { restorers }
    }
}

impl StreamRewriter for CompleteStream {
    fn on_event(&mut self, mut ev: SseEvent, out: &mut Vec<SseEvent>) {
        let Ok(mut v) = serde_json::from_str::<Value>(&ev.data) else {
            out.push(ev);
            return;
        };
        let done = v.get("stop_reason").is_some_and(|r| !r.is_null());
        if let Some(Value::String(t)) = v.get_mut("completion") {
            let mut restored = self.restorers.push(Self::KEY, t);
            if done {
                // The held-back tail belongs in this, the last, event.
                restored.push_str(&self.restorers.finish(Self::KEY));
            }
            *t = restored;
            ev.set_data(v.to_string());
        }
        out.push(ev);
    }

    fn on_end(&mut self, out: &mut Vec<SseEvent>) {
        let rest = self.restorers.finish(Self::KEY);
        if !rest.is_empty() {
            let data = json!({"type": "completion", "completion": rest, "stop_reason": null});
            out.push(SseEvent::new(Some("completion"), data.to_string()));
        }
    }
}

/// OpenAI `/v1/completions` streams: `choices[].text` per choice.
pub(crate) struct CompletionsStream {
    restorers: Restorers,
    template: Option<Map<String, Value>>,
}

impl CompletionsStream {
    pub(crate) fn new(restorers: Restorers) -> Self {
        CompletionsStream {
            restorers,
            template: None,
        }
    }

    fn key(choice: u64) -> String {
        format!("c:{choice}")
    }

    fn flush_open(&mut self, out: &mut Vec<SseEvent>) {
        for key in self.restorers.open_keys() {
            let Some(choice) = key.strip_prefix("c:").and_then(|c| c.parse::<u64>().ok()) else {
                continue;
            };
            let rest = self.restorers.finish(&key);
            if rest.is_empty() {
                continue;
            }
            let mut chunk = self.template.clone().unwrap_or_default();
            chunk.insert(
                "choices".into(),
                json!([{"index": choice, "text": rest, "finish_reason": null}]),
            );
            chunk.remove("usage");
            out.push(SseEvent::new(None, Value::Object(chunk).to_string()));
        }
    }
}

impl StreamRewriter for CompletionsStream {
    fn on_event(&mut self, mut ev: SseEvent, out: &mut Vec<SseEvent>) {
        if ev.data.trim() == "[DONE]" {
            self.flush_open(out);
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
        let mut changed = false;
        if let Some(Value::Array(choices)) = v.get_mut("choices") {
            for c in choices.iter_mut() {
                let index = c.get("index").and_then(Value::as_u64).unwrap_or(0);
                let done = c.get("finish_reason").is_some_and(|r| !r.is_null());
                let key = Self::key(index);
                let mut text = match c.get("text") {
                    Some(Value::String(t)) => self.restorers.push(&key, t),
                    _ => String::new(),
                };
                if done {
                    text.push_str(&self.restorers.finish(&key));
                }
                if c.get("text").is_some() || !text.is_empty() {
                    c["text"] = Value::String(text);
                    changed = true;
                }
            }
        }
        if changed {
            ev.set_data(v.to_string());
        }
        out.push(ev);
    }

    fn on_end(&mut self, out: &mut Vec<SseEvent>) {
        self.flush_open(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walk::collect;

    #[test]
    fn walkers() {
        let mut v = json!({"prompt": ["a", "b"], "suffix": "s"});
        assert_eq!(
            collect(&mut v, |v, f| {
                walk_completions_request(v, f);
            }),
            ["a", "b", "s"]
        );
        let mut v = json!({"input": [[1, 2], [3]]});
        assert_eq!(walk_embeddings_request(&mut v, &mut |_| {}).media, 1);
        let mut v = json!({"requests": [{"custom_id": "x", "params": {"messages": [{"role": "user", "content": "U"}]}}]});
        assert_eq!(
            collect(&mut v, |v, f| {
                walk_batch_request(v, f);
            }),
            ["U"]
        );
    }
}
