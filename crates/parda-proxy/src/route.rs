//! Which API a request is for, and whether parda rewrites it.

use http::{HeaderMap, Method};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// Anthropic Messages (`/v1/messages`, `/v1/messages/count_tokens`).
    Anthropic,
    /// Anthropic Message Batches (`POST /v1/messages/batches`): every
    /// `requests[].params` is a Messages request.
    AnthropicBatches,
    /// Anthropic legacy Text Completions (`/v1/complete`).
    AnthropicComplete,
    /// OpenAI Chat Completions (`/v1/chat/completions`).
    OpenAiChat,
    /// OpenAI Responses (`/v1/responses`, `/v1/responses/input_tokens`,
    /// `/v1/responses/compact`).
    OpenAiResponses,
    /// OpenAI legacy Completions, incl. fill-in-the-middle (`/v1/completions`).
    OpenAiCompletions,
    /// OpenAI Embeddings (`/v1/embeddings`).
    OpenAiEmbeddings,
    /// OpenAI Conversations items (`POST /v1/conversations`,
    /// `POST /v1/conversations/{id}/items`).
    OpenAiConversations,
    /// Any other Anthropic endpoint: forwarded unchanged if it carries no text.
    PassAnthropic,
    /// Any other endpoint: forwarded unchanged to the OpenAI upstream if it
    /// carries no text.
    PassOpenAi,
}

impl Provider {
    pub fn name(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::AnthropicBatches => "anthropic-batches",
            Provider::AnthropicComplete => "anthropic-complete",
            Provider::OpenAiChat => "openai-chat",
            Provider::OpenAiResponses => "openai-responses",
            Provider::OpenAiCompletions => "openai-completions",
            Provider::OpenAiEmbeddings => "openai-embeddings",
            Provider::OpenAiConversations => "openai-conversations",
            Provider::PassAnthropic => "anthropic-passthrough",
            Provider::PassOpenAi => "openai-passthrough",
        }
    }

    pub fn is_anthropic(self) -> bool {
        matches!(
            self,
            Provider::Anthropic
                | Provider::AnthropicBatches
                | Provider::AnthropicComplete
                | Provider::PassAnthropic
        )
    }

    /// Request bodies of this route are redacted (and error bodies restored).
    pub fn rewrites(self) -> bool {
        !matches!(self, Provider::PassAnthropic | Provider::PassOpenAi)
    }

    /// Successful answers of this route carry model text to restore.
    pub fn restores(self) -> bool {
        matches!(
            self,
            Provider::Anthropic
                | Provider::AnthropicComplete
                | Provider::OpenAiChat
                | Provider::OpenAiResponses
                | Provider::OpenAiCompletions
        )
    }
}

/// Endpoints parda knows how to redact, for error messages.
pub(crate) const SUPPORTED: &str = "/v1/messages, /v1/messages/count_tokens, \
    /v1/messages/batches, /v1/complete, /v1/chat/completions, /v1/responses, \
    /v1/responses/input_tokens, /v1/responses/compact, /v1/completions, /v1/embeddings, \
    /v1/conversations, /v1/conversations/{id}/items";

fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// The path as an upstream server would see it after its own
/// normalisation: percent-encoded unreserved characters decoded, empty and
/// `.` segments dropped, `..` applied, no trailing slash. Encoded reserved
/// characters (`%2F`, …) stay encoded.
pub fn normalize_path(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let (Some(h), Some(l)) = (
                bytes.get(i + 1).copied().and_then(hex),
                bytes.get(i + 2).copied().and_then(hex),
            )
            && unreserved(h << 4 | l)
        {
            decoded.push(h << 4 | l);
            i += 3;
            continue;
        }
        decoded.push(bytes[i]);
        i += 1;
    }
    let decoded = String::from_utf8_lossy(&decoded);
    let mut segments: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    format!("/{}", segments.join("/"))
}

/// Route a request by method and normalised path (see [`normalize_path`]).
pub fn route(method: &Method, path: &str, headers: &HeaderMap) -> Provider {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if method == Method::POST {
        let found = match segs.as_slice() {
            ["v1", "messages"] | ["v1", "messages", "count_tokens"] => Some(Provider::Anthropic),
            ["v1", "messages", "batches"] => Some(Provider::AnthropicBatches),
            ["v1", "complete"] => Some(Provider::AnthropicComplete),
            ["v1", "chat", "completions"] => Some(Provider::OpenAiChat),
            ["v1", "responses"]
            | ["v1", "responses", "input_tokens"]
            | ["v1", "responses", "compact"] => Some(Provider::OpenAiResponses),
            ["v1", "completions"] => Some(Provider::OpenAiCompletions),
            ["v1", "embeddings"] => Some(Provider::OpenAiEmbeddings),
            ["v1", "conversations"] | ["v1", "conversations", _, "items"] => {
                Some(Provider::OpenAiConversations)
            }
            _ => None,
        };
        if let Some(p) = found {
            return p;
        }
    }
    if path.starts_with("/v1/messages")
        || path == "/v1/complete"
        || headers.contains_key("anthropic-version")
        || headers.contains_key("x-api-key")
    {
        Provider::PassAnthropic
    } else {
        Provider::PassOpenAi
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        let h = HeaderMap::new();
        let post = |p: &str| route(&Method::POST, &normalize_path(p), &h);
        assert_eq!(post("/v1/messages"), Provider::Anthropic);
        assert_eq!(post("/v1/messages/count_tokens"), Provider::Anthropic);
        assert_eq!(post("/v1/chat/completions"), Provider::OpenAiChat);
        assert_eq!(post("/v1/responses/"), Provider::OpenAiResponses);
        assert_eq!(
            post("/v1/responses/input_tokens"),
            Provider::OpenAiResponses
        );
        assert_eq!(post("/v1/messages/batches"), Provider::AnthropicBatches);
        assert_eq!(post("/v1/complete"), Provider::AnthropicComplete);
        assert_eq!(post("/v1/completions"), Provider::OpenAiCompletions);
        assert_eq!(post("/v1/embeddings"), Provider::OpenAiEmbeddings);
        assert_eq!(
            post("/v1/conversations/c1/items"),
            Provider::OpenAiConversations
        );
        assert_eq!(
            post("/v1/messages/batches/b1/cancel"),
            Provider::PassAnthropic
        );
        assert_eq!(route(&Method::GET, "/v1/models", &h), Provider::PassOpenAi);
        let mut a = HeaderMap::new();
        a.insert("anthropic-version", "2023-06-01".parse().unwrap());
        assert_eq!(
            route(&Method::GET, "/v1/models", &a),
            Provider::PassAnthropic
        );
    }

    #[test]
    fn normalises_paths() {
        for (raw, want) in [
            ("/v1/messages", "/v1/messages"),
            ("/v1//chat/completions", "/v1/chat/completions"),
            ("//v1/messages/", "/v1/messages"),
            ("/v1/%6Dessages", "/v1/messages"),
            ("/v1/%6dessages", "/v1/messages"),
            ("/v1/./x/../messages", "/v1/messages"),
            ("/../v1/messages", "/v1/messages"),
            ("/v1%2Fmessages", "/v1%2Fmessages"),
            ("/v1/%zz", "/v1/%zz"),
            ("/v1/%", "/v1/%"),
            ("", "/"),
            ("/", "/"),
        ] {
            assert_eq!(normalize_path(raw), want, "{raw}");
        }
    }
}
