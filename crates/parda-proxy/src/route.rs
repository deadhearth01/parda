//! Which API a request is for, and whether parda rewrites it.

use http::{HeaderMap, Method};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// Anthropic Messages (`/v1/messages`, `/v1/messages/count_tokens`).
    Anthropic,
    /// OpenAI Chat Completions (`/v1/chat/completions`).
    OpenAiChat,
    /// OpenAI Responses (`/v1/responses`).
    OpenAiResponses,
    /// Any other Anthropic endpoint: forwarded unchanged.
    PassAnthropic,
    /// Any other endpoint: forwarded unchanged to the OpenAI upstream.
    PassOpenAi,
}

impl Provider {
    pub fn name(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::OpenAiChat => "openai-chat",
            Provider::OpenAiResponses => "openai-responses",
            Provider::PassAnthropic => "anthropic-passthrough",
            Provider::PassOpenAi => "openai-passthrough",
        }
    }

    pub fn is_anthropic(self) -> bool {
        matches!(self, Provider::Anthropic | Provider::PassAnthropic)
    }

    /// Bodies of this route are redacted / restored.
    pub fn rewrites(self) -> bool {
        matches!(
            self,
            Provider::Anthropic | Provider::OpenAiChat | Provider::OpenAiResponses
        )
    }
}

pub fn route(method: &Method, path: &str, headers: &HeaderMap) -> Provider {
    let p = path.trim_end_matches('/');
    if method == Method::POST {
        match p {
            "/v1/messages" | "/v1/messages/count_tokens" => return Provider::Anthropic,
            "/v1/chat/completions" => return Provider::OpenAiChat,
            "/v1/responses" => return Provider::OpenAiResponses,
            _ => {}
        }
    }
    if p.starts_with("/v1/messages")
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
        assert_eq!(
            route(&Method::POST, "/v1/messages", &h),
            Provider::Anthropic
        );
        assert_eq!(
            route(&Method::POST, "/v1/messages/count_tokens", &h),
            Provider::Anthropic
        );
        assert_eq!(
            route(&Method::POST, "/v1/chat/completions", &h),
            Provider::OpenAiChat
        );
        assert_eq!(
            route(&Method::POST, "/v1/responses/", &h),
            Provider::OpenAiResponses
        );
        assert_eq!(route(&Method::GET, "/v1/models", &h), Provider::PassOpenAi);
        let mut a = HeaderMap::new();
        a.insert("anthropic-version", "2023-06-01".parse().unwrap());
        assert_eq!(
            route(&Method::GET, "/v1/models", &a),
            Provider::PassAnthropic
        );
        assert_eq!(
            route(&Method::POST, "/v1/messages/batches", &h),
            Provider::PassAnthropic
        );
    }
}
