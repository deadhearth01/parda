//! The pluggable body rewriting used on decrypted (listed-host) traffic.

use std::collections::BTreeMap;

use bytes::Bytes;

/// A request the transform will not let through. The client gets `status`
/// with `message` as a plain-text body, and nothing is sent upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub message: String,
}

/// What a transform did to one request body (for the event feed).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestOutcome {
    /// The body to send upstream, identity-encoded.
    pub body: Bytes,
    /// Replacements by kind. Never values.
    pub counts: BTreeMap<String, u32>,
    /// Parts forwarded without being scanned (images, binary files, …).
    pub unscanned: u32,
    /// The request target (path and query) to send upstream, when the
    /// transform rewrote it; `None` keeps the one the client sent.
    pub target: Option<String>,
}

/// Rewrites bodies of decrypted traffic: requests on the way out, responses
/// on the way back.
pub trait BodyTransform: Send + Sync + 'static {
    /// The request body to send upstream. `body` is exactly what the client
    /// sent (it may be compressed: see `content-encoding` in `headers`); the
    /// returned body must be identity-encoded, because parda drops the
    /// request's `content-encoding` and recomputes its length.
    fn request(
        &self,
        host: &str,
        path: &str,
        headers: &http::HeaderMap,
        body: Bytes,
    ) -> Result<Bytes, Refusal>;

    /// A fresh rewriter for one response body (identity-encoded): the
    /// answer to a `method` request for `path` (no query) on `host`. The
    /// method and path decide whose content it is: an engine-backed
    /// transform restores only the user's own sends and history.
    fn response_stream(
        &self,
        method: &http::Method,
        host: &str,
        path: &str,
        content_type: &str,
    ) -> Box<dyn StreamTransform>;

    /// [`BodyTransform::request`] plus what it did, for the event feed. The
    /// default reports no counts; engine-backed transforms override it.
    fn request_outcome(
        &self,
        host: &str,
        path: &str,
        headers: &http::HeaderMap,
        body: Bytes,
    ) -> Result<RequestOutcome, Refusal> {
        self.request(host, path, headers, body)
            .map(|body| RequestOutcome {
                body,
                ..RequestOutcome::default()
            })
    }

    /// The request target (path and query string) to send upstream. The
    /// default keeps it unchanged.
    fn request_target(&self, host: &str, path_and_query: &str) -> Result<String, Refusal> {
        let _ = host;
        Ok(path_and_query.to_string())
    }

    /// One whole request, target and body together, so an engine-backed
    /// transform can redact all of its text in one batch. The server calls
    /// this (on the blocking pool); `body` may be empty. The default calls
    /// [`BodyTransform::request_target`] and, for a non-empty body,
    /// [`BodyTransform::request_outcome`].
    fn rewrite_request(
        &self,
        host: &str,
        path_and_query: &str,
        headers: &http::HeaderMap,
        body: Bytes,
    ) -> Result<RequestOutcome, Refusal> {
        let target = self.request_target(host, path_and_query)?;
        let path = path_and_query
            .split_once('?')
            .map_or(path_and_query, |(p, _)| p);
        let mut out = if body.is_empty() {
            RequestOutcome::default()
        } else {
            self.request_outcome(host, path, headers, body)?
        };
        if target != path_and_query {
            out.target = Some(target);
        }
        Ok(out)
    }

    /// The hosts to decrypt right now, for a transform that keeps a live
    /// list (the engine transform follows `intercept.hosts` through its
    /// `set_config`). The server asks on every CONNECT and PAC request;
    /// `None` (the default) keeps [`crate::InterceptState::hosts`].
    fn hosts(&self) -> Option<crate::HostList> {
        None
    }
}

/// Rewrites one response body chunk by chunk, without buffering it whole.
pub trait StreamTransform: Send {
    /// Rewrite the next chunk; may hold back bytes (e.g. a tag split across
    /// chunks) until the next call or [`StreamTransform::finish`].
    fn push(&mut self, chunk: &[u8]) -> Bytes;
    /// The end of the body: return anything still held back.
    fn finish(&mut self) -> Bytes;
    /// True if this rewriter never changes a byte: the server then streams
    /// the body without calling it.
    fn is_passthrough(&self) -> bool {
        false
    }
}

/// An identity transform for unit tests only: it would forward a compressed
/// request body after the server dropped its `content-encoding`.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    pub(crate) struct Identity;

    impl BodyTransform for Identity {
        fn request(
            &self,
            _: &str,
            _: &str,
            _: &http::HeaderMap,
            body: Bytes,
        ) -> Result<Bytes, Refusal> {
            Ok(body)
        }

        fn response_stream(
            &self,
            _: &http::Method,
            _: &str,
            _: &str,
            _: &str,
        ) -> Box<dyn StreamTransform> {
            Box::new(Identity)
        }
    }

    impl StreamTransform for Identity {
        fn push(&mut self, chunk: &[u8]) -> Bytes {
            Bytes::copy_from_slice(chunk)
        }

        fn finish(&mut self) -> Bytes {
            Bytes::new()
        }
    }
}
