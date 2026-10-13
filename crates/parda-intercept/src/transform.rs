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

    /// A fresh rewriter for one response body (identity-encoded).
    fn response_stream(
        &self,
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
}

/// Rewrites one response body chunk by chunk, without buffering it whole.
pub trait StreamTransform: Send {
    /// Rewrite the next chunk; may hold back bytes (e.g. a tag split across
    /// chunks) until the next call or [`StreamTransform::finish`].
    fn push(&mut self, chunk: &[u8]) -> Bytes;
    /// The end of the body: return anything still held back.
    fn finish(&mut self) -> Bytes;
}

/// Forwards bodies unchanged.
#[derive(Debug, Clone, Copy, Default)]
pub struct Passthrough;

impl BodyTransform for Passthrough {
    fn request(
        &self,
        _: &str,
        _: &str,
        _: &http::HeaderMap,
        body: Bytes,
    ) -> Result<Bytes, Refusal> {
        Ok(body)
    }

    fn response_stream(&self, _: &str, _: &str, _: &str) -> Box<dyn StreamTransform> {
        Box::new(Passthrough)
    }
}

impl StreamTransform for Passthrough {
    fn push(&mut self, chunk: &[u8]) -> Bytes {
        Bytes::copy_from_slice(chunk)
    }

    fn finish(&mut self) -> Bytes {
        Bytes::new()
    }
}
