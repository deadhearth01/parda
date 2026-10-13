//! Restoring real values in the answers of intercepted AI sites.

use bytes::Bytes;
use parda_engine::Engine;

use crate::StreamTransform;

/// A rewriter for one response body of type `content_type`.
pub(crate) fn for_content_type(
    engine: &Engine,
    scope: &str,
    content_type: &str,
) -> Box<dyn StreamTransform> {
    let _ = (engine, scope, content_type);
    Box::new(Passthrough)
}

/// Bodies parda does not rewrite (images, binaries, unknown types).
struct Passthrough;

impl StreamTransform for Passthrough {
    fn push(&mut self, chunk: &[u8]) -> Bytes {
        Bytes::copy_from_slice(chunk)
    }

    fn finish(&mut self) -> Bytes {
        Bytes::new()
    }

    fn is_passthrough(&self) -> bool {
        true
    }
}
