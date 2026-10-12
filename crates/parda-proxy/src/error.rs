//! parda's own errors, shaped like the provider's so SDKs surface them well.

use axum::response::{IntoResponse, Response};
use http::StatusCode;
use http::header::CONTENT_TYPE;
use serde_json::json;

use crate::route::Provider;

pub(crate) fn error_response(
    provider: Provider,
    status: StatusCode,
    kind: &str,
    message: &str,
) -> Response {
    let body = if provider.is_anthropic() {
        json!({"type": "error", "error": {"type": kind, "message": message}})
    } else {
        json!({"error": {"message": message, "type": kind, "code": kind, "param": null}})
    };
    (
        status,
        [(CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}
