//! HTTP body plumbing shared by the agent proxy (`parda-proxy`) and the
//! HTTPS interception proxy (`parda-intercept`):
//!
//! - [`body`]: undo `Content-Encoding` with output caps; lenient but
//!   fail-closed JSON parsing.
//! - [`sse`]: an incremental server-sent-events parser and serialiser.
//! - [`walk`]: JSON string-leaf walking that keeps number literals as written.
//! - [`jsonfrag`]: restoring surrogates in a JSON document that arrives in
//!   fragments.
//! - [`urlguard`]: never restoring inside URLs (links, images, autolinks,
//!   HTML attribute values, CSS).

pub mod body;
pub mod jsonfrag;
pub mod sse;
pub mod urlguard;
pub mod walk;

pub use jsonfrag::JsonFragRestorer;
pub use sse::{SseEvent, SseParser, parse_rest, parse_sse, serialize};
