//! parda intercept: a loopback CONNECT proxy that decrypts only listed AI
//! hosts (with a locally generated root CA), passes their bodies through a
//! [`BodyTransform`], forwards them to the real server with verified TLS, and
//! tunnels every other host byte-for-byte.

pub mod ca;
mod engine_transform;
pub mod hosts;
pub mod pac;
mod restore;
pub mod server;
mod sites;
pub mod transform;
mod walk;

pub use ca::{CA_NAME, Ca};
pub use engine_transform::EngineTransform;
pub use hosts::HostList;
pub use pac::pac;
pub use server::{InterceptEvent, InterceptState, Timeouts, serve, upstream_client_builder};
pub use transform::{BodyTransform, Refusal, RequestOutcome, StreamTransform};
