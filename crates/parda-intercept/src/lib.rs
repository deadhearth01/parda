//! parda intercept: a loopback CONNECT proxy that decrypts only listed AI
//! hosts (with a locally generated root CA), passes their bodies through a
//! tunnels every other host byte-for-byte.

pub mod ca;
pub mod hosts;
pub mod pac;
pub mod transform;

pub use ca::Ca;
pub use hosts::HostList;
pub use pac::pac;
pub use transform::{BodyTransform, Passthrough, Refusal, RequestOutcome, StreamTransform};
