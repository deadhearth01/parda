//! parda intercept: a loopback CONNECT proxy that decrypts only listed AI
//! hosts (with a locally generated root CA), passes their bodies through a
//! body transform, forwards them to the real server with verified TLS, and
//! tunnels every other host byte-for-byte.

pub mod ca;
pub mod hosts;
pub mod pac;

pub use ca::Ca;
pub use hosts::HostList;
pub use pac::pac;
