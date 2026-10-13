//! parda intercept: a loopback CONNECT proxy that decrypts only listed AI
//! hosts (with a locally generated root CA), passes their bodies through a
//! [`BodyTransform`], forwards them to the real server with verified TLS, and
//! tunnels every other host byte-for-byte.

pub mod ca;

pub use ca::Ca;
