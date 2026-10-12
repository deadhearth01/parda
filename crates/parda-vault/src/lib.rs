//! Encrypted reversible mapping store (`real value <-> surrogate`) and the
//! deterministic, format-preserving surrogate generator.
//!
//! * [`VaultKey`] / [`load_or_create_key`] - the 256-bit vault key and where it
//!   lives (OS keyring, or a `0600` key file as fallback).
//! * [`Store`] - SQLite mapping table; real values only ever hit disk as
//!   XChaCha20-Poly1305 ciphertext plus a keyed HMAC index.
//! * [`surrogate::SurrogateGen`] - realistic stand-ins (Indian names, Aadhaar,
//!   PAN, GSTIN, UPI, phones, cards, ...) derived deterministically from a seed.

pub mod crypto;
pub mod keystore;
pub mod store;
pub mod surrogate;

pub use crypto::VaultKey;
pub use keystore::{KeySource, delete_key, find_key, load_or_create_key};
pub use store::{RowsGuard, Store};
pub use surrogate::{SurrogateGen, token};

/// Errors produced by the vault. Messages never contain real values.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The surrogate string is already mapped (in this scope) to another value,
    /// or equals the real value itself. Re-seed (`attempt + 1`) and retry.
    #[error("surrogate is already taken in this scope")]
    SurrogateTaken,
    /// The real value is already mapped to a different surrogate. Call
    /// `Store::get_surrogate` and use the stored mapping instead.
    #[error("value is already mapped to a different surrogate")]
    AlreadyMapped,
    /// The supplied key cannot decrypt this vault.
    #[error("vault key does not match this vault")]
    WrongKey,
    /// Encryption or decryption failed (corrupt or tampered data).
    #[error("crypto error: {0}")]
    Crypto(String),
    /// The vault key could not be loaded, created or stored.
    #[error("key storage error: {0}")]
    Key(String),
    /// SQLite error.
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    /// Filesystem error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
