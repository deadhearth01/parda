//! Vault key, AEAD encryption and keyed hashing.
//!
//! One 256-bit master key does three jobs, kept apart by domain separation:
//! * XChaCha20-Poly1305 encryption of real values (the master key itself),
//! * HMAC-SHA256 index under the HKDF subkey `"parda-index"`,
//! * deterministic surrogate seeds under the HKDF subkey `"parda-seed"`.

use std::fmt;

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

const NONCE_LEN: usize = 24;
const INFO_INDEX: &[u8] = b"parda-index";
const INFO_SEED: &[u8] = b"parda-seed";

/// The 256-bit vault key. Zeroized on drop; never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; 32]);

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

impl VaultKey {
    /// A fresh random key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
        VaultKey(bytes)
    }

    /// Wrap existing key material (e.g. loaded from the keyring or key file).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        VaultKey(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn subkey(&self, info: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(None, &self.0)
            .expand(info, &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        out
    }

    fn keyed_hash(&self, info: &[u8], data: &[u8]) -> [u8; 32] {
        let mut sub = self.subkey(info);
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&sub).expect("HMAC accepts keys of any length");
        mac.update(data);
        sub.zeroize();
        mac.finalize().into_bytes().into()
    }

    /// HMAC-SHA256 under the HKDF subkey `"parda-index"`: the blind index used
    /// to look up a real value without storing it in the clear.
    pub fn hmac(&self, data: &[u8]) -> [u8; 32] {
        self.keyed_hash(INFO_INDEX, data)
    }

    /// HMAC-SHA256 under the HKDF subkey `"parda-seed"`: the secret seed that
    /// drives the deterministic surrogate generator.
    pub fn seed(&self, data: &[u8]) -> [u8; 32] {
        self.keyed_hash(INFO_SEED, data)
    }

    /// Encrypt with XChaCha20-Poly1305 under a fresh random 24-byte nonce.
    /// Returns `(nonce, ciphertext_with_tag)`.
    pub fn encrypt(&self, pt: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, pt)
            .expect("XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail");
        (nonce.to_vec(), ct)
    }

    /// Decrypt and authenticate. Fails on a wrong key, wrong nonce length or
    /// any modification of the ciphertext.
    pub fn decrypt(&self, nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_aad(nonce, ct, b"")
    }

    /// [`encrypt`](Self::encrypt) with associated data: the ciphertext only
    /// opens with the same `aad` (binds it to where it is stored).
    pub fn encrypt_aad(&self, pt: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, Payload { msg: pt, aad })
            .expect("XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail");
        (nonce.to_vec(), ct)
    }

    /// [`decrypt`](Self::decrypt) with associated data; fails if `aad`
    /// differs from what the ciphertext was sealed with.
    pub fn decrypt_aad(&self, nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != NONCE_LEN {
            return Err(Error::Crypto("invalid nonce length".into()));
        }
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
            .map_err(|_| Error::Crypto("authentication failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt() {
        let k = VaultKey::generate();
        let (n, c) = k.encrypt(b"Ravi");
        assert_eq!(k.decrypt(&n, &c).unwrap(), b"Ravi");
    }

    #[test]
    fn associated_data_must_match() {
        let k = VaultKey::generate();
        let (n, c) = k.encrypt_aad(b"Ravi", b"row-1");
        assert_eq!(k.decrypt_aad(&n, &c, b"row-1").unwrap(), b"Ravi");
        assert!(k.decrypt_aad(&n, &c, b"row-2").is_err());
        assert!(k.decrypt(&n, &c).is_err());
    }

    #[test]
    fn hmac_deterministic() {
        let k = VaultKey::generate();
        assert_eq!(k.hmac(b"x"), k.hmac(b"x"));
        assert_ne!(k.hmac(b"x"), k.hmac(b"y"));
    }

    #[test]
    fn nonce_is_24_bytes_and_fresh_each_time() {
        let k = VaultKey::generate();
        let (n1, c1) = k.encrypt(b"same");
        let (n2, c2) = k.encrypt(b"same");
        assert_eq!(n1.len(), 24);
        assert_ne!(n1, n2);
        assert_ne!(c1, c2);
        assert_eq!(c1.len(), 4 + 16, "ciphertext = plaintext + 16-byte tag");
    }

    #[test]
    fn tampering_and_wrong_key_are_rejected() {
        let k = VaultKey::generate();
        let (n, mut c) = k.encrypt(b"Ravi Kumar");
        assert!(VaultKey::generate().decrypt(&n, &c).is_err());
        c[0] ^= 1;
        assert!(k.decrypt(&n, &c).is_err());
        assert!(
            k.decrypt(&n[..23], &c).is_err(),
            "short nonce must not panic"
        );
        assert!(k.decrypt(&[], &[]).is_err());
    }

    #[test]
    fn subkeys_are_domain_separated() {
        let k = VaultKey::generate();
        assert_ne!(k.hmac(b"x"), k.seed(b"x"));
        assert_eq!(k.seed(b"x"), k.seed(b"x"));
        assert_ne!(k.seed(b"x"), k.seed(b"y"));
        assert_ne!(k.seed(b"x"), VaultKey::generate().seed(b"x"));
    }

    #[test]
    fn debug_never_prints_key_material() {
        let k = VaultKey::from_bytes([0xAB; 32]);
        let shown = format!("{k:?}");
        assert!(!shown.to_lowercase().contains("ab"));
        assert!(!shown.contains("171"));
    }

    #[test]
    fn from_bytes_is_deterministic() {
        let a = VaultKey::from_bytes([7; 32]);
        let b = VaultKey::from_bytes([7; 32]);
        assert_eq!(a.hmac(b"q"), b.hmac(b"q"));
        let (n, c) = a.encrypt(b"hello");
        assert_eq!(b.decrypt(&n, &c).unwrap(), b"hello");
    }
}
