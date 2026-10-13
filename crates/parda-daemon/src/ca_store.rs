//! The local root certificate used by `parda intercept`, kept in the data
//! directory: the certificate in the clear (`parda-ca.pem`, it is public) and
//! the private key encrypted with the vault key (`parda-ca.key.enc`).

use std::path::PathBuf;

use anyhow::{Context, bail};
use base64::Engine as _;
use parda_intercept::Ca;
use parda_vault::load_or_create_key;

use crate::paths::{Paths, write_private};

const CERT_FILE: &str = "parda-ca.pem";
const KEY_FILE: &str = "parda-ca.key.enc";
/// Binds the ciphertext to its purpose (see `VaultKey::encrypt_aad`).
const KEY_AAD: &[u8] = b"parda-ca-key-v1";
const NONCE_LEN: usize = 24;
const RECREATE: &str =
    "run `parda ca uninstall`, then `parda ca create --force` and `parda ca install`";

pub fn ca_cert_path(paths: &Paths) -> PathBuf {
    paths.data_dir.join(CERT_FILE)
}

fn ca_key_path(paths: &Paths) -> PathBuf {
    paths.data_dir.join(KEY_FILE)
}

pub fn ca_exists(paths: &Paths) -> bool {
    ca_cert_path(paths).is_file() && ca_key_path(paths).is_file()
}

/// Create a new root certificate. Refuses to replace an existing one unless
/// `force` (the old one must then be removed from the OS trust store).
pub fn create_ca(paths: &Paths, use_keyring: bool, force: bool) -> anyhow::Result<Ca> {
    // Guard on the certificate alone: a lone (maybe trusted) certificate whose
    // key is missing must not be silently replaced either.
    if ca_cert_path(paths).is_file() && !force {
        bail!(
            "a parda root certificate already exists ({}); use --force to replace it",
            ca_cert_path(paths).display()
        );
    }
    paths.ensure()?;
    let ca = Ca::generate()?;
    let (key, _) = load_or_create_key(&paths.data_dir, use_keyring)?;
    let pem = ca.key_pem();
    let (nonce, ct) = key.encrypt_aad(pem.as_bytes(), KEY_AAD);
    let mut blob = nonce;
    blob.extend_from_slice(&ct);
    // Key first, certificate last: a crash in between leaves no certificate,
    // so `ca_exists` stays false and `create` simply runs again.
    let _ = std::fs::remove_file(ca_cert_path(paths));
    write_private(
        &ca_key_path(paths),
        &base64::engine::general_purpose::STANDARD.encode(&blob),
    )?;
    write_private(&ca_cert_path(paths), &ca.cert_pem())?;
    Ok(ca)
}

/// Load the root certificate created by [`create_ca`].
pub fn load_ca(paths: &Paths, use_keyring: bool) -> anyhow::Result<Ca> {
    let cert = std::fs::read_to_string(ca_cert_path(paths))
        .context("no parda root certificate yet — run `parda ca create`")?;
    let text = std::fs::read_to_string(ca_key_path(paths)).context("reading the CA key")?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|_| anyhow::anyhow!("the CA key file is damaged — {RECREATE}"))?;
    if blob.len() <= NONCE_LEN {
        bail!("the CA key file is damaged — {RECREATE}");
    }
    let (key, _) = load_or_create_key(&paths.data_dir, use_keyring)?;
    let pem = key
        .decrypt_aad(&blob[..NONCE_LEN], &blob[NONCE_LEN..], KEY_AAD)
        .map_err(|_| {
            anyhow::anyhow!(
                "the CA key cannot be decrypted with this vault key (damaged, or the vault was reset) — {RECREATE}"
            )
        })?;
    let pem = zeroize::Zeroizing::new(String::from_utf8(pem).context("CA key is not text")?);
    Ca::from_pem(&cert, &pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> (tempfile::TempDir, Paths) {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path().to_path_buf());
        (d, p)
    }

    #[test]
    fn create_then_load_returns_the_same_certificate() {
        let (_d, p) = paths();
        assert!(!ca_exists(&p));
        let ca = create_ca(&p, false, false).unwrap();
        assert!(ca_exists(&p));
        let again = load_ca(&p, false).unwrap();
        assert_eq!(ca.cert_pem(), again.cert_pem());
    }

    #[test]
    fn key_is_encrypted_and_private() {
        let (_d, p) = paths();
        create_ca(&p, false, false).unwrap();
        let raw = std::fs::read(ca_key_path(&p)).unwrap();
        assert!(!raw.windows(11).any(|w| w == b"PRIVATE KEY"));
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(String::from_utf8(raw).unwrap().trim())
            .unwrap();
        assert!(!decoded.windows(11).any(|w| w == b"PRIVATE KEY"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(ca_key_path(&p))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn existing_ca_is_kept_unless_forced() {
        let (_d, p) = paths();
        let first = create_ca(&p, false, false).unwrap();
        assert!(create_ca(&p, false, false).is_err());
        assert_eq!(load_ca(&p, false).unwrap().cert_pem(), first.cert_pem());
        let second = create_ca(&p, false, true).unwrap();
        assert_ne!(second.cert_pem(), first.cert_pem());
    }

    #[test]
    fn tampered_key_file_is_rejected() {
        let (_d, p) = paths();
        create_ca(&p, false, false).unwrap();
        let text = std::fs::read_to_string(ca_key_path(&p)).unwrap();
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        std::fs::write(
            ca_key_path(&p),
            base64::engine::general_purpose::STANDARD.encode(raw),
        )
        .unwrap();
        assert!(load_ca(&p, false).is_err());
    }

    #[test]
    fn a_different_vault_key_cannot_open_the_ca_key() {
        let (_d, p) = paths();
        create_ca(&p, false, false).unwrap();
        // The vault was reset: a new key replaces the old one.
        std::fs::remove_file(p.data_dir.join("vault.key")).unwrap();
        let e = load_ca(&p, false).unwrap_err().to_string();
        assert!(e.contains("parda ca create --force"), "{e}");
    }
}
