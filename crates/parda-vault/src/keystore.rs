//! Where the vault key lives: the OS keyring first, a `0600` key file as the
//! fallback (headless Linux, locked-down machines, keyring errors).

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::{Error, Result, VaultKey};

/// Keyring service name.
pub const KEYRING_SERVICE: &str = "parda";
/// Keyring user (entry) name.
pub const KEYRING_USER: &str = "vault-key";
/// File name of the fallback key file inside the data directory.
pub const KEY_FILE_NAME: &str = "vault.key";

/// Where the key was found or created (`parda doctor` reports this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    Keyring,
    File(PathBuf),
}

/// Load the vault key, creating it on first use.
///
/// With `use_keyring` the OS keyring (service `"parda"`, user `"vault-key"`) is
/// tried first. If the keyring has no entry but a `vault.key` file already
/// exists, the file wins (it holds the key of an existing vault written when
/// the keyring was unavailable). If the keyring is unavailable or errors, the
/// key lives in `<data_dir>/vault.key` (mode `0600` on Unix). A key file or
/// keyring entry that exists but is malformed is an error - it is never
/// silently replaced, because that would orphan the vault.
pub fn load_or_create_key(data_dir: &Path, use_keyring: bool) -> Result<(VaultKey, KeySource)> {
    fs::create_dir_all(data_dir)?;
    let file = data_dir.join(KEY_FILE_NAME);
    if use_keyring {
        match os_keyring::get() {
            Lookup::Found(key) => return Ok((key, KeySource::Keyring)),
            Lookup::Missing => {
                if file.exists() {
                    return load_or_create_file(&file);
                }
                let key = VaultKey::generate();
                if os_keyring::set(&key) {
                    return Ok((key, KeySource::Keyring));
                }
            }
            Lookup::Corrupt => {
                return Err(Error::Key(
                    "corrupt keyring entry (expected 64 hex characters)".into(),
                ));
            }
            Lookup::Unavailable => {}
        }
    }
    load_or_create_file(&file)
}

fn load_or_create_file(path: &Path) -> Result<(VaultKey, KeySource)> {
    if let Some(key) = read_key_file(path)? {
        return Ok((key, KeySource::File(path.to_path_buf())));
    }
    let key = VaultKey::generate();
    match write_new_key_file(path, &key) {
        Ok(()) => Ok((key, KeySource::File(path.to_path_buf()))),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            // Another process created it first; a reader may briefly see it empty.
            for _ in 0..50 {
                if let Some(k) = read_key_file(path)? {
                    return Ok((k, KeySource::File(path.to_path_buf())));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(Error::Key("corrupt key file".into()))
        }
        Err(e) => Err(e.into()),
    }
}

/// `Ok(None)` when the file does not exist or is still empty.
fn read_key_file(path: &Path) -> Result<Option<VaultKey>> {
    let text = match fs::read_to_string(path) {
        Ok(t) => Zeroizing::new(t),
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if text.trim().is_empty() {
        return Ok(None);
    }
    let key = decode_key(text.trim()).ok_or_else(|| {
        Error::Key(format!(
            "corrupt key file {} (expected 64 hex characters)",
            path.display()
        ))
    })?;
    ensure_private(path);
    Ok(Some(key))
}

fn write_new_key_file(path: &Path, key: &VaultKey) -> std::io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    let hex = Zeroizing::new(encode_key(key));
    f.write_all(hex.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()
}

/// Best effort: tighten an existing key file that is group/world accessible.
fn ensure_private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path)
            && meta.permissions().mode() & 0o077 != 0
        {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn encode_key(key: &VaultKey) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in key.as_bytes() {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

fn decode_key(hex: &str) -> Option<VaultKey> {
    let hex = hex.as_bytes();
    if hex.len() != 64 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut bytes = [0u8; 32];
    for (i, pair) in hex.as_chunks::<2>().0.iter().enumerate() {
        bytes[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(VaultKey::from_bytes(bytes))
}

/// Outcome of looking in the OS keyring.
#[allow(dead_code)] // not every variant is constructed on every platform
enum Lookup {
    Found(VaultKey),
    /// The keyring works but holds no key yet.
    Missing,
    /// No backend, locked, denied, ... - use the key file instead.
    Unavailable,
    /// An entry exists but is not a valid key.
    Corrupt,
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
mod os_keyring {
    use super::{KEYRING_SERVICE, KEYRING_USER, Lookup, decode_key, encode_key};
    use crate::VaultKey;
    use zeroize::Zeroizing;

    pub(super) fn get() -> Lookup {
        let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER) else {
            return Lookup::Unavailable;
        };
        match entry.get_password() {
            Ok(secret) => {
                let secret = Zeroizing::new(secret);
                decode_key(secret.trim()).map_or(Lookup::Corrupt, Lookup::Found)
            }
            Err(keyring::Error::NoEntry) => Lookup::Missing,
            Err(_) => Lookup::Unavailable,
        }
    }

    /// `true` only if the key was written and reads back identically (some
    /// backends accept writes without persisting them).
    pub(super) fn set(key: &VaultKey) -> bool {
        let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER) else {
            return false;
        };
        let hex = Zeroizing::new(encode_key(key));
        if entry.set_password(&hex).is_err() {
            return false;
        }
        matches!(get(), Lookup::Found(back) if back.as_bytes() == key.as_bytes())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
mod os_keyring {
    use super::Lookup;
    use crate::VaultKey;

    pub(super) fn get() -> Lookup {
        Lookup::Unavailable
    }

    pub(super) fn set(_key: &VaultKey) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_file_fallback_perms() {
        let dir = tempfile::tempdir().unwrap();
        let (k1, src) = load_or_create_key(dir.path(), false).unwrap();
        let path = dir.path().join("vault.key");
        assert_eq!(src, KeySource::File(path.clone()));
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let (k2, src2) = load_or_create_key(dir.path(), false).unwrap();
        assert_eq!(src2, KeySource::File(path));
        assert_eq!(k1.hmac(b"probe"), k2.hmac(b"probe"), "same key reloaded");
    }

    #[test]
    fn creates_missing_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        let (_, src) = load_or_create_key(&nested, false).unwrap();
        assert_eq!(src, KeySource::File(nested.join("vault.key")));
    }

    #[test]
    fn corrupt_key_file_is_an_error_not_a_silent_reset() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("vault.key"), b"too short").unwrap();
        assert!(load_or_create_key(dir.path(), false).is_err());
        assert_eq!(
            std::fs::read(dir.path().join("vault.key")).unwrap(),
            b"too short",
            "must not overwrite a bad key file"
        );
    }

    #[test]
    fn distinct_dirs_get_distinct_keys() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let (ka, _) = load_or_create_key(a.path(), false).unwrap();
        let (kb, _) = load_or_create_key(b.path(), false).unwrap();
        assert_ne!(ka.hmac(b"probe"), kb.hmac(b"probe"));
    }
}
