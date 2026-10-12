//! Black-box tests of the public store API against a real on-disk vault.

use parda_core::EntityKind;
use parda_vault::{Error, KeySource, Store, load_or_create_key};

#[test]
fn key_file_to_store_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    {
        let (key, src) = load_or_create_key(dir.path(), false).unwrap();
        assert!(matches!(src, KeySource::File(_)));
        let store = Store::open(&db, key).unwrap();
        store
            .insert("global", &EntityKind::Pan, "ABCPE1234F", "QWRPA4321Z")
            .unwrap();
    }
    // a "new process": reload the same key from the key file and reopen
    let (key, _) = load_or_create_key(dir.path(), false).unwrap();
    let store = Store::open(&db, key).unwrap();
    assert_eq!(
        store
            .get_surrogate("global", "ABCPE1234F")
            .unwrap()
            .as_deref(),
        Some("QWRPA4321Z")
    );
    assert_eq!(
        store.get_real("global", "QWRPA4321Z").unwrap(),
        Some(("ABCPE1234F".to_string(), EntityKind::Pan))
    );
}

#[test]
fn deleting_the_key_file_makes_the_vault_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    {
        let (key, _) = load_or_create_key(dir.path(), false).unwrap();
        let store = Store::open(&db, key).unwrap();
        store
            .insert("global", &EntityKind::Person, "Ravi", "Arjun")
            .unwrap();
    }
    std::fs::remove_file(dir.path().join("vault.key")).unwrap();
    // No new key is minted for a vault that has data: that key could never
    // open it.
    assert!(matches!(
        load_or_create_key(dir.path(), false),
        Err(Error::Key(_))
    ));
    // Any other key is refused by the vault itself.
    let err = Store::open(&db, parda_vault::VaultKey::generate())
        .err()
        .unwrap();
    assert!(matches!(err, Error::WrongKey));
}

#[test]
fn stored_rows_hold_only_ciphertext_and_hmac() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let (key, _) = load_or_create_key(dir.path(), false).unwrap();
    {
        let store = Store::open(&db, key).unwrap();
        store
            .insert(
                "global",
                &EntityKind::Email,
                "very.secret@corp.in",
                "w@z.example",
            )
            .unwrap();
    }
    let conn = rusqlite::Connection::open(&db).unwrap();
    let (ct, nonce, hmac): (Vec<u8>, Vec<u8>, Vec<u8>) = conn
        .query_row("SELECT real_ct, nonce, real_hmac FROM mappings", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert!(!ct.windows(6).any(|w| w == b"secret"));
    assert_eq!(nonce.len(), 24);
    assert_eq!(hmac.len(), 32);
    assert_eq!(ct.len(), "very.secret@corp.in".len() + 16);
}
