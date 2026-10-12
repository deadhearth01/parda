//! SQLite mapping store: real values encrypted at rest, keyed-HMAC index.
//!
//! Table `mappings(scope, kind, real_hmac, real_ct, nonce, surrogate,
//! created_at, last_used_at)` with `UNIQUE(scope, real_hmac)` and
//! `UNIQUE(scope, surrogate)`. The real value is stored only as
//! XChaCha20-Poly1305 ciphertext; `real_hmac` is a keyed blind index so a
//! value can be found without being readable. Surrogates are stored in the
//! clear (they are fake by construction and are what the LLM sees anyway).
//! WAL mode and `secure_delete` are on; timestamps are unix seconds.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parda_core::EntityKind;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{Error, Result, VaultKey};

const SCHEMA_VERSION: i64 = 1;
const KEY_CHECK_NAME: &str = "key_check";
const KEY_CHECK_PLAINTEXT: &[u8] = b"parda-vault-key-check-v1";
const SECS_PER_DAY: i64 = 86_400;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS mappings (
    scope        TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    real_hmac    BLOB    NOT NULL,
    real_ct      BLOB    NOT NULL,
    nonce        BLOB    NOT NULL,
    surrogate    TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    UNIQUE (scope, real_hmac),
    UNIQUE (scope, surrogate)
);
CREATE INDEX IF NOT EXISTS idx_mappings_last_used ON mappings (last_used_at);
CREATE TABLE IF NOT EXISTS meta (
    name  TEXT PRIMARY KEY,
    value BLOB NOT NULL
) WITHOUT ROWID;
";

/// Current unix time in seconds.
pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The encrypted mapping store. `Send + Sync`: one connection behind a mutex,
/// shared by every engine thread.
pub struct Store {
    conn: Mutex<Connection>,
    key: VaultKey,
    generation: AtomicU64,
    /// Bumped (under the write lock) by every prune or wipe that removed
    /// rows. Redactions hold the read lock, so rows cannot vanish while one
    /// is choosing stand-ins, and they see the change on their next run.
    deletions: RwLock<u64>,
}

/// Held while a redaction uses mappings: `prune` and `wipe` wait for it.
pub struct RowsGuard<'a>(RwLockReadGuard<'a, u64>);

impl RowsGuard<'_> {
    /// The deletion generation (see [`Store::deletions`]).
    pub fn deletions(&self) -> u64 {
        *self.0
    }
}

impl Store {
    /// Open (creating if needed) the vault database at `path`.
    ///
    /// Fails with [`Error::WrongKey`] if `key` is not the key this vault was
    /// created with.
    pub fn open(path: &Path, key: VaultKey) -> Result<Store> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        precreate_private(path)?;
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        // `journal_mode` answers with the resulting mode, so read it as a query.
        conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0))?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        let store = Store {
            conn: Mutex::new(conn),
            key,
            generation: AtomicU64::new(0),
            deletions: RwLock::new(0),
        };
        store.verify_or_init_key_check()?;
        Ok(store)
    }

    fn verify_or_init_key_check(&self) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT value FROM meta WHERE name = ?1",
                [KEY_CHECK_NAME],
                |r| r.get(0),
            )
            .optional()?;
        match existing {
            Some(blob) => {
                let ok = blob.len() > 24
                    && self
                        .key
                        .decrypt(&blob[..24], &blob[24..])
                        .is_ok_and(|pt| pt == KEY_CHECK_PLAINTEXT);
                if !ok {
                    return Err(Error::WrongKey);
                }
            }
            None => {
                let (nonce, ct) = self.key.encrypt(KEY_CHECK_PLAINTEXT);
                let mut blob = nonce;
                blob.extend_from_slice(&ct);
                tx.execute(
                    "INSERT INTO meta (name, value) VALUES (?1, ?2)",
                    params![KEY_CHECK_NAME, blob],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn bump(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// A counter that increases on every insert, prune and wipe. The engine
    /// compares it with the value it last saw to know when to rebuild its
    /// restore automaton.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// A counter that increases whenever a prune or wipe removed rows. An
    /// in-memory view of the mappings built under an older value may hold
    /// mappings that no longer exist and must be rebuilt.
    pub fn deletions(&self) -> u64 {
        *self
            .deletions
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Keep `prune` and `wipe` out until the guard is dropped. Do not call
    /// [`Store::deletions`], `prune` or `wipe` on the same thread while
    /// holding it (use [`RowsGuard::deletions`]).
    pub fn hold_rows(&self) -> RowsGuard<'_> {
        RowsGuard(
            self.deletions
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// The seed for the deterministic surrogate generator (HKDF subkey
    /// `"parda-seed"` of the vault key). Convenience so callers that only hold
    /// a `Store` need not keep a second copy of the key.
    pub fn seed(&self, data: &[u8]) -> [u8; 32] {
        self.key.seed(data)
    }

    /// The surrogate currently mapped to `real` in `scope`.
    pub fn get_surrogate(&self, scope: &str, real: &str) -> Result<Option<String>> {
        let h = self.key.hmac(real.as_bytes());
        Ok(self
            .conn()
            .query_row(
                "SELECT surrogate FROM mappings WHERE scope = ?1 AND real_hmac = ?2",
                params![scope, &h[..]],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// The real value (and its kind) behind `surrogate` in `scope`.
    pub fn get_real(&self, scope: &str, surrogate: &str) -> Result<Option<(String, EntityKind)>> {
        let row: Option<(String, Vec<u8>, Vec<u8>)> = self
            .conn()
            .query_row(
                "SELECT kind, nonce, real_ct FROM mappings WHERE scope = ?1 AND surrogate = ?2",
                params![scope, surrogate],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(kind, nonce, ct)| Ok((self.decrypt_text(&nonce, &ct)?, parse_kind(&kind))))
            .transpose()
    }

    /// Record `real -> surrogate` in `scope`.
    ///
    /// * `Err(SurrogateTaken)`: the surrogate already stands for another value
    ///   in this scope, or equals `real`. Re-seed and try again.
    /// * `Err(AlreadyMapped)`: `real` already has a different surrogate (a
    ///   concurrent writer won); read it with [`Store::get_surrogate`].
    /// * Re-inserting the identical pair succeeds without changing anything.
    pub fn insert(
        &self,
        scope: &str,
        kind: &EntityKind,
        real: &str,
        surrogate: &str,
    ) -> Result<()> {
        if real == surrogate {
            return Err(Error::SurrogateTaken);
        }
        let h = self.key.hmac(real.as_bytes());
        let (nonce, ct) = self.key.encrypt(real.as_bytes());
        let ts = now();
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT surrogate FROM mappings WHERE scope = ?1 AND real_hmac = ?2",
                params![scope, &h[..]],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            return if existing == surrogate {
                Ok(())
            } else {
                Err(Error::AlreadyMapped)
            };
        }
        let taken: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM mappings WHERE scope = ?1 AND surrogate = ?2)",
            params![scope, surrogate],
            |r| r.get(0),
        )?;
        if taken {
            return Err(Error::SurrogateTaken);
        }
        tx.execute(
            "INSERT INTO mappings
                 (scope, kind, real_hmac, real_ct, nonce, surrogate, created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![scope, kind.to_string(), &h[..], ct, nonce, surrogate, ts],
        )?;
        tx.commit()?;
        drop(conn);
        self.bump();
        Ok(())
    }

    /// Does `s` already stand for some value in `scope`?
    pub fn surrogate_exists(&self, scope: &str, s: &str) -> Result<bool> {
        Ok(self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM mappings WHERE scope = ?1 AND surrogate = ?2)",
            params![scope, s],
            |r| r.get(0),
        )?)
    }

    /// Every `(surrogate, real, kind)` in `scope`, for building the restore
    /// automaton. A row that fails authentication (corrupt or tampered) is
    /// skipped rather than failing the whole restore.
    pub fn reverse_map(&self, scope: &str) -> Result<Vec<(String, String, EntityKind)>> {
        let rows: Vec<(String, String, Vec<u8>, Vec<u8>)> = {
            let conn = self.conn();
            let mut stmt = conn.prepare_cached(
                "SELECT surrogate, kind, nonce, real_ct FROM mappings
                 WHERE scope = ?1 ORDER BY rowid",
            )?;
            stmt.query_map([scope], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        let mut out = Vec::with_capacity(rows.len());
        for (surrogate, kind, nonce, ct) in rows {
            match self.decrypt_text(&nonce, &ct) {
                Ok(real) => out.push((surrogate, real, parse_kind(&kind))),
                Err(_) => tracing::warn!(
                    scope,
                    "skipping vault row that failed authentication (corrupt or tampered)"
                ),
            }
        }
        Ok(out)
    }

    /// Mark `real` as used now, postponing its TTL expiry.
    pub fn touch(&self, scope: &str, real: &str) -> Result<()> {
        let h = self.key.hmac(real.as_bytes());
        self.conn().execute(
            "UPDATE mappings SET last_used_at = ?3 WHERE scope = ?1 AND real_hmac = ?2",
            params![scope, &h[..], now()],
        )?;
        Ok(())
    }

    /// Delete mappings not used for `ttl_days` days. `0` disables expiry.
    /// Returns the number of rows removed.
    pub fn prune(&self, ttl_days: u32) -> Result<usize> {
        let mut deletions = self
            .deletions
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let removed = if ttl_days == 0 {
            0
        } else {
            let cutoff = now() - i64::from(ttl_days) * SECS_PER_DAY;
            let conn = self.conn();
            let n = conn.execute("DELETE FROM mappings WHERE last_used_at < ?1", [cutoff])?;
            checkpoint(&conn);
            n
        };
        if removed > 0 {
            *deletions += 1;
        }
        self.bump();
        Ok(removed)
    }

    /// Delete every mapping, or only those of `scope`. Returns rows removed.
    pub fn wipe(&self, scope: Option<&str>) -> Result<usize> {
        let mut deletions = self
            .deletions
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let removed = {
            let conn = self.conn();
            let n = match scope {
                Some(s) => conn.execute("DELETE FROM mappings WHERE scope = ?1", [s])?,
                None => conn.execute("DELETE FROM mappings", [])?,
            };
            checkpoint(&conn);
            n
        };
        if removed > 0 {
            *deletions += 1;
        }
        self.bump();
        Ok(removed)
    }

    /// `(scope, kind, count)` for `parda vault stats`.
    pub fn stats(&self) -> Result<Vec<(String, String, u64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT scope, kind, COUNT(*) FROM mappings GROUP BY scope, kind ORDER BY scope, kind",
        )?;
        Ok(stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|(scope, kind, n)| (scope, kind, u64::try_from(n).unwrap_or(0)))
            .collect())
    }

    fn decrypt_text(&self, nonce: &[u8], ct: &[u8]) -> Result<String> {
        String::from_utf8(self.key.decrypt(nonce, ct)?)
            .map_err(|_| Error::Crypto("stored value is not valid UTF-8".into()))
    }
}

fn parse_kind(s: &str) -> EntityKind {
    s.parse()
        .unwrap_or_else(|e: std::convert::Infallible| match e {})
}

/// Fold the WAL back into the main file so deleted rows do not linger in it.
fn checkpoint(conn: &Connection) {
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
}

/// Create the database file with owner-only permissions *before* SQLite does,
/// so the WAL and shared-memory files inherit them too.
fn precreate_private(path: &Path) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn open_tmp() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("v.db"), VaultKey::generate()).unwrap();
        (dir, s)
    }

    #[test]
    fn store_insert_lookup_reverse() {
        let (_d, s) = open_tmp();
        s.insert("global", &EntityKind::Person, "Ravi Kumar", "Arjun Mehta")
            .unwrap();
        assert_eq!(
            s.get_surrogate("global", "Ravi Kumar").unwrap().as_deref(),
            Some("Arjun Mehta")
        );
        assert_eq!(s.get_surrogate("other", "Ravi Kumar").unwrap(), None);
        assert!(
            s.reverse_map("global")
                .unwrap()
                .iter()
                .any(|(sur, real, _)| sur == "Arjun Mehta" && real == "Ravi Kumar")
        );
    }

    #[test]
    fn real_value_not_plaintext_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.db");
        {
            let s = Store::open(&p, VaultKey::generate()).unwrap();
            s.insert(
                "global",
                &EntityKind::Email,
                "secret.person@corp.in",
                "x@y.example",
            )
            .unwrap();
        }
        let bytes = std::fs::read(&p).unwrap();
        assert!(!bytes.windows(13).any(|w| w == b"secret.person"));
    }

    #[test]
    fn real_value_not_plaintext_in_wal_while_open() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.db");
        let s = Store::open(&p, VaultKey::generate()).unwrap();
        s.insert(
            "global",
            &EntityKind::Email,
            "secret.person@corp.in",
            "x@y.example",
        )
        .unwrap();
        for name in ["v.db", "v.db-wal"] {
            if let Ok(bytes) = std::fs::read(dir.path().join(name)) {
                assert!(!bytes.windows(13).any(|w| w == b"secret.person"), "{name}");
            }
        }
        drop(s);
    }

    #[test]
    fn surrogate_unique_per_scope() {
        let (_d, s) = open_tmp();
        s.insert("global", &EntityKind::Person, "Ravi", "Arjun")
            .unwrap();
        let err = s
            .insert("global", &EntityKind::Person, "Amit", "Arjun")
            .unwrap_err();
        assert!(matches!(err, Error::SurrogateTaken), "{err:?}");
        // same surrogate in another scope is fine
        s.insert("other", &EntityKind::Person, "Amit", "Arjun")
            .unwrap();
        assert!(s.surrogate_exists("global", "Arjun").unwrap());
        assert!(!s.surrogate_exists("global", "Nobody").unwrap());
    }

    #[test]
    fn surrogate_equal_to_real_is_rejected() {
        let (_d, s) = open_tmp();
        let err = s
            .insert("global", &EntityKind::Person, "Ravi", "Ravi")
            .unwrap_err();
        assert!(matches!(err, Error::SurrogateTaken));
        assert_eq!(s.get_surrogate("global", "Ravi").unwrap(), None);
    }

    #[test]
    fn real_already_mapped_semantics() {
        let (_d, s) = open_tmp();
        s.insert("global", &EntityKind::Person, "Ravi", "Arjun")
            .unwrap();
        // identical re-insert is a no-op success (concurrent writers racing)
        s.insert("global", &EntityKind::Person, "Ravi", "Arjun")
            .unwrap();
        let err = s
            .insert("global", &EntityKind::Person, "Ravi", "Vikram")
            .unwrap_err();
        assert!(matches!(err, Error::AlreadyMapped), "{err:?}");
        assert_eq!(
            s.get_surrogate("global", "Ravi").unwrap().as_deref(),
            Some("Arjun")
        );
        assert!(!s.surrogate_exists("global", "Vikram").unwrap());
    }

    #[test]
    fn get_real_returns_value_and_kind() {
        let (_d, s) = open_tmp();
        s.insert(
            "global",
            &EntityKind::Aadhaar,
            "2345 6789 0124",
            "3456 7890 1235",
        )
        .unwrap();
        s.insert(
            "global",
            &EntityKind::Custom("Badge".into()),
            "B-77",
            "B-12",
        )
        .unwrap();
        assert_eq!(
            s.get_real("global", "3456 7890 1235").unwrap(),
            Some(("2345 6789 0124".to_string(), EntityKind::Aadhaar))
        );
        assert_eq!(
            s.get_real("global", "B-12").unwrap(),
            Some(("B-77".to_string(), EntityKind::Custom("Badge".into())))
        );
        assert_eq!(s.get_real("global", "nope").unwrap(), None);
        assert_eq!(s.get_real("other", "B-12").unwrap(), None);
    }

    #[test]
    fn reverse_map_is_scoped_and_empty_when_unused() {
        let (_d, s) = open_tmp();
        assert!(s.reverse_map("global").unwrap().is_empty());
        s.insert("a", &EntityKind::Person, "Ravi", "Arjun").unwrap();
        s.insert("b", &EntityKind::Email, "r@x.in", "q@y.example")
            .unwrap();
        let a = s.reverse_map("a").unwrap();
        assert_eq!(a, vec![("Arjun".into(), "Ravi".into(), EntityKind::Person)]);
        assert_eq!(s.reverse_map("b").unwrap().len(), 1);
    }

    #[test]
    fn unicode_values_roundtrip() {
        let (_d, s) = open_tmp();
        s.insert("global", &EntityKind::Person, "रवि कुमार", "Arjun Mehta")
            .unwrap();
        assert_eq!(
            s.get_surrogate("global", "रवि कुमार").unwrap().as_deref(),
            Some("Arjun Mehta")
        );
        assert_eq!(s.reverse_map("global").unwrap()[0].1, "रवि कुमार");
    }

    #[test]
    fn prune_and_wipe() {
        let (_d, s) = open_tmp();
        s.insert("global", &EntityKind::Person, "Old One", "Old Sur")
            .unwrap();
        s.insert("global", &EntityKind::Person, "New One", "New Sur")
            .unwrap();
        {
            let c = s.conn.lock().unwrap();
            let old = crate::store::now() - 40 * 86_400;
            c.execute(
                "UPDATE mappings SET created_at=?1, last_used_at=?1 WHERE surrogate='Old Sur'",
                [old],
            )
            .unwrap();
        }
        assert_eq!(s.prune(30).unwrap(), 1);
        assert_eq!(s.get_surrogate("global", "Old One").unwrap(), None);
        assert!(s.get_surrogate("global", "New One").unwrap().is_some());
        assert_eq!(s.prune(30).unwrap(), 0);
        assert_eq!(s.wipe(None).unwrap(), 1);
        assert!(s.reverse_map("global").unwrap().is_empty());
    }

    #[test]
    fn prune_uses_last_used_and_touch_refreshes_it() {
        let (_d, s) = open_tmp();
        s.insert("global", &EntityKind::Person, "Kept", "K Sur")
            .unwrap();
        s.insert("global", &EntityKind::Person, "Dropped", "D Sur")
            .unwrap();
        {
            let c = s.conn.lock().unwrap();
            let old = crate::store::now() - 90 * 86_400;
            c.execute("UPDATE mappings SET created_at=?1, last_used_at=?1", [old])
                .unwrap();
        }
        s.touch("global", "Kept").unwrap();
        assert_eq!(s.prune(30).unwrap(), 1);
        assert!(s.get_surrogate("global", "Kept").unwrap().is_some());
        assert!(s.get_surrogate("global", "Dropped").unwrap().is_none());
    }

    #[test]
    fn prune_zero_ttl_means_keep_forever() {
        let (_d, s) = open_tmp();
        s.insert("global", &EntityKind::Person, "A", "B").unwrap();
        {
            let c = s.conn.lock().unwrap();
            c.execute("UPDATE mappings SET created_at=0, last_used_at=0", [])
                .unwrap();
        }
        assert_eq!(s.prune(0).unwrap(), 0);
        assert_eq!(s.reverse_map("global").unwrap().len(), 1);
    }

    #[test]
    fn wipe_by_scope_only_touches_that_scope() {
        let (_d, s) = open_tmp();
        s.insert("a", &EntityKind::Person, "R1", "S1").unwrap();
        s.insert("a", &EntityKind::Person, "R2", "S2").unwrap();
        s.insert("b", &EntityKind::Person, "R1", "S1").unwrap();
        assert_eq!(s.wipe(Some("a")).unwrap(), 2);
        assert!(s.reverse_map("a").unwrap().is_empty());
        assert_eq!(s.reverse_map("b").unwrap().len(), 1);
        assert_eq!(s.wipe(Some("missing")).unwrap(), 0);
    }

    #[test]
    fn stats_groups_by_scope_and_kind() {
        let (_d, s) = open_tmp();
        s.insert("global", &EntityKind::Person, "R1", "S1").unwrap();
        s.insert("global", &EntityKind::Person, "R2", "S2").unwrap();
        s.insert("global", &EntityKind::Email, "e@x.in", "f@y.example")
            .unwrap();
        s.insert("proj", &EntityKind::Person, "R1", "S1").unwrap();
        let mut st = s.stats().unwrap();
        st.sort();
        assert_eq!(
            st,
            vec![
                ("global".into(), "Email".into(), 1),
                ("global".into(), "Person".into(), 2),
                ("proj".into(), "Person".into(), 1),
            ]
        );
    }

    #[test]
    fn generation_bumps_on_insert_prune_wipe() {
        let (_d, s) = open_tmp();
        let g0 = s.generation();
        s.insert("global", &EntityKind::Person, "R", "S").unwrap();
        let g1 = s.generation();
        assert!(g1 > g0);
        s.prune(30).unwrap();
        let g2 = s.generation();
        assert!(g2 > g1);
        s.wipe(None).unwrap();
        assert!(s.generation() > g2);
    }

    #[test]
    fn deletions_count_only_removals() {
        let (_d, s) = open_tmp();
        assert_eq!(s.deletions(), 0);
        s.insert("global", &EntityKind::Person, "R", "S").unwrap();
        s.prune(30).unwrap();
        assert_eq!(s.deletions(), 0, "nothing expired");
        s.wipe(Some("other")).unwrap();
        assert_eq!(s.deletions(), 0);
        {
            let g = s.hold_rows();
            assert_eq!(g.deletions(), 0);
        }
        s.wipe(None).unwrap();
        assert_eq!(s.deletions(), 1);
    }

    #[test]
    fn persists_across_reopen_and_rejects_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.db");
        let key = VaultKey::from_bytes([9; 32]);
        {
            let s = Store::open(&p, key.clone()).unwrap();
            s.insert("global", &EntityKind::Person, "Ravi", "Arjun")
                .unwrap();
        }
        {
            let s = Store::open(&p, key.clone()).unwrap();
            assert_eq!(
                s.get_surrogate("global", "Ravi").unwrap().as_deref(),
                Some("Arjun")
            );
        }
        let err = Store::open(&p, VaultKey::from_bytes([10; 32]))
            .err()
            .unwrap();
        assert!(matches!(err, Error::WrongKey), "{err:?}");
    }

    #[test]
    fn store_is_send_and_sync_and_usable_across_threads() {
        fn assert_ss<T: Send + Sync>() {}
        assert_ss::<Store>();
        let (_d, s) = open_tmp();
        let s = std::sync::Arc::new(s);
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let s = s.clone();
                std::thread::spawn(move || {
                    for i in 0..25 {
                        s.insert(
                            "global",
                            &EntityKind::Person,
                            &format!("real {t}-{i}"),
                            &format!("sur {t}-{i}"),
                        )
                        .unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(s.reverse_map("global").unwrap().len(), 100);
    }

    #[cfg(unix)]
    #[test]
    fn db_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.db");
        let _s = Store::open(&p, VaultKey::generate()).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
