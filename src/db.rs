use rusqlite::Connection;

use crate::constants::*;
use crate::crypto;

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

pub(crate) fn init_db(conn: &Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS metadata (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            time_cost INTEGER NOT NULL,
            memory_cost INTEGER NOT NULL,
            parallelism INTEGER NOT NULL,
            verify_nonce BLOB NOT NULL,
            verify_ciphertext BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS credentials (
            service TEXT PRIMARY KEY,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL
        );",
    )
    .expect("Failed to initialize database");
    // Idempotent migration: add updated_at column if it doesn't exist yet.
    let _ = conn.execute("ALTER TABLE credentials ADD COLUMN updated_at INTEGER", []);
}

pub(crate) fn is_first_run(conn: &Connection) -> bool {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM metadata", [], |row| row.get(0))
        .expect("Failed to query metadata");
    count == 0
}

pub(crate) fn store_metadata(
    conn: &Connection,
    salt: &[u8],
    params: crypto::KdfParams,
    verify_nonce: &[u8],
    verify_ciphertext: &[u8],
) {
    conn.execute(
        "INSERT INTO metadata (id, salt, time_cost, memory_cost, parallelism, verify_nonce, verify_ciphertext)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            salt,
            params.time_cost(),
            params.memory_cost(),
            params.parallelism(),
            verify_nonce,
            verify_ciphertext
        ],
    )
    .expect("Failed to store metadata");
}

/// The Argon2 parameters this vault's key was derived with.
///
/// These columns were written from the day the schema existed but never read back —
/// `derive_key` always used the compile-time constants, so raising a constant would
/// have locked every existing vault out with nothing but "Wrong master password."
/// Reading them is what makes the constants safe to change.
pub(crate) fn load_params(conn: &Connection) -> Result<crypto::KdfParams, String> {
    let (time_cost, memory_cost, parallelism): (u32, u32, u32) = conn
        .query_row(
            "SELECT time_cost, memory_cost, parallelism FROM metadata WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("Failed to load Argon2 parameters");

    crypto::KdfParams::validated(time_cost, memory_cost, parallelism)
}

pub(crate) fn load_salt(conn: &Connection) -> Vec<u8> {
    conn.query_row("SELECT salt FROM metadata WHERE id = 1", [], |row| {
        row.get(0)
    })
    .expect("Failed to load salt")
}

pub(crate) fn load_verify_token(conn: &Connection) -> (Vec<u8>, Vec<u8>) {
    conn.query_row(
        "SELECT verify_nonce, verify_ciphertext FROM metadata WHERE id = 1",
        [],
        |row| {
            let nonce: Vec<u8> = row.get(0)?;
            let ciphertext: Vec<u8> = row.get(1)?;
            Ok((nonce, ciphertext))
        },
    )
    .expect("Failed to load verify token")
}

pub(crate) fn add_credential(
    conn: &Connection,
    key: &[u8; KEY_LEN],
    service: &str,
    username: &str,
    password: &str,
    notes: &str,
    url: &str,
) {
    let (nonce, ciphertext) = crypto::encrypt(key, service, username, password, notes, url);
    conn.execute(
        "INSERT OR REPLACE INTO credentials (service, nonce, ciphertext, updated_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![service, nonce, ciphertext, unix_now()],
    )
    .expect("Failed to store credential");
}

#[cfg(feature = "import")]
pub(crate) fn upsert_credential_tx(
    tx: &rusqlite::Transaction,
    key: &[u8; KEY_LEN],
    service: &str,
    username: &str,
    password: &str,
    notes: &str,
    url: &str,
) -> Result<(), rusqlite::Error> {
    let (nonce, ciphertext) = crypto::encrypt(key, service, username, password, notes, url);
    tx.execute(
        "INSERT OR REPLACE INTO credentials (service, nonce, ciphertext, updated_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![service, nonce, ciphertext, unix_now()],
    )?;
    Ok(())
}

/// Shared message for a row that will not decrypt under the current key.
///
/// A corrupt row used to `.expect()`, so the natural follow-up to a failed
/// `sk2 verify` — `get`, `edit`, `rename`, `export`, `change-password` — met a raw
/// Rust panic. Secrets were never leaked (panics unwind, so `Zeroizing` destructors
/// run), but a corrupt vault is exactly when a clear message matters most. This
/// mirrors the recovery advice `Command::Verify` already prints.
pub(crate) fn decrypt_failure(service: &str) -> String {
    format!(
        "Failed to decrypt the credential for '{service}' — the vault may be corrupt. \
         Run 'sk2 verify' to check every entry, then either restore from a backup with \
         'sk2 import <backup>' or drop this entry with 'sk2 delete {service}' and reset \
         the password on the affected site."
    )
}

#[allow(clippy::type_complexity)]
pub(crate) fn get_credential(
    conn: &Connection,
    key: &[u8; KEY_LEN],
    service: &str,
) -> Result<Option<(String, String, String, String, Option<i64>)>, String> {
    let result = conn.query_row(
        "SELECT nonce, ciphertext, updated_at FROM credentials WHERE service = ?1",
        rusqlite::params![service],
        |row| {
            let nonce: Vec<u8> = row.get(0)?;
            let ciphertext: Vec<u8> = row.get(1)?;
            let updated_at: Option<i64> = row.get(2)?;
            Ok((nonce, ciphertext, updated_at))
        },
    );

    match result {
        Ok((nonce, ciphertext, updated_at)) => {
            let (username, password, notes, url) =
                crypto::decrypt(key, service, &nonce, &ciphertext)
                    .map_err(|()| decrypt_failure(service))?;
            Ok(Some((username, password, notes, url, updated_at)))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => panic!("Database error: {e}"),
    }
}

pub(crate) fn delete_credential(conn: &Connection, service: &str) -> bool {
    let rows = conn
        .execute(
            "DELETE FROM credentials WHERE service = ?1",
            rusqlite::params![service],
        )
        .expect("Failed to delete credential");
    rows > 0
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn update_credential(
    conn: &Connection,
    key: &[u8; KEY_LEN],
    service: &str,
    username: &str,
    password: &str,
    notes: &str,
    url: &str,
    update_timestamp: bool,
) -> bool {
    let (nonce, ciphertext) = crypto::encrypt(key, service, username, password, notes, url);
    let rows = if update_timestamp {
        conn.execute(
            "UPDATE credentials SET nonce = ?1, ciphertext = ?2, updated_at = ?3 WHERE service = ?4",
            rusqlite::params![nonce, ciphertext, unix_now(), service],
        )
    } else {
        conn.execute(
            "UPDATE credentials SET nonce = ?1, ciphertext = ?2 WHERE service = ?3",
            rusqlite::params![nonce, ciphertext, service],
        )
    }
    .expect("Failed to update credential");
    rows > 0
}

pub(crate) fn rename_credential(
    conn: &Connection,
    key: &[u8; KEY_LEN],
    old_service: &str,
    new_service: &str,
) -> Result<(), String> {
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM credentials WHERE service = ?1",
            rusqlite::params![new_service],
            |row| row.get(0),
        )
        .expect("Failed to query credentials");
    if exists > 0 {
        return Err(format!("A credential for '{new_service}' already exists."));
    }

    let result = conn.query_row(
        "SELECT nonce, ciphertext, updated_at FROM credentials WHERE service = ?1",
        rusqlite::params![old_service],
        |row| {
            let nonce: Vec<u8> = row.get(0)?;
            let ciphertext: Vec<u8> = row.get(1)?;
            let updated_at: Option<i64> = row.get(2)?;
            Ok((nonce, ciphertext, updated_at))
        },
    );

    let (nonce, ciphertext, updated_at) = match result {
        Ok(data) => data,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Err(format!("No credential found for '{old_service}'."));
        }
        Err(e) => panic!("Database error: {e}"),
    };

    let (username, password, notes, url) = crypto::decrypt(key, old_service, &nonce, &ciphertext)
        .map_err(|()| decrypt_failure(old_service))?;

    let (new_nonce, new_ciphertext) =
        crypto::encrypt(key, new_service, &username, &password, &notes, &url);

    conn.execute(
        "UPDATE credentials SET service = ?1, nonce = ?2, ciphertext = ?3, updated_at = ?4 WHERE service = ?5",
        rusqlite::params![new_service, new_nonce, new_ciphertext, updated_at, old_service],
    )
    .expect("Failed to rename credential");

    Ok(())
}

pub(crate) fn list_services(conn: &Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT service FROM credentials ORDER BY service")
        .expect("Failed to prepare query");

    stmt.query_map([], |row| row.get(0))
        .expect("Failed to query credentials")
        .map(|r| r.expect("Failed to read row"))
        .collect()
}

pub(crate) fn list_services_with_timestamps(conn: &Connection) -> Vec<(String, Option<i64>)> {
    let mut stmt = conn
        .prepare("SELECT service, updated_at FROM credentials ORDER BY service")
        .expect("Failed to prepare query");
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("Failed to query credentials")
        .map(|r| r.expect("Failed to read row"))
        .collect()
}

pub(crate) fn service_exists(conn: &Connection, service: &str) -> bool {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM credentials WHERE service = ?1",
            rusqlite::params![service],
            |row| row.get(0),
        )
        .expect("Failed to query credentials");
    count > 0
}

pub(crate) fn get_all_credentials_raw(conn: &Connection) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut stmt = conn
        .prepare("SELECT service, nonce, ciphertext FROM credentials ORDER BY service")
        .expect("Failed to prepare query");
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("Failed to query credentials")
        .map(|r| r.expect("Failed to read row"))
        .collect()
}

pub(crate) fn find_matching_services(conn: &Connection, query: &str) -> Vec<String> {
    let query_lower = query.to_lowercase();
    let mut stmt = conn
        .prepare(
            "SELECT service FROM credentials WHERE INSTR(LOWER(service), ?1) > 0 ORDER BY service",
        )
        .expect("Failed to prepare query");
    stmt.query_map(rusqlite::params![query_lower], |row| row.get(0))
        .expect("Failed to query credentials")
        .map(|r| r.expect("Failed to read row"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; KEY_LEN] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn);
        conn
    }

    // -- init / metadata (5 tests) --

    #[test]
    fn init_db_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn);
        init_db(&conn); // should not panic
    }

    #[test]
    fn is_first_run_before_metadata() {
        let conn = setup();
        assert!(is_first_run(&conn));
    }

    #[test]
    fn is_first_run_after_metadata() {
        let conn = setup();
        store_metadata(
            &conn,
            &[0u8; 16],
            crypto::KdfParams::CURRENT,
            &[0u8; 24],
            &[0u8; 32],
        );
        assert!(!is_first_run(&conn));
    }

    #[test]
    fn salt_roundtrip() {
        let conn = setup();
        let salt = vec![0xaa; 16];
        store_metadata(
            &conn,
            &salt,
            crypto::KdfParams::CURRENT,
            &[0u8; 24],
            &[0u8; 32],
        );
        assert_eq!(load_salt(&conn), salt);
    }

    #[test]
    fn verify_token_roundtrip() {
        let conn = setup();
        let nonce = vec![0xbb; 24];
        let ct = vec![0xcc; 32];
        store_metadata(&conn, &[0u8; 16], crypto::KdfParams::CURRENT, &nonce, &ct);
        let (n, c) = load_verify_token(&conn);
        assert_eq!(n, nonce);
        assert_eq!(c, ct);
    }

    #[test]
    fn params_roundtrip() {
        let conn = setup();
        store_metadata(
            &conn,
            &[0u8; 16],
            crypto::KdfParams::CURRENT,
            &[0u8; 24],
            &[0u8; 32],
        );
        assert_eq!(load_params(&conn).unwrap(), crypto::KdfParams::CURRENT);
    }

    /// F2: a vault written under parameters that differ from this build's constants
    /// must read back its *own* parameters, not the constants. Before the fix these
    /// columns were written and never read, so such a vault could not be unlocked.
    #[test]
    fn params_roundtrip_when_they_differ_from_current() {
        let conn = setup();
        let old = crypto::KdfParams::validated(2, 32 * 1024, 1).unwrap();
        assert_ne!(
            old,
            crypto::KdfParams::CURRENT,
            "test needs distinct values"
        );

        store_metadata(&conn, &[0u8; 16], old, &[0u8; 24], &[0u8; 32]);
        assert_eq!(load_params(&conn).unwrap(), old);
    }

    /// F2, end to end at the storage layer: this is exactly the sequence
    /// `vault::unlock_vault` runs, minus the TTY prompt. A vault created by a build
    /// whose constants differ from this one's must still verify its master password —
    /// and the second half asserts that the pre-fix code path would *not* have.
    #[test]
    fn vault_created_under_older_params_still_unlocks() {
        let conn = setup();
        let old = crypto::KdfParams::validated(2, 32 * 1024, 1).unwrap();
        assert_ne!(
            old,
            crypto::KdfParams::CURRENT,
            "test needs distinct values"
        );

        // As an older build created it: key derived under `old`, params recorded.
        let salt = [0x11u8; 16];
        let key_at_creation = crypto::derive_key("correct horse", &salt, old);
        let (n, c) = crypto::encrypt_raw(&key_at_creation, VERIFY_PLAINTEXT);
        store_metadata(&conn, &salt, old, &n, &c);

        // As this build unlocks it: parameters come from the vault, not the constants.
        let params = load_params(&conn).unwrap();
        let key = crypto::derive_key("correct horse", &load_salt(&conn), params);
        let (nonce, ct) = load_verify_token(&conn);
        assert!(
            crypto::verify_key(&key, &nonce, &ct),
            "vault created under older parameters must still unlock"
        );

        // What the code did before F2 was fixed: always derive with the constants.
        let pre_fix = crypto::derive_key(
            "correct horse",
            &load_salt(&conn),
            crypto::KdfParams::CURRENT,
        );
        assert!(
            !crypto::verify_key(&pre_fix, &nonce, &ct),
            "deriving with the build's constants is what produced the bogus \
             'Wrong master password.' — if this passes, the test proves nothing"
        );
    }

    /// A tampered or corrupt metadata row yields an error, not a panic in derive_key.
    #[test]
    fn load_params_rejects_corrupt_row() {
        let conn = setup();
        store_metadata(
            &conn,
            &[0u8; 16],
            crypto::KdfParams::CURRENT,
            &[0u8; 24],
            &[0u8; 32],
        );
        conn.execute("UPDATE metadata SET memory_cost = 0 WHERE id = 1", [])
            .unwrap();

        let err = load_params(&conn).unwrap_err();
        assert!(err.contains("Argon2 parameters"), "got: {err}");
    }

    // -- credential CRUD (9 tests) --

    #[test]
    fn add_get_roundtrip() {
        let conn = setup();
        add_credential(
            &conn,
            &TEST_KEY,
            "github",
            "user",
            "pass123",
            "notes",
            "https://github.com",
        );
        let (u, p, n, url, ts) = get_credential(&conn, &TEST_KEY, "github").unwrap().unwrap();
        assert_eq!(u, "user");
        assert_eq!(p, "pass123");
        assert_eq!(n, "notes");
        assert_eq!(url, "https://github.com");
        assert!(ts.is_some());
    }

    #[test]
    fn get_missing_returns_none() {
        let conn = setup();
        assert!(
            get_credential(&conn, &TEST_KEY, "nonexistent")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn add_overwrite_semantics() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "svc", "old_user", "old_pass", "", "");
        add_credential(&conn, &TEST_KEY, "svc", "new_user", "new_pass", "", "");
        let (u, p, _, _, _) = get_credential(&conn, &TEST_KEY, "svc").unwrap().unwrap();
        assert_eq!(u, "new_user");
        assert_eq!(p, "new_pass");
    }

    #[test]
    fn delete_existing() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "svc", "u", "p", "", "");
        assert!(delete_credential(&conn, "svc"));
        assert!(get_credential(&conn, &TEST_KEY, "svc").unwrap().is_none());
    }

    #[test]
    fn delete_nonexistent() {
        let conn = setup();
        assert!(!delete_credential(&conn, "nope"));
    }

    #[test]
    fn update_existing() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "svc", "u1", "p1", "", "");
        assert!(update_credential(
            &conn, &TEST_KEY, "svc", "u2", "p2", "notes", "url", true
        ));
        let (u, p, n, url, _) = get_credential(&conn, &TEST_KEY, "svc").unwrap().unwrap();
        assert_eq!(u, "u2");
        assert_eq!(p, "p2");
        assert_eq!(n, "notes");
        assert_eq!(url, "url");
    }

    #[test]
    fn update_nonexistent() {
        let conn = setup();
        assert!(!update_credential(
            &conn, &TEST_KEY, "svc", "u", "p", "", "", true
        ));
    }

    #[test]
    fn update_preserves_timestamp() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "svc", "u", "p", "", "");
        let ts1 = get_credential(&conn, &TEST_KEY, "svc").unwrap().unwrap().4;
        update_credential(&conn, &TEST_KEY, "svc", "u2", "p2", "", "", false);
        let ts2 = get_credential(&conn, &TEST_KEY, "svc").unwrap().unwrap().4;
        assert_eq!(ts1, ts2);
    }

    #[test]
    fn update_changes_timestamp() {
        let conn = setup();
        let (nonce, ct) = crypto::encrypt(&TEST_KEY, "svc", "u", "p", "", "");
        conn.execute(
            "INSERT INTO credentials (service, nonce, ciphertext, updated_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["svc", nonce, ct, 1000],
        ).unwrap();
        let ts1 = get_credential(&conn, &TEST_KEY, "svc")
            .unwrap()
            .unwrap()
            .4
            .unwrap();
        assert_eq!(ts1, 1000);
        update_credential(&conn, &TEST_KEY, "svc", "u2", "p2", "", "", true);
        let ts2 = get_credential(&conn, &TEST_KEY, "svc")
            .unwrap()
            .unwrap()
            .4
            .unwrap();
        assert!(ts2 > ts1);
    }

    // -- rename (3 tests) --

    #[test]
    fn rename_happy_path() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "old", "u", "p", "n", "url");
        rename_credential(&conn, &TEST_KEY, "old", "new").unwrap();
        assert!(get_credential(&conn, &TEST_KEY, "old").unwrap().is_none());
        let (u, p, n, url, _) = get_credential(&conn, &TEST_KEY, "new").unwrap().unwrap();
        assert_eq!(u, "u");
        assert_eq!(p, "p");
        assert_eq!(n, "n");
        assert_eq!(url, "url");
    }

    #[test]
    fn rename_target_exists() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "a", "u", "p", "", "");
        add_credential(&conn, &TEST_KEY, "b", "u", "p", "", "");
        let err = rename_credential(&conn, &TEST_KEY, "a", "b").unwrap_err();
        assert!(err.contains("already exists"));
    }

    #[test]
    fn rename_source_missing() {
        let conn = setup();
        let err = rename_credential(&conn, &TEST_KEY, "nope", "new").unwrap_err();
        assert!(err.contains("No credential found"));
    }

    // -- listing / search (6 tests) --

    #[test]
    fn list_empty() {
        let conn = setup();
        assert!(list_services(&conn).is_empty());
    }

    #[test]
    fn list_alphabetical_order() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "charlie", "u", "p", "", "");
        add_credential(&conn, &TEST_KEY, "alpha", "u", "p", "", "");
        add_credential(&conn, &TEST_KEY, "bravo", "u", "p", "", "");
        assert_eq!(list_services(&conn), vec!["alpha", "bravo", "charlie"]);
    }

    #[test]
    fn list_with_timestamps() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "svc", "u", "p", "", "");
        let items = list_services_with_timestamps(&conn);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, "svc");
        assert!(items[0].1.is_some());
    }

    #[test]
    fn service_exists_true_and_false() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "exists", "u", "p", "", "");
        assert!(service_exists(&conn, "exists"));
        assert!(!service_exists(&conn, "nope"));
    }

    #[test]
    fn find_matching_case_insensitive() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "GitHub", "u", "p", "", "");
        add_credential(&conn, &TEST_KEY, "GitLab", "u", "p", "", "");
        add_credential(&conn, &TEST_KEY, "BitBucket", "u", "p", "", "");
        let matches = find_matching_services(&conn, "git");
        assert_eq!(matches, vec!["GitHub", "GitLab"]);
    }

    #[test]
    fn find_matching_no_match() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "github", "u", "p", "", "");
        assert!(find_matching_services(&conn, "zzz").is_empty());
    }

    // -- edge cases (3 tests) --

    #[test]
    fn get_all_credentials_raw_returns_blobs() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "svc", "u", "p", "", "");
        let raw = get_all_credentials_raw(&conn);
        assert_eq!(raw.len(), 1);
        assert_eq!(raw[0].0, "svc");
        assert!(!raw[0].1.is_empty());
        assert!(!raw[0].2.is_empty());
    }

    /// F3: a row that will not decrypt returns a diagnosable error rather than
    /// panicking. Before this, the natural follow-up to a failed `sk2 verify` --
    /// `get`, `edit`, `rename`, `export`, `change-password` -- met a raw Rust panic,
    /// in exactly the situation where a user most needs to be told what to do.
    #[test]
    fn corrupt_row_returns_error_rather_than_panicking() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "svc", "u", "p", "", "");
        conn.execute(
            "UPDATE credentials SET ciphertext = X'0001020304' WHERE service = 'svc'",
            [],
        )
        .unwrap();

        let err = get_credential(&conn, &TEST_KEY, "svc").unwrap_err();
        assert!(err.contains("may be corrupt"), "got: {err}");
        assert!(
            err.contains("sk2 verify"),
            "the message must point at the recovery path: {err}"
        );
    }

    /// Same guarantee on the rename path, which decrypts under the old service name
    /// as AAD before re-encrypting under the new one.
    #[test]
    fn corrupt_row_rename_returns_error_rather_than_panicking() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "old", "u", "p", "", "");
        conn.execute(
            "UPDATE credentials SET ciphertext = X'0001020304' WHERE service = 'old'",
            [],
        )
        .unwrap();

        let err = rename_credential(&conn, &TEST_KEY, "old", "new").unwrap_err();
        assert!(err.contains("may be corrupt"), "got: {err}");
        // The original row must survive a failed rename.
        assert!(service_exists(&conn, "old"));
        assert!(!service_exists(&conn, "new"));
    }

    #[test]
    fn sql_injection_resistance() {
        let conn = setup();
        let evil = "'; DROP TABLE credentials; --";
        add_credential(&conn, &TEST_KEY, evil, "u", "p", "", "");
        let result = get_credential(&conn, &TEST_KEY, evil).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "u");
    }

    #[test]
    fn unicode_service_names() {
        let conn = setup();
        add_credential(
            &conn,
            &TEST_KEY,
            "日本語サービス",
            "ユーザー",
            "パスワード",
            "",
            "",
        );
        assert!(service_exists(&conn, "日本語サービス"));
        let (u, _, _, _, _) = get_credential(&conn, &TEST_KEY, "日本語サービス")
            .unwrap()
            .unwrap();
        assert_eq!(u, "ユーザー");
    }
}
