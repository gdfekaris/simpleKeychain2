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

pub(crate) fn store_metadata(conn: &Connection, salt: &[u8], verify_nonce: &[u8], verify_ciphertext: &[u8]) {
    conn.execute(
        "INSERT INTO metadata (id, salt, time_cost, memory_cost, parallelism, verify_nonce, verify_ciphertext)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![salt, TIME_COST, MEMORY_COST, PARALLELISM, verify_nonce, verify_ciphertext],
    )
    .expect("Failed to store metadata");
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

pub(crate) fn add_credential(conn: &Connection, key: &[u8; KEY_LEN], service: &str, username: &str, password: &str, notes: &str, url: &str) {
    let (nonce, ciphertext) = crypto::encrypt(key, service, username, password, notes, url);
    conn.execute(
        "INSERT OR REPLACE INTO credentials (service, nonce, ciphertext, updated_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![service, nonce, ciphertext, unix_now()],
    )
    .expect("Failed to store credential");
}

pub(crate) fn get_credential(conn: &Connection, key: &[u8; KEY_LEN], service: &str) -> Option<(String, String, String, String, Option<i64>)> {
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
            let (username, password, notes, url) = crypto::decrypt(key, service, &nonce, &ciphertext)
                .expect("Data corruption — failed to decrypt credential");
            Some((username, password, notes, url, updated_at))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
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

pub(crate) fn rename_credential(conn: &Connection, key: &[u8; KEY_LEN], old_service: &str, new_service: &str) -> Result<(), String> {
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
        .expect("Data corruption — failed to decrypt credential");

    let (new_nonce, new_ciphertext) = crypto::encrypt(key, new_service, &username, &password, &notes, &url);

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
        .prepare("SELECT service FROM credentials WHERE INSTR(LOWER(service), ?1) > 0 ORDER BY service")
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
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
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
        store_metadata(&conn, &[0u8; 16], &[0u8; 24], &[0u8; 32]);
        assert!(!is_first_run(&conn));
    }

    #[test]
    fn salt_roundtrip() {
        let conn = setup();
        let salt = vec![0xaa; 16];
        store_metadata(&conn, &salt, &[0u8; 24], &[0u8; 32]);
        assert_eq!(load_salt(&conn), salt);
    }

    #[test]
    fn verify_token_roundtrip() {
        let conn = setup();
        let nonce = vec![0xbb; 24];
        let ct = vec![0xcc; 32];
        store_metadata(&conn, &[0u8; 16], &nonce, &ct);
        let (n, c) = load_verify_token(&conn);
        assert_eq!(n, nonce);
        assert_eq!(c, ct);
    }

    // -- credential CRUD (9 tests) --

    #[test]
    fn add_get_roundtrip() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "github", "user", "pass123", "notes", "https://github.com");
        let (u, p, n, url, ts) = get_credential(&conn, &TEST_KEY, "github").unwrap();
        assert_eq!(u, "user");
        assert_eq!(p, "pass123");
        assert_eq!(n, "notes");
        assert_eq!(url, "https://github.com");
        assert!(ts.is_some());
    }

    #[test]
    fn get_missing_returns_none() {
        let conn = setup();
        assert!(get_credential(&conn, &TEST_KEY, "nonexistent").is_none());
    }

    #[test]
    fn add_overwrite_semantics() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "svc", "old_user", "old_pass", "", "");
        add_credential(&conn, &TEST_KEY, "svc", "new_user", "new_pass", "", "");
        let (u, p, _, _, _) = get_credential(&conn, &TEST_KEY, "svc").unwrap();
        assert_eq!(u, "new_user");
        assert_eq!(p, "new_pass");
    }

    #[test]
    fn delete_existing() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "svc", "u", "p", "", "");
        assert!(delete_credential(&conn, "svc"));
        assert!(get_credential(&conn, &TEST_KEY, "svc").is_none());
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
        assert!(update_credential(&conn, &TEST_KEY, "svc", "u2", "p2", "notes", "url", true));
        let (u, p, n, url, _) = get_credential(&conn, &TEST_KEY, "svc").unwrap();
        assert_eq!(u, "u2");
        assert_eq!(p, "p2");
        assert_eq!(n, "notes");
        assert_eq!(url, "url");
    }

    #[test]
    fn update_nonexistent() {
        let conn = setup();
        assert!(!update_credential(&conn, &TEST_KEY, "svc", "u", "p", "", "", true));
    }

    #[test]
    fn update_preserves_timestamp() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "svc", "u", "p", "", "");
        let ts1 = get_credential(&conn, &TEST_KEY, "svc").unwrap().4;
        update_credential(&conn, &TEST_KEY, "svc", "u2", "p2", "", "", false);
        let ts2 = get_credential(&conn, &TEST_KEY, "svc").unwrap().4;
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
        let ts1 = get_credential(&conn, &TEST_KEY, "svc").unwrap().4.unwrap();
        assert_eq!(ts1, 1000);
        update_credential(&conn, &TEST_KEY, "svc", "u2", "p2", "", "", true);
        let ts2 = get_credential(&conn, &TEST_KEY, "svc").unwrap().4.unwrap();
        assert!(ts2 > ts1);
    }

    // -- rename (3 tests) --

    #[test]
    fn rename_happy_path() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "old", "u", "p", "n", "url");
        rename_credential(&conn, &TEST_KEY, "old", "new").unwrap();
        assert!(get_credential(&conn, &TEST_KEY, "old").is_none());
        let (u, p, n, url, _) = get_credential(&conn, &TEST_KEY, "new").unwrap();
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

    #[test]
    fn sql_injection_resistance() {
        let conn = setup();
        let evil = "'; DROP TABLE credentials; --";
        add_credential(&conn, &TEST_KEY, evil, "u", "p", "", "");
        let result = get_credential(&conn, &TEST_KEY, evil);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "u");
    }

    #[test]
    fn unicode_service_names() {
        let conn = setup();
        add_credential(&conn, &TEST_KEY, "日本語サービス", "ユーザー", "パスワード", "", "");
        assert!(service_exists(&conn, "日本語サービス"));
        let (u, _, _, _, _) = get_credential(&conn, &TEST_KEY, "日本語サービス").unwrap();
        assert_eq!(u, "ユーザー");
    }
}
