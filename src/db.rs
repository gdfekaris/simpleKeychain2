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
