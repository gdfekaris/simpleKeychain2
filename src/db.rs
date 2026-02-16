use rusqlite::Connection;

use crate::constants::*;
use crate::crypto;

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

pub(crate) fn add_credential(conn: &Connection, key: &[u8; KEY_LEN], service: &str, username: &str, password: &str) {
    let (nonce, ciphertext) = crypto::encrypt(key, service, username, password);
    conn.execute(
        "INSERT OR REPLACE INTO credentials (service, nonce, ciphertext)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![service, nonce, ciphertext],
    )
    .expect("Failed to store credential");
}

pub(crate) fn get_credential(conn: &Connection, key: &[u8; KEY_LEN], service: &str) -> Option<(String, String)> {
    let result = conn.query_row(
        "SELECT nonce, ciphertext FROM credentials WHERE service = ?1",
        rusqlite::params![service],
        |row| {
            let nonce: Vec<u8> = row.get(0)?;
            let ciphertext: Vec<u8> = row.get(1)?;
            Ok((nonce, ciphertext))
        },
    );

    match result {
        Ok((nonce, ciphertext)) => {
            let (username, password) = crypto::decrypt(key, service, &nonce, &ciphertext)
                .expect("Data corruption — failed to decrypt credential");
            Some((username, password))
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

pub(crate) fn list_services(conn: &Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT service FROM credentials ORDER BY service")
        .expect("Failed to prepare query");

    stmt.query_map([], |row| row.get(0))
        .expect("Failed to query credentials")
        .map(|r| r.expect("Failed to read row"))
        .collect()
}
