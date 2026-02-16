use argon2::{Argon2, Algorithm, Version, Params};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, Key};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use rand::RngCore;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

const DB_PATH: &str = "vault.db";
const TIME_COST: u32 = 3;
const MEMORY_COST: u32 = 64 * 1024; // 64 MiB
const PARALLELISM: u32 = 4;
const KEY_LEN: usize = 32;

#[derive(Serialize, Deserialize)]
struct Credential {
    username: String,
    password: String,
}

// --- Database ---

fn init_db(conn: &Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS metadata (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            time_cost INTEGER NOT NULL,
            memory_cost INTEGER NOT NULL,
            parallelism INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS credentials (
            service TEXT PRIMARY KEY,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL
        );",
    )
    .expect("Failed to initialize database");
}

fn is_first_run(conn: &Connection) -> bool {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM metadata", [], |row| row.get(0))
        .expect("Failed to query metadata");
    count == 0
}

fn store_salt(conn: &Connection, salt: &[u8]) {
    conn.execute(
        "INSERT INTO metadata (id, salt, time_cost, memory_cost, parallelism)
         VALUES (1, ?1, ?2, ?3, ?4)",
        rusqlite::params![salt, TIME_COST, MEMORY_COST, PARALLELISM],
    )
    .expect("Failed to store salt");
}

fn load_salt(conn: &Connection) -> Vec<u8> {
    conn.query_row("SELECT salt FROM metadata WHERE id = 1", [], |row| {
        row.get(0)
    })
    .expect("Failed to load salt")
}

// --- Key derivation ---

fn derive_key(master_password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(KEY_LEN))
        .expect("Invalid Argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut key)
        .expect("Key derivation failed");
    key
}

// --- Encryption ---

fn encrypt(key: &[u8; KEY_LEN], username: &str, password: &str) -> (Vec<u8>, Vec<u8>) {
    let cred = Credential {
        username: username.to_string(),
        password: password.to_string(),
    };
    let plaintext = serde_json::to_vec(&cred).expect("Failed to serialize credential");

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("Encryption failed");
    (nonce_bytes.to_vec(), ciphertext)
}

fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8], ciphertext: &[u8]) -> (String, String) {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .expect("Decryption failed — wrong master password?");

    let cred: Credential =
        serde_json::from_slice(&plaintext).expect("Failed to deserialize credential");
    (cred.username, cred.password)
}

// --- Credential storage ---

fn add_credential(conn: &Connection, key: &[u8; KEY_LEN], service: &str, username: &str, password: &str) {
    let (nonce, ciphertext) = encrypt(key, username, password);
    conn.execute(
        "INSERT OR REPLACE INTO credentials (service, nonce, ciphertext)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![service, nonce, ciphertext],
    )
    .expect("Failed to store credential");
}

fn get_credential(conn: &Connection, key: &[u8; KEY_LEN], service: &str) -> Option<(String, String)> {
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
        Ok((nonce, ciphertext)) => Some(decrypt(key, &nonce, &ciphertext)),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => panic!("Database error: {e}"),
    }
}

// --- Helpers ---

fn prompt(msg: &str) -> String {
    print!("{msg}");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input");
    input.trim().to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- Main ---

fn main() {
    let conn = Connection::open(DB_PATH).expect("Failed to open database");
    init_db(&conn);

    let master_password = rpassword::read_password_from_tty(Some("Enter master password: "))
        .expect("Failed to read password");

    if master_password.is_empty() {
        eprintln!("Password cannot be empty.");
        std::process::exit(1);
    }

    let salt = if is_first_run(&conn) {
        println!("First run — initializing vault.");
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        store_salt(&conn, &salt);
        salt.to_vec()
    } else {
        load_salt(&conn)
    };

    let key = derive_key(&master_password, &salt);
    println!("Derived key: {}", hex(&key));

    // --- Demo: add a credential and read it back ---
    let service = prompt("Service name: ");
    let username = prompt("Username: ");
    let password = rpassword::read_password_from_tty(Some("Password: "))
        .expect("Failed to read password");

    add_credential(&conn, &key, &service, &username, &password);
    println!("Credential stored for '{service}'.");

    // Read it back to verify round-trip
    match get_credential(&conn, &key, &service) {
        Some((u, p)) => {
            println!("Round-trip verification for '{service}':");
            println!("  Username: {u}");
            println!("  Password: {p}");
        }
        None => eprintln!("Failed to retrieve credential!"),
    }
}
