use arboard::Clipboard;
use argon2::{Argon2, Algorithm, Version, Params};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, Key};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use clap::{Parser, Subcommand};
use rand::RngCore;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::process;
use std::thread;
use std::time::Duration;

const DB_PATH: &str = "vault.db";
const TIME_COST: u32 = 3;
const MEMORY_COST: u32 = 64 * 1024; // 64 MiB
const PARALLELISM: u32 = 4;
const KEY_LEN: usize = 32;
const VERIFY_PLAINTEXT: &[u8] = b"sk2-vault-ok";

#[derive(Parser)]
#[command(name = "sk2", about = "A local-only CLI password manager")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new vault (set master password)
    Init,
    /// Add or update a credential for a service
    Add {
        /// The service name (e.g. "github", "gmail")
        service: String,
    },
    /// Retrieve a credential by service name
    Get {
        /// The service name to look up
        service: String,
    },
    /// Delete a credential by service name
    Delete {
        /// The service name to delete
        service: String,
    },
    /// List all stored service names
    List,
}

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

fn is_first_run(conn: &Connection) -> bool {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM metadata", [], |row| row.get(0))
        .expect("Failed to query metadata");
    count == 0
}

fn store_metadata(conn: &Connection, salt: &[u8], verify_nonce: &[u8], verify_ciphertext: &[u8]) {
    conn.execute(
        "INSERT INTO metadata (id, salt, time_cost, memory_cost, parallelism, verify_nonce, verify_ciphertext)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![salt, TIME_COST, MEMORY_COST, PARALLELISM, verify_nonce, verify_ciphertext],
    )
    .expect("Failed to store metadata");
}

fn load_salt(conn: &Connection) -> Vec<u8> {
    conn.query_row("SELECT salt FROM metadata WHERE id = 1", [], |row| {
        row.get(0)
    })
    .expect("Failed to load salt")
}

fn load_verify_token(conn: &Connection) -> (Vec<u8>, Vec<u8>) {
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

fn encrypt_raw(key: &[u8; KEY_LEN], plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("Encryption failed");
    (nonce_bytes.to_vec(), ciphertext)
}

fn decrypt_raw(key: &[u8; KEY_LEN], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext).map_err(|_| ())
}

fn verify_key(conn: &Connection, key: &[u8; KEY_LEN]) -> bool {
    let (nonce, ciphertext) = load_verify_token(conn);
    match decrypt_raw(key, &nonce, &ciphertext) {
        Ok(plaintext) => plaintext == VERIFY_PLAINTEXT,
        Err(()) => false,
    }
}

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

fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8], ciphertext: &[u8]) -> Result<(String, String), ()> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce);

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| ())?;

    let cred: Credential =
        serde_json::from_slice(&plaintext).map_err(|_| ())?;
    Ok((cred.username, cred.password))
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
        Ok((nonce, ciphertext)) => {
            let (username, password) = decrypt(key, &nonce, &ciphertext)
                .expect("Data corruption — failed to decrypt credential");
            Some((username, password))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => panic!("Database error: {e}"),
    }
}

fn delete_credential(conn: &Connection, service: &str) -> bool {
    let rows = conn
        .execute(
            "DELETE FROM credentials WHERE service = ?1",
            rusqlite::params![service],
        )
        .expect("Failed to delete credential");
    rows > 0
}

fn list_services(conn: &Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT service FROM credentials ORDER BY service")
        .expect("Failed to prepare query");

    stmt.query_map([], |row| row.get(0))
        .expect("Failed to query credentials")
        .map(|r| r.expect("Failed to read row"))
        .collect()
}

// --- Helpers ---

fn prompt(msg: &str) -> String {
    print!("{msg}");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input");
    input.trim().to_string()
}

fn vault_exists(conn: &Connection) -> bool {
    !is_first_run(conn)
}

fn require_vault(conn: &Connection) {
    if !vault_exists(conn) {
        eprintln!("Vault not initialized. Run 'init' first.");
        process::exit(1);
    }
}

fn read_master_password() -> String {
    let password = rpassword::read_password_from_tty(Some("Master password: "))
        .expect("Failed to read password");

    if password.is_empty() {
        eprintln!("Password cannot be empty.");
        process::exit(1);
    }

    password
}

fn init_vault(conn: &Connection) {
    if vault_exists(conn) {
        eprintln!("Vault already initialized.");
        process::exit(1);
    }

    let password = rpassword::read_password_from_tty(Some("Set master password: "))
        .expect("Failed to read password");

    if password.is_empty() {
        eprintln!("Password cannot be empty.");
        process::exit(1);
    }

    let confirm = rpassword::read_password_from_tty(Some("Confirm master password: "))
        .expect("Failed to read password");

    if password != confirm {
        eprintln!("Passwords do not match.");
        process::exit(1);
    }

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(&password, &salt);
    let (verify_nonce, verify_ciphertext) = encrypt_raw(&key, VERIFY_PLAINTEXT);
    store_metadata(conn, &salt, &verify_nonce, &verify_ciphertext);

    println!("Vault initialized.");
}

fn unlock_vault(conn: &Connection) -> [u8; KEY_LEN] {
    require_vault(conn);
    let master_password = read_master_password();
    let salt = load_salt(conn);
    let key = derive_key(&master_password, &salt);

    if !verify_key(conn, &key) {
        eprintln!("Wrong master password.");
        process::exit(1);
    }

    key
}

// --- Main ---

fn main() {
    let cli = Cli::parse();

    let conn = Connection::open(DB_PATH).expect("Failed to open database");
    init_db(&conn);

    match cli.command {
        Command::Init => {
            init_vault(&conn);
        }

        Command::Add { service } => {
            let key = unlock_vault(&conn);
            let username = prompt("Username: ");
            let password = rpassword::read_password_from_tty(Some("Password: "))
                .expect("Failed to read password");

            if password.is_empty() {
                eprintln!("Password cannot be empty.");
                process::exit(1);
            }

            add_credential(&conn, &key, &service, &username, &password);
            println!("Credential stored for '{service}'.");
        }

        Command::Get { service } => {
            let key = unlock_vault(&conn);
            match get_credential(&conn, &key, &service) {
                Some((username, password)) => {
                    let mut clipboard = Clipboard::new().unwrap_or_else(|e| {
                        eprintln!("Failed to access clipboard: {e}");
                        process::exit(1);
                    });
                    clipboard.set_text(&password).unwrap_or_else(|e| {
                        eprintln!("Failed to copy to clipboard: {e}");
                        process::exit(1);
                    });
                    println!("Service:  {service}");
                    println!("Username: {username}");
                    println!("Password copied to clipboard.");
                    // Brief pause so the clipboard manager can grab the contents
                    // before the process exits (needed on Linux/Wayland).
                    thread::sleep(Duration::from_millis(100));
                }
                None => {
                    eprintln!("No credential found for '{service}'.");
                    process::exit(1);
                }
            }
        }

        Command::Delete { service } => {
            unlock_vault(&conn);
            if delete_credential(&conn, &service) {
                println!("Credential for '{service}' deleted.");
            } else {
                eprintln!("No credential found for '{service}'.");
                process::exit(1);
            }
        }

        Command::List => {
            unlock_vault(&conn);
            let services = list_services(&conn);
            if services.is_empty() {
                println!("No credentials stored.");
            } else {
                println!("Stored credentials:");
                for s in &services {
                    println!("  {s}");
                }
            }
        }
    }
}
