use arboard::Clipboard;
use argon2::{Argon2, Algorithm, Version, Params};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, Key};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use clap::{Parser, Subcommand};
use rand::RngCore;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::process;
use std::thread;
use std::time::Duration;
use zeroize::Zeroizing;

const TIME_COST: u32 = 4;
const MEMORY_COST: u32 = 128 * 1024; // 128 MiB
const PARALLELISM: u32 = 4;
const KEY_LEN: usize = 32;
const VERIFY_PLAINTEXT: &[u8] = b"sk2-vault-ok";
const CLIPBOARD_CLEAR_SECONDS: u64 = 10;

fn vault_path() -> std::path::PathBuf {
    let dir = dirs::home_dir()
        .expect("Could not determine home directory")
        .join(".sk2");
    std::fs::create_dir_all(&dir).expect("Failed to create vault directory");
    dir.join("vault.db")
}

#[derive(Parser)]
#[command(name = "sk2", about = "A local-only CLI password manager")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Internal: clear clipboard after N seconds (used by spawned child)
    #[arg(long = "clear-clipboard", hide = true)]
    clear_clipboard: Option<u64>,
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
    /// Change the master password
    ChangePassword,
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

fn derive_key(master_password: &str, salt: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(KEY_LEN))
        .expect("Invalid Argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut *key)
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

fn encrypt(key: &[u8; KEY_LEN], service: &str, username: &str, password: &str) -> (Vec<u8>, Vec<u8>) {
    let cred = Credential {
        username: username.to_string(),
        password: password.to_string(),
    };
    let plaintext = serde_json::to_vec(&cred).expect("Failed to serialize credential");

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, Payload {
        msg: plaintext.as_ref(),
        aad: service.as_bytes(),
    }).expect("Encryption failed");
    (nonce_bytes.to_vec(), ciphertext)
}

fn decrypt(key: &[u8; KEY_LEN], service: &str, nonce: &[u8], ciphertext: &[u8]) -> Result<(String, String), ()> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce);

    let plaintext = cipher.decrypt(nonce, Payload {
        msg: ciphertext,
        aad: service.as_bytes(),
    }).map_err(|_| ())?;

    let cred: Credential =
        serde_json::from_slice(&plaintext).map_err(|_| ())?;
    Ok((cred.username, cred.password))
}

// --- Credential storage ---

fn add_credential(conn: &Connection, key: &[u8; KEY_LEN], service: &str, username: &str, password: &str) {
    let (nonce, ciphertext) = encrypt(key, service, username, password);
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
            let (username, password) = decrypt(key, service, &nonce, &ciphertext)
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

fn restrict_db_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(parent) = path.parent() {
            let dir_perms = std::fs::Permissions::from_mode(0o700);
            if let Err(e) = std::fs::set_permissions(parent, dir_perms) {
                eprintln!("Warning: could not set directory permissions: {e}");
            }
        }
        let file_perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(path, file_perms) {
            eprintln!("Warning: could not set database permissions: {e}");
        }
    }
}

fn read_master_password() -> Zeroizing<String> {
    let password = Zeroizing::new(
        rpassword::read_password_from_tty(Some("Master password: "))
            .expect("Failed to read password"),
    );

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

    let password = Zeroizing::new(
        rpassword::read_password_from_tty(Some("Set master password: "))
            .expect("Failed to read password"),
    );

    if password.is_empty() {
        eprintln!("Password cannot be empty.");
        process::exit(1);
    }

    let confirm = Zeroizing::new(
        rpassword::read_password_from_tty(Some("Confirm master password: "))
            .expect("Failed to read password"),
    );

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

fn unlock_vault(conn: &Connection) -> Zeroizing<[u8; KEY_LEN]> {
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

fn change_password(conn: &Connection) {
    require_vault(conn);

    let old_password = read_master_password();
    let salt = load_salt(conn);
    let old_key = derive_key(&old_password, &salt);
    if !verify_key(conn, &old_key) {
        eprintln!("Wrong master password.");
        process::exit(1);
    }

    let new_password = Zeroizing::new(
        rpassword::read_password_from_tty(Some("New master password: "))
            .expect("Failed to read password"),
    );
    if new_password.is_empty() {
        eprintln!("Password cannot be empty.");
        process::exit(1);
    }
    let confirm = Zeroizing::new(
        rpassword::read_password_from_tty(Some("Confirm new master password: "))
            .expect("Failed to read password"),
    );
    if new_password != confirm {
        eprintln!("Passwords do not match.");
        process::exit(1);
    }

    let mut new_salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut new_salt);
    let new_key = derive_key(&new_password, &new_salt);

    let tx = conn.unchecked_transaction().expect("Failed to begin transaction");

    // Re-encrypt all credentials
    let mut stmt = tx
        .prepare("SELECT service, nonce, ciphertext FROM credentials")
        .expect("Failed to prepare query");
    let rows: Vec<(String, Vec<u8>, Vec<u8>)> = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .expect("Failed to query credentials")
        .map(|r| r.expect("Failed to read row"))
        .collect();
    drop(stmt);

    for (service, nonce, ciphertext) in &rows {
        let (username, password) = decrypt(&old_key, service, nonce, ciphertext)
            .expect("Data corruption — failed to decrypt credential during password change");
        let (new_nonce, new_ciphertext) = encrypt(&new_key, service, &username, &password);
        tx.execute(
            "UPDATE credentials SET nonce = ?1, ciphertext = ?2 WHERE service = ?3",
            rusqlite::params![new_nonce, new_ciphertext, service],
        )
        .expect("Failed to update credential");
    }

    // Re-encrypt verification token and update metadata with new salt
    let (verify_nonce, verify_ciphertext) = encrypt_raw(&new_key, VERIFY_PLAINTEXT);
    tx.execute(
        "UPDATE metadata SET salt = ?1, time_cost = ?2, memory_cost = ?3, parallelism = ?4, verify_nonce = ?5, verify_ciphertext = ?6 WHERE id = 1",
        rusqlite::params![new_salt.as_slice(), TIME_COST, MEMORY_COST, PARALLELISM, verify_nonce, verify_ciphertext],
    )
    .expect("Failed to update metadata");

    tx.commit().expect("Failed to commit transaction");
    println!("Master password changed.");
}

// --- Main ---

fn main() {
    let cli = Cli::parse();

    // Hidden mode: clear clipboard after a delay, then exit.
    if let Some(seconds) = cli.clear_clipboard {
        thread::sleep(Duration::from_secs(seconds));
        if let Ok(mut clipboard) = Clipboard::new() {
            let _ = clipboard.set_text("");
        }
        return;
    }

    let command = cli.command.unwrap_or_else(|| {
        eprintln!("No command provided. Run with --help for usage.");
        process::exit(1);
    });

    let db_path = vault_path();
    let conn = Connection::open(&db_path).expect("Failed to open database");
    restrict_db_permissions(&db_path);
    init_db(&conn);

    match command {
        Command::Init => {
            init_vault(&conn);
        }

        Command::Add { service } => {
            let key = unlock_vault(&conn);
            let username = prompt("Username: ");
            let password = Zeroizing::new(
                rpassword::read_password_from_tty(Some("Password: "))
                    .expect("Failed to read password"),
            );

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
                    let password = Zeroizing::new(password);
                    let mut clipboard = Clipboard::new().unwrap_or_else(|e| {
                        eprintln!("Failed to access clipboard: {e}");
                        process::exit(1);
                    });
                    clipboard.set_text(&*password).unwrap_or_else(|e| {
                        eprintln!("Failed to copy to clipboard: {e}");
                        process::exit(1);
                    });

                    // Spawn a detached child process to clear the clipboard after the timeout.
                    match std::env::current_exe() {
                        Ok(exe) => {
                            let result = process::Command::new(exe)
                                .arg("--clear-clipboard")
                                .arg(CLIPBOARD_CLEAR_SECONDS.to_string())
                                .stdin(process::Stdio::null())
                                .stdout(process::Stdio::null())
                                .stderr(process::Stdio::null())
                                .spawn();
                            if let Err(e) = result {
                                eprintln!("Warning: could not spawn clipboard-clear process: {e}");
                            }
                        }
                        Err(e) => {
                            eprintln!("Warning: could not determine executable path: {e}");
                        }
                    }

                    println!("Service:  {service}");
                    println!("Username: {username}");
                    println!("Password copied to clipboard (will be cleared in {CLIPBOARD_CLEAR_SECONDS}s).");
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

        Command::ChangePassword => {
            change_password(&conn);
        }
    }
}
