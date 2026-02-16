use rand::RngCore;
use rusqlite::Connection;
use std::io::{self, Write};
use zeroize::Zeroizing;

use crate::constants::*;
use crate::crypto;
use crate::db;

pub(crate) fn prompt(msg: &str) -> String {
    print!("{msg}");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input");
    input.trim().to_string()
}

pub(crate) fn vault_exists(conn: &Connection) -> bool {
    !db::is_first_run(conn)
}

fn require_vault(conn: &Connection) -> Result<(), String> {
    if !vault_exists(conn) {
        return Err("Vault not initialized. Run 'init' first.".into());
    }
    Ok(())
}

pub(crate) fn restrict_db_permissions(path: &std::path::Path) {
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

fn read_master_password() -> Result<Zeroizing<String>, String> {
    let password = Zeroizing::new(
        rpassword::read_password_from_tty(Some("Master password: "))
            .expect("Failed to read password"),
    );

    if password.is_empty() {
        return Err("Password cannot be empty.".into());
    }

    Ok(password)
}

pub(crate) fn init_vault(conn: &Connection) -> Result<(), String> {
    if vault_exists(conn) {
        return Err("Vault already initialized.".into());
    }

    let password = Zeroizing::new(
        rpassword::read_password_from_tty(Some("Set master password: "))
            .expect("Failed to read password"),
    );

    if password.is_empty() {
        return Err("Password cannot be empty.".into());
    }

    let confirm = Zeroizing::new(
        rpassword::read_password_from_tty(Some("Confirm master password: "))
            .expect("Failed to read password"),
    );

    if password != confirm {
        return Err("Passwords do not match.".into());
    }

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = crypto::derive_key(&password, &salt);
    let (verify_nonce, verify_ciphertext) = crypto::encrypt_raw(&key, VERIFY_PLAINTEXT);
    db::store_metadata(conn, &salt, &verify_nonce, &verify_ciphertext);

    println!("Vault initialized.");
    Ok(())
}

pub(crate) fn unlock_vault(conn: &Connection) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    require_vault(conn)?;
    let master_password = read_master_password()?;
    let salt = db::load_salt(conn);
    let key = crypto::derive_key(&master_password, &salt);

    let (nonce, ciphertext) = db::load_verify_token(conn);
    if !crypto::verify_key(&key, &nonce, &ciphertext) {
        return Err("Wrong master password.".into());
    }

    Ok(key)
}

pub(crate) fn change_password(conn: &Connection) -> Result<(), String> {
    require_vault(conn)?;

    let old_password = read_master_password()?;
    let salt = db::load_salt(conn);
    let old_key = crypto::derive_key(&old_password, &salt);
    let (nonce, ciphertext) = db::load_verify_token(conn);
    if !crypto::verify_key(&old_key, &nonce, &ciphertext) {
        return Err("Wrong master password.".into());
    }

    let new_password = Zeroizing::new(
        rpassword::read_password_from_tty(Some("New master password: "))
            .expect("Failed to read password"),
    );
    if new_password.is_empty() {
        return Err("Password cannot be empty.".into());
    }
    let confirm = Zeroizing::new(
        rpassword::read_password_from_tty(Some("Confirm new master password: "))
            .expect("Failed to read password"),
    );
    if new_password != confirm {
        return Err("Passwords do not match.".into());
    }

    let mut new_salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut new_salt);
    let new_key = crypto::derive_key(&new_password, &new_salt);

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
        let (username, password) = crypto::decrypt(&old_key, service, nonce, ciphertext)
            .expect("Data corruption — failed to decrypt credential during password change");
        let (new_nonce, new_ciphertext) = crypto::encrypt(&new_key, service, &username, &password);
        tx.execute(
            "UPDATE credentials SET nonce = ?1, ciphertext = ?2 WHERE service = ?3",
            rusqlite::params![new_nonce, new_ciphertext, service],
        )
        .expect("Failed to update credential");
    }

    // Re-encrypt verification token and update metadata with new salt
    let (verify_nonce, verify_ciphertext) = crypto::encrypt_raw(&new_key, VERIFY_PLAINTEXT);
    tx.execute(
        "UPDATE metadata SET salt = ?1, time_cost = ?2, memory_cost = ?3, parallelism = ?4, verify_nonce = ?5, verify_ciphertext = ?6 WHERE id = 1",
        rusqlite::params![new_salt.as_slice(), TIME_COST, MEMORY_COST, PARALLELISM, verify_nonce, verify_ciphertext],
    )
    .expect("Failed to update metadata");

    tx.commit().expect("Failed to commit transaction");
    println!("Master password changed.");
    Ok(())
}
