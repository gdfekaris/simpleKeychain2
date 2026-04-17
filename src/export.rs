use rusqlite::Connection;
use std::fs::File;
use std::io::{self, Write};
use std::process;
use zeroize::Zeroizing;

use crate::backup;
use crate::constants::*;
use crate::db;
use crate::ui;
use crate::vault;

fn csv_escape(field: &str) -> String {
    format!("\"{}\"", field.replace('"', "\"\""))
}

fn open_output(path: &str, overwrite: bool) -> Result<File, String> {
    if overwrite {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("Failed to remove existing file '{path}': {e}")),
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            format!("Output file '{path}' already exists. Pass --overwrite to replace it.")
        } else {
            format!("Failed to open output file '{path}': {e}")
        }
    })
}

fn read_backup_passphrase() -> Result<Zeroizing<String>, String> {
    ui::password_prompt("Backup passphrase: ");
    let p1 =
        Zeroizing::new(rpassword::read_password_from_tty(None).expect("Failed to read password"));
    if p1.is_empty() {
        return Err("Backup passphrase cannot be empty.".into());
    }
    ui::password_prompt("Confirm backup passphrase: ");
    let p2 =
        Zeroizing::new(rpassword::read_password_from_tty(None).expect("Failed to read password"));
    if *p1 != *p2 {
        return Err("Backup passphrases do not match.".into());
    }
    Ok(p1)
}

pub(crate) fn export_sk2b(
    conn: &Connection,
    key: &[u8; KEY_LEN],
    output: &str,
    overwrite: bool,
) -> Result<(), String> {
    let services = db::list_services(conn);
    if services.is_empty() {
        ui::muted("No credentials to export.");
        return Ok(());
    }

    ui::warning_block(&[
        "This will export ALL stored credentials into an encrypted sk2 backup (.sk2backup).",
        "The backup can be decrypted only with 'sk2 import' and the passphrase you choose next.",
        "Anyone with the backup passphrase can read your passwords.",
    ]);
    println!();
    let answer = vault::prompt("Type 'yes' to continue: ");
    if answer != "yes" {
        return Err("Export cancelled.".into());
    }

    let passphrase = read_backup_passphrase()?;

    let blob = backup::export_vault(conn, key, &passphrase)?;

    let mut file = open_output(output, overwrite)?;
    file.write_all(&blob)
        .map_err(|e| format!("Failed to write backup to '{output}': {e}"))?;
    file.sync_all()
        .map_err(|e| format!("Failed to flush backup to disk: {e}"))?;

    let count = services.len();
    println!();
    ui::success(&format!("Exported {count} credential(s) to: {output}"));
    ui::muted("Format: SK2B (Argon2id + XChaCha20-Poly1305). Permissions: 0600.");
    println!();
    ui::info("To restore", &format!("sk2 import {output}"));
    ui::reminder("REMINDER: Delete this file once you no longer need it.");

    Ok(())
}

pub(crate) fn export_gpg(
    conn: &Connection,
    key: &[u8; KEY_LEN],
    output: &str,
    overwrite: bool,
) -> Result<(), String> {
    let gpg_check = process::Command::new("gpg")
        .arg("--version")
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status();
    match gpg_check {
        Ok(status) if status.success() => {}
        _ => {
            return Err(
                "GPG is not installed or not found in PATH. Install GPG to use --format gpg."
                    .into(),
            );
        }
    }

    let services = db::list_services(conn);
    if services.is_empty() {
        ui::muted("No credentials to export.");
        return Ok(());
    }

    ui::warning_block(&[
        "This will export ALL stored credentials into a GPG-encrypted file (legacy format).",
        &format!("The file can be decrypted with: gpg -d {output}"),
        "Anyone with the export passphrase can read your passwords.",
        "Note: .sk2backup uses a stronger KDF and is the recommended format.",
    ]);
    println!();
    let answer = vault::prompt("Type 'yes' to continue: ");
    if answer != "yes" {
        return Err("Export cancelled.".into());
    }

    let mut csv = Zeroizing::new(String::from("name,username,password,notes,url\n"));
    for service in &services {
        match db::get_credential(conn, key, service) {
            Some((username, password, notes, url, _)) => {
                let password = Zeroizing::new(password);
                csv.push_str(&csv_escape(service));
                csv.push(',');
                csv.push_str(&csv_escape(&username));
                csv.push(',');
                csv.push_str(&csv_escape(&password));
                csv.push(',');
                csv.push_str(&csv_escape(&notes));
                csv.push(',');
                csv.push_str(&csv_escape(&url));
                csv.push('\n');
            }
            None => {
                ui::warning(&format!(
                    "Could not decrypt credential for '{service}', skipping."
                ));
            }
        }
    }

    // Open our own output file (H7 fix: do not let gpg --output create the file).
    let mut file = open_output(output, overwrite)?;

    let mut child = process::Command::new("gpg")
        .arg("--symmetric")
        .arg("--cipher-algo")
        .arg("AES256")
        .stdin(process::Stdio::piped())
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to start GPG: {e}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "Failed to open GPG stdin".to_string())?;
    let writer = std::thread::spawn(move || -> io::Result<()> {
        stdin.write_all(csv.as_bytes())?;
        // csv (Zeroizing) drops here; stdin closes to signal EOF to GPG.
        Ok(())
    });

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Failed to open GPG stdout".to_string())?;
    io::copy(&mut stdout, &mut file)
        .map_err(|e| format!("Failed to write GPG output to '{output}': {e}"))?;

    writer
        .join()
        .map_err(|_| "GPG writer thread panicked".to_string())?
        .map_err(|e| format!("Failed to feed CSV into GPG: {e}"))?;

    let status = child
        .wait()
        .map_err(|e| format!("Failed to wait for GPG: {e}"))?;
    if !status.success() {
        // File will be a partial GPG stream; remove it so users aren't misled.
        let _ = std::fs::remove_file(output);
        return Err("GPG encryption failed.".into());
    }

    file.sync_all()
        .map_err(|e| format!("Failed to flush GPG output to disk: {e}"))?;

    let count = services.len();
    println!();
    ui::success(&format!("Exported {count} credential(s) to: {output}"));
    ui::muted("Format: GPG symmetric (legacy, weaker KDF). Permissions: 0600.");
    println!();
    ui::info("To decrypt", &format!("gpg -d {output}"));
    ui::reminder("REMINDER: Delete this file once you no longer need it.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_plain_text() {
        assert_eq!(csv_escape("hello"), "\"hello\"");
    }

    #[test]
    fn escape_quotes() {
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn escape_commas() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn escape_empty() {
        assert_eq!(csv_escape(""), "\"\"");
    }

    #[test]
    fn escape_newlines() {
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
    }
}
