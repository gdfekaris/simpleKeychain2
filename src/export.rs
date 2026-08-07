use rusqlite::Connection;
use std::fs::File;
use std::io::{self, Write};
use std::process;
use zeroize::Zeroizing;

use crate::backup;
use crate::constants::*;
use crate::crypto;
use crate::db;
use crate::ui;
use crate::vault;

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
    let p1 = Zeroizing::new(rpassword::read_password().expect("Failed to read password"));
    if p1.is_empty() {
        return Err("Backup passphrase cannot be empty.".into());
    }
    // Shown before the confirmation prompt so a weak choice can still be abandoned.
    // This passphrase guards every credential at once, in a file designed to leave
    // the machine — the widest blast radius of any secret sk2 handles, and the one
    // users are most likely to treat as throwaway.
    ui::password_strength(crypto::password_entropy(&p1));
    ui::password_prompt("Confirm backup passphrase: ");
    let p2 = Zeroizing::new(rpassword::read_password().expect("Failed to read password"));
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

    // `services.len()` is the true count here, unlike on the GPG path:
    // `backup::export_vault` returns `Err` on the first row that will not decrypt
    // rather than skipping it, so reaching this line means every row is in the blob.
    let count = services.len();
    println!();
    ui::success(&format!("Exported {count} credential(s) to: {output}"));
    ui::muted("Format: SK2B (Argon2id + XChaCha20-Poly1305). Permissions: 0600.");
    println!();
    ui::info("To restore", &format!("sk2 import {output}"));
    ui::reminder("REMINDER: Delete this file once you no longer need it.");

    Ok(())
}

/// Build the GPG export CSV. Returns it with the number of rows actually written
/// and the number skipped.
///
/// Split out of `export_gpg` so the counts are testable. The success line used to
/// report `services.len()`, captured before the loop — but the loop skips rows that
/// vanished or will not decrypt, so a vault with an unreadable entry announced more
/// credentials than the file contained. Per-row warnings were printed either way;
/// the summary contradicted them.
///
/// The CSV holds every credential in plaintext, so it stays inside `Zeroizing` and
/// is returned by move. There is deliberately no unwrapped intermediate here — see
/// F4 in `project-assessment.md`.
fn build_gpg_csv(
    conn: &Connection,
    key: &[u8; KEY_LEN],
    services: &[String],
) -> (Zeroizing<String>, usize, usize) {
    let mut csv = Zeroizing::new(String::from("name,username,password,notes,url\n"));
    let mut exported = 0usize;
    let mut skipped = 0usize;

    for service in services {
        match db::get_credential(conn, key, service) {
            Ok(Some((username, password, notes, url, _))) => {
                csv.push_str(&backup::csv_escape(service));
                csv.push(',');
                csv.push_str(&backup::csv_escape(&username));
                csv.push(',');
                csv.push_str(&backup::csv_escape(&password));
                csv.push(',');
                csv.push_str(&backup::csv_escape(&notes));
                csv.push(',');
                csv.push_str(&backup::csv_escape(&url));
                csv.push('\n');
                exported += 1;
            }
            Ok(None) => {
                // Raced with a delete between list_services and now.
                ui::warning(&format!("Credential for '{service}' vanished, skipping."));
                skipped += 1;
            }
            Err(e) => {
                // Corrupt row. Skip it rather than aborting the export -- a partial
                // backup of the readable entries is more useful than none, and the
                // message says exactly which entry was lost.
                ui::warning(&format!("{e} Skipping it in this export."));
                skipped += 1;
            }
        }
    }

    (csv, exported, skipped)
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

    let (csv, exported, skipped) = build_gpg_csv(conn, key, &services);

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

    println!();
    ui::success(&format!("Exported {exported} credential(s) to: {output}"));
    if skipped > 0 {
        ui::warning(&format!(
            "{skipped} credential(s) could not be read and are NOT in this backup (see above)."
        ));
    }
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
        assert_eq!(backup::csv_escape("hello"), "\"hello\"");
    }

    #[test]
    fn escape_quotes() {
        assert_eq!(backup::csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn escape_commas() {
        assert_eq!(backup::csv_escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn escape_empty() {
        assert_eq!(backup::csv_escape(""), "\"\"");
    }

    #[test]
    fn escape_newlines() {
        assert_eq!(backup::csv_escape("line1\nline2"), "\"line1\nline2\"");
    }

    /// F1 regression, end to end across the module boundary: what `export_gpg` writes
    /// must survive the parser `import_gpg` reads it back with. `escape_newlines`
    /// above only pins the escaper's output; this pins the two halves against each
    /// other, which is where F1 actually lived.
    #[test]
    #[cfg(feature = "import")]
    fn escaped_multiline_note_reparses() {
        let note = "recovery codes:\n  1111-2222\n  3333-4444";
        let fields = [
            "gmail",
            "me@x.com",
            "hunter2",
            note,
            "https://mail.google.com",
        ];

        let mut csv = String::from("name,username,password,notes,url\n");
        for field in fields {
            csv.push_str(&backup::csv_escape(field));
            csv.push(',');
        }
        csv.pop();
        csv.push('\n');

        let records = crate::backup::parse_csv_records(&csv).unwrap();
        assert_eq!(
            records.len(),
            2,
            "header + one credential, not one per line"
        );
        assert_eq!(records[1], fields, "every field round-trips intact");
    }

    // -- build_gpg_csv counts --

    const TEST_KEY: [u8; KEY_LEN] = [7u8; KEY_LEN];

    fn scratch_vault() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        db::init_db(&conn);
        conn
    }

    #[test]
    fn every_readable_row_is_counted_and_written() {
        let conn = scratch_vault();
        db::add_credential(&conn, &TEST_KEY, "a", "ua", "pa", "", "");
        db::add_credential(&conn, &TEST_KEY, "b", "ub", "pb", "", "");

        let services = db::list_services(&conn);
        let (csv, exported, skipped) = build_gpg_csv(&conn, &TEST_KEY, &services);

        assert_eq!(exported, 2);
        assert_eq!(skipped, 0);
        assert_eq!(
            csv.lines().count(),
            3,
            "header plus one line per credential"
        );
    }

    /// The bug this function was extracted for: an unreadable row is skipped, so the
    /// count reported to the user must come from rows actually written, not from
    /// `list_services().len()` captured before the loop.
    #[test]
    fn a_corrupt_row_is_skipped_and_not_counted_as_exported() {
        let conn = scratch_vault();
        db::add_credential(&conn, &TEST_KEY, "good", "ug", "pg", "", "");
        db::add_credential(&conn, &TEST_KEY, "bad", "ub", "pb", "", "");
        conn.execute(
            "UPDATE credentials SET ciphertext = X'0001020304' WHERE service = 'bad'",
            [],
        )
        .unwrap();

        let services = db::list_services(&conn);
        assert_eq!(services.len(), 2, "both rows are still listed");

        let (csv, exported, skipped) = build_gpg_csv(&conn, &TEST_KEY, &services);

        assert_eq!(exported, 1, "only the readable row reached the CSV");
        assert_eq!(skipped, 1);
        assert_ne!(
            exported,
            services.len(),
            "the pre-fix code reported services.len() here, overstating the backup"
        );
        assert!(csv.contains("\"good\""));
        assert!(
            !csv.contains("\"bad\""),
            "the corrupt row must not appear in the backup"
        );
    }
}
