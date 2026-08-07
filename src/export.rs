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

/// Build the GPG export CSV. Returns it with the number of rows written and the
/// number skipped, or `Err` if any row will not decrypt.
///
/// **A corrupt row aborts the export.** This matches SK2B, which has always failed
/// on the first row it cannot decrypt. The GPG path used to warn and continue, on
/// the reasoning that a partial backup of the readable entries beats none — that
/// was reversed deliberately on 2026-08-07 (see F3 in `project-assessment.md`).
/// The argument against it: a backup's whole purpose is to be trusted later, and
/// one that silently omits entries is worse than an absent one, because the user
/// stops looking for the missing data. Nothing is lost by failing here — the
/// unreadable credential was already unreadable, and `sk2 verify` plus `sk2 import`
/// or `sk2 delete` is the actual recovery path.
///
/// A *vanished* row is different and still warns-and-skips: it means the credential
/// was deleted between `list_services` and now, so there is no data to lose and
/// nothing to diagnose. Failing there would be friction buying no safety. (SK2B
/// cannot hit this case at all — `get_all_credentials_raw` is a single query, so it
/// has no list-then-fetch window.)
///
/// Split out of `export_gpg` so the counts and this abort are testable.
///
/// The CSV holds every credential in plaintext, so it stays inside `Zeroizing` and
/// is returned by move. There is deliberately no unwrapped intermediate here — see
/// F4 in `project-assessment.md`.
fn build_gpg_csv(
    conn: &Connection,
    key: &[u8; KEY_LEN],
    services: &[String],
) -> Result<(Zeroizing<String>, usize, usize), String> {
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
                // `e` is db::decrypt_failure — it already names the entry and the
                // recovery path. Returning here is what keeps a partial backup off
                // disk: the caller has not opened the output file yet.
                return Err(format!("{e} No backup file was written."));
            }
        }
    }

    Ok((csv, exported, skipped))
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

    // Deliberately after the confirmation prompt, not before it: this materializes
    // every credential in plaintext, and that buffer should not sit in memory across
    // an indefinite wait for the user to type "yes".
    let (csv, exported, skipped) = build_gpg_csv(conn, key, &services)?;

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
        let (csv, exported, skipped) = build_gpg_csv(&conn, &TEST_KEY, &services).unwrap();

        assert_eq!(exported, 2);
        assert_eq!(skipped, 0);
        assert_eq!(
            csv.lines().count(),
            3,
            "header plus one line per credential"
        );
    }

    /// A corrupt row aborts rather than producing a backup that silently omits it.
    ///
    /// The error must name the entry and the recovery path, because that is the only
    /// thing standing between the user and a vault they cannot fully back up.
    #[test]
    fn a_corrupt_row_aborts_the_export() {
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

        let err = build_gpg_csv(&conn, &TEST_KEY, &services)
            .expect_err("a row that will not decrypt must abort the export");

        assert!(err.contains("bad"), "the error must name the entry: {err}");
        assert!(
            err.contains("sk2 verify"),
            "the error must point at the recovery path: {err}"
        );
        assert!(
            err.contains("No backup file was written"),
            "the user must be told no partial file exists: {err}"
        );
    }

    /// The counterpart to the rule above: a *vanished* row is a benign race, not
    /// corruption, so it warns and skips. There is no data to lose — the credential
    /// was deleted — and aborting would be friction buying nothing.
    #[test]
    fn a_vanished_row_is_skipped_rather_than_aborting() {
        let conn = scratch_vault();
        db::add_credential(&conn, &TEST_KEY, "stays", "u", "p", "", "");

        // Name a service that is not in the vault, standing in for a row deleted
        // between list_services and the read.
        let services = vec!["stays".to_string(), "deleted_meanwhile".to_string()];
        let (csv, exported, skipped) = build_gpg_csv(&conn, &TEST_KEY, &services)
            .expect("a vanished row must not abort the export");

        assert_eq!(exported, 1);
        assert_eq!(skipped, 1);
        assert!(csv.contains("\"stays\""));
    }
}
