use rusqlite::Connection;
use std::io::Read;
use std::process;
use zeroize::Zeroizing;

use crate::backup;
use crate::constants::*;
use crate::db;
use crate::ui;
use crate::vault;

/// Parse and validate a decrypted GPG CSV export, returning the accepted records
/// and the number skipped.
///
/// Parsing is whole-text via `backup::parse_csv_records` rather than line-scoped:
/// `export::csv_escape` quotes fields but cannot escape newlines, so a note
/// containing `\n` is written as a real newline inside a quoted field. Splitting on
/// lines before parsing tore such a record into fragments that each failed to parse,
/// silently dropping the whole credential.
///
/// Once embedded newlines are in play a syntax error is no longer attributable to a
/// single row — everything after it is misaligned — so a bad quote aborts the import.
/// Per-row problems that *are* localizable (wrong field count, empty service name)
/// still warn and skip, preserving the legacy importer's best-effort behavior.
fn parse_gpg_csv(csv: &str) -> Result<(Vec<Vec<String>>, usize), String> {
    let records = backup::parse_csv_records(csv).map_err(|e| {
        format!("CSV parse error: {e}. Nothing was imported — the file may be corrupt or may not be an sk2 export.")
    })?;

    let mut iter = records.into_iter();
    let header = iter.next().ok_or("CSV file is empty.")?;
    let header_str = header.join(",");
    if header_str != "name,username,password" && header_str != "name,username,password,notes,url" {
        return Err(format!(
            "Invalid CSV header. Expected 'name,username,password,notes,url', got '{header_str}'."
        ));
    }

    let mut accepted = Vec::new();
    let mut skipped = 0usize;

    for (i, fields) in iter.enumerate() {
        // Records, not lines: a note with newlines is still one record.
        let row_num = i + 1;

        if fields.len() == 1 && fields[0].trim().is_empty() {
            continue;
        }

        if fields.len() != 3 && fields.len() != 5 {
            ui::warning(&format!(
                "Row {row_num}: expected 3 or 5 fields, got {}, skipping.",
                fields.len()
            ));
            skipped += 1;
            continue;
        }

        if fields[0].is_empty() {
            ui::warning(&format!("Row {row_num}: empty service name, skipping."));
            skipped += 1;
            continue;
        }

        accepted.push(fields);
    }

    Ok((accepted, skipped))
}

fn read_backup_passphrase() -> Result<Zeroizing<String>, String> {
    ui::password_prompt("Backup passphrase: ");
    let p = Zeroizing::new(rpassword::read_password().expect("Failed to read password"));
    if p.is_empty() {
        return Err("Backup passphrase cannot be empty.".into());
    }
    Ok(p)
}

pub(crate) fn import_credentials(
    conn: &Connection,
    key: &[u8; KEY_LEN],
    file: &str,
) -> Result<(), String> {
    if !std::path::Path::new(file).exists() {
        return Err(format!("File not found: {file}"));
    }

    let mut magic = [0u8; 4];
    let n = {
        let mut f =
            std::fs::File::open(file).map_err(|e| format!("Failed to open '{file}': {e}"))?;
        f.read(&mut magic).unwrap_or(0)
    };

    if n >= 4 && magic == backup::BACKUP_MAGIC {
        import_sk2b(conn, key, file)
    } else {
        import_gpg(conn, key, file)
    }
}

fn import_sk2b(conn: &Connection, key: &[u8; KEY_LEN], file: &str) -> Result<(), String> {
    ui::warning_block(&[
        "This will import credentials from an sk2 backup (.sk2backup).",
        "Existing credentials with the same service name will be OVERWRITTEN.",
    ]);
    println!();
    let answer = vault::prompt("Type 'yes' to continue: ");
    if answer != "yes" {
        return Err("Import cancelled.".into());
    }

    let blob =
        Zeroizing::new(std::fs::read(file).map_err(|e| format!("Failed to read '{file}': {e}"))?);
    let passphrase = read_backup_passphrase()?;

    let count = backup::import_vault(conn, key, &blob, &passphrase)?;

    println!();
    ui::success(&format!("Imported {count} credential(s)."));
    ui::reminder("REMINDER: Delete the backup file if you no longer need it.");
    Ok(())
}

fn import_gpg(conn: &Connection, key: &[u8; KEY_LEN], file: &str) -> Result<(), String> {
    let gpg_check = process::Command::new("gpg")
        .arg("--version")
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status();
    match gpg_check {
        Ok(status) if status.success() => {}
        _ => {
            return Err(
                "GPG is not installed or not found in PATH. Install GPG to import .csv.gpg files."
                    .into(),
            );
        }
    }

    ui::warning_block(&[
        "This will import credentials from a GPG-encrypted CSV file (legacy format).",
        "Existing credentials with the same service name will be OVERWRITTEN.",
        "Note: .sk2backup uses a stronger KDF and is the recommended format for new backups.",
    ]);
    println!();
    let answer = vault::prompt("Type 'yes' to continue: ");
    if answer != "yes" {
        return Err("Import cancelled.".into());
    }

    let output = process::Command::new("gpg")
        .arg("--decrypt")
        .arg("--quiet")
        .arg(file)
        .output()
        .map_err(|e| format!("Failed to start GPG: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("GPG decryption failed: {}", stderr.trim()));
    }

    let csv = Zeroizing::new(
        String::from_utf8(output.stdout).map_err(|_| "Decrypted file contains invalid UTF-8.")?,
    );

    // Parse and validate everything before writing anything, so a malformed file
    // cannot leave a half-populated vault.
    let (records, skipped) = parse_gpg_csv(&csv)?;

    if records.is_empty() && skipped == 0 {
        return Err("No credentials found in CSV file.".into());
    }

    for fields in &records {
        let notes = fields.get(3).map(|s| s.as_str()).unwrap_or("");
        let url = fields.get(4).map(|s| s.as_str()).unwrap_or("");
        db::add_credential(conn, key, &fields[0], &fields[1], &fields[2], notes, url);
    }
    let imported = records.len();

    println!();
    ui::success(&format!("Imported {imported} credential(s)."));
    if skipped > 0 {
        ui::warning(&format!("Skipped {skipped} malformed row(s)."));
    }
    ui::reminder("REMINDER: Delete the encrypted export file if you no longer need it.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F1 regression. `export::csv_escape` quotes fields but writes newlines raw, so a
    /// multi-line note lands as a real newline inside a quoted field. The old
    /// line-scoped parser split on those newlines *before* parsing, tearing this single
    /// record into three unparseable fragments and dropping the whole credential —
    /// username and password included — while reporting "Imported 0 credential(s)".
    ///
    /// The CSV below is byte-for-byte what `export::export_gpg` writes for this entry.
    #[test]
    fn multiline_notes_survive() {
        let csv = concat!(
            "name,username,password,notes,url\n",
            "\"gmail\",\"me@x.com\",\"hunter2\",",
            "\"recovery codes:\n  1111-2222\n  3333-4444\",",
            "\"https://mail.google.com\"\n",
        );

        let (records, skipped) = parse_gpg_csv(csv).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(records.len(), 1, "one credential, not one record per line");
        assert_eq!(records[0][0], "gmail");
        assert_eq!(records[0][1], "me@x.com");
        assert_eq!(records[0][2], "hunter2");
        assert_eq!(records[0][3], "recovery codes:\n  1111-2222\n  3333-4444");
        assert_eq!(records[0][4], "https://mail.google.com");
    }

    #[test]
    fn five_column_header_accepted() {
        let csv = "name,username,password,notes,url\nsvc,user,pass,note,https://example.com\n";
        let (records, skipped) = parse_gpg_csv(csv).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].len(), 5);
        assert_eq!(records[0][4], "https://example.com");
    }

    #[test]
    fn legacy_three_column_header_accepted() {
        let csv = "name,username,password\nsvc,user,pass\n";
        let (records, skipped) = parse_gpg_csv(csv).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].len(),
            3,
            "notes/url default to empty at the call site"
        );
    }

    /// The header check and the per-row field count are independent, matching
    /// `backup::import_vault`.
    #[test]
    fn five_column_header_with_three_field_rows() {
        let csv = "name,username,password,notes,url\nsvc,user,pass\n";
        let (records, skipped) = parse_gpg_csv(csv).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn quoted_commas_and_escaped_quotes() {
        let csv = "name,username,password\n\"a,b\",\"he said \"\"hi\"\"\",\"p,w\"\n";
        let (records, _) = parse_gpg_csv(csv).unwrap();
        assert_eq!(records[0][0], "a,b");
        assert_eq!(records[0][1], "he said \"hi\"");
        assert_eq!(records[0][2], "p,w");
    }

    #[test]
    fn crlf_line_endings() {
        let csv = "name,username,password\r\nsvc,user,pass\r\n";
        let (records, skipped) = parse_gpg_csv(csv).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0][2], "pass");
    }

    #[test]
    fn blank_lines_ignored() {
        let csv = "name,username,password\n\nsvc,user,pass\n\n";
        let (records, skipped) = parse_gpg_csv(csv).unwrap();
        assert_eq!(skipped, 0, "blank lines are not malformed rows");
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn wrong_field_count_skipped() {
        let csv = "name,username,password\nsvc,user,pass\na,b\n";
        let (records, skipped) = parse_gpg_csv(csv).unwrap();
        assert_eq!(records.len(), 1, "good row still imports");
        assert_eq!(skipped, 1);
    }

    #[test]
    fn empty_service_skipped() {
        let csv = "name,username,password\n\"\",user,pass\nsvc,user,pass\n";
        let (records, skipped) = parse_gpg_csv(csv).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(skipped, 1);
    }

    /// A broken quote desynchronizes every record after it, so it is not attributable
    /// to one row. Aborting is why `import_gpg` parses fully before it writes anything.
    #[test]
    fn unterminated_quote_aborts() {
        let csv = "name,username,password\n\"unterminated,user,pass\n";
        let err = parse_gpg_csv(csv).unwrap_err();
        assert!(err.contains("unterminated quoted field"), "got: {err}");
    }

    #[test]
    fn mid_field_quote_aborts() {
        let csv = "name,username,password\nab\"cd,user,pass\n";
        let err = parse_gpg_csv(csv).unwrap_err();
        assert!(err.contains("unexpected quote"), "got: {err}");
    }

    #[test]
    fn bad_header_rejected() {
        let csv = "service,login,secret\nsvc,user,pass\n";
        let err = parse_gpg_csv(csv).unwrap_err();
        assert!(err.contains("Invalid CSV header"), "got: {err}");
    }

    #[test]
    fn empty_input_rejected() {
        let err = parse_gpg_csv("").unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn header_only_yields_nothing() {
        let csv = "name,username,password,notes,url\n";
        let (records, skipped) = parse_gpg_csv(csv).unwrap();
        assert!(records.is_empty());
        assert_eq!(skipped, 0, "caller reports 'No credentials found'");
    }
}
