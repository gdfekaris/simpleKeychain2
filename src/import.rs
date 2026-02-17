use rusqlite::Connection;
use std::process;
use zeroize::Zeroizing;

use crate::constants::*;
use crate::db;
use crate::ui;
use crate::vault;

fn parse_csv_line(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    // Escaped double quote
                    chars.next();
                    current.push('"');
                } else {
                    // End of quoted field
                    in_quotes = false;
                }
            } else {
                current.push(ch);
            }
        } else if ch == '"' {
            if current.is_empty() {
                in_quotes = true;
            } else {
                return Err("unexpected quote in unquoted field".into());
            }
        } else if ch == ',' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }

    if in_quotes {
        return Err("unterminated quoted field".into());
    }

    fields.push(current);
    Ok(fields)
}

pub(crate) fn import_credentials(
    conn: &Connection,
    key: &[u8; KEY_LEN],
    file: &str,
) -> Result<(), String> {
    // Validate file exists
    if !std::path::Path::new(file).exists() {
        return Err(format!("File not found: {file}"));
    }

    // Check that GPG is available
    let gpg_check = process::Command::new("gpg")
        .arg("--version")
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status();
    match gpg_check {
        Ok(status) if status.success() => {}
        _ => return Err("GPG is not installed or not found in PATH. Install GPG to use import.".into()),
    }

    // Warning and confirmation
    ui::warning_block(&[
        "This will import credentials from a GPG-encrypted CSV file.",
        "Existing credentials with the same service name will be OVERWRITTEN.",
    ]);
    println!();
    let answer = vault::prompt("Type 'yes' to continue: ");
    if answer != "yes" {
        return Err("Import cancelled.".into());
    }

    // Decrypt via GPG
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

    // Wrap plaintext in Zeroizing
    let csv = Zeroizing::new(
        String::from_utf8(output.stdout)
            .map_err(|_| "Decrypted file contains invalid UTF-8.")?
    );

    let mut lines = csv.lines();

    // Validate header
    let header = lines.next().ok_or("CSV file is empty.")?;
    if header != "name,username,password" {
        return Err(format!(
            "Invalid CSV header. Expected 'name,username,password', got '{header}'."
        ));
    }

    // Parse and store each row
    let mut imported = 0usize;
    let mut skipped = 0usize;

    for (i, line) in lines.enumerate() {
        let line_num = i + 2; // 1-indexed, header is line 1

        if line.trim().is_empty() {
            continue;
        }

        let fields = match parse_csv_line(line) {
            Ok(f) => f,
            Err(e) => {
                ui::warning(&format!("Line {line_num}: {e}, skipping."));
                skipped += 1;
                continue;
            }
        };

        if fields.len() != 3 {
            ui::warning(&format!(
                "Line {line_num}: expected 3 fields, got {}, skipping.",
                fields.len()
            ));
            skipped += 1;
            continue;
        }

        let service = &fields[0];
        let username = &fields[1];
        let password = &fields[2];

        if service.is_empty() {
            ui::warning(&format!("Line {line_num}: empty service name, skipping."));
            skipped += 1;
            continue;
        }

        db::add_credential(conn, key, service, username, password);
        imported += 1;
    }

    if imported == 0 && skipped == 0 {
        return Err("No credentials found in CSV file.".into());
    }

    println!();
    ui::success(&format!("Imported {imported} credential(s)."));
    if skipped > 0 {
        ui::warning(&format!("Skipped {skipped} malformed row(s)."));
    }
    ui::reminder("REMINDER: Delete the encrypted export file if you no longer need it.");

    Ok(())
}
