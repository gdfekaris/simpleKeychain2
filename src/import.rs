use rusqlite::Connection;
use std::io::Read;
use std::process;
use zeroize::Zeroizing;

use crate::backup;
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
                    chars.next();
                    current.push('"');
                } else {
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

fn read_backup_passphrase() -> Result<Zeroizing<String>, String> {
    ui::password_prompt("Backup passphrase: ");
    let p =
        Zeroizing::new(rpassword::read_password_from_tty(None).expect("Failed to read password"));
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

    let mut lines = csv.lines();
    let header = lines.next().ok_or("CSV file is empty.")?;
    if header != "name,username,password" && header != "name,username,password,notes,url" {
        return Err(format!(
            "Invalid CSV header. Expected 'name,username,password,notes,url', got '{header}'."
        ));
    }

    let mut imported = 0usize;
    let mut skipped = 0usize;

    for (i, line) in lines.enumerate() {
        let line_num = i + 2;

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

        if fields.len() != 3 && fields.len() != 5 {
            ui::warning(&format!(
                "Line {line_num}: expected 3 or 5 fields, got {}, skipping.",
                fields.len()
            ));
            skipped += 1;
            continue;
        }

        let service = &fields[0];
        let username = &fields[1];
        let password = &fields[2];
        let notes = fields.get(3).map(|s| s.as_str()).unwrap_or("");
        let url = fields.get(4).map(|s| s.as_str()).unwrap_or("");

        if service.is_empty() {
            ui::warning(&format!("Line {line_num}: empty service name, skipping."));
            skipped += 1;
            continue;
        }

        db::add_credential(conn, key, service, username, password, notes, url);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_unquoted() {
        let fields = parse_csv_line("a,b,c").unwrap();
        assert_eq!(fields, vec!["a", "b", "c"]);
    }

    #[test]
    fn quoted_fields() {
        let fields = parse_csv_line("\"hello\",\"world\"").unwrap();
        assert_eq!(fields, vec!["hello", "world"]);
    }

    #[test]
    fn escaped_quotes() {
        let fields = parse_csv_line("\"he said \"\"hi\"\"\"").unwrap();
        assert_eq!(fields, vec!["he said \"hi\""]);
    }

    #[test]
    fn commas_inside_quotes() {
        let fields = parse_csv_line("\"a,b\",c").unwrap();
        assert_eq!(fields, vec!["a,b", "c"]);
    }

    #[test]
    fn empty_fields() {
        let fields = parse_csv_line(",,").unwrap();
        assert_eq!(fields, vec!["", "", ""]);
    }

    #[test]
    fn unterminated_quote() {
        let result = parse_csv_line("\"unterminated");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unterminated"));
    }

    #[test]
    fn mid_field_quote() {
        let result = parse_csv_line("ab\"cd");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unexpected quote"));
    }

    #[test]
    fn single_field() {
        let fields = parse_csv_line("hello").unwrap();
        assert_eq!(fields, vec!["hello"]);
    }

    #[test]
    fn empty_string() {
        let fields = parse_csv_line("").unwrap();
        assert_eq!(fields, vec![""]);
    }

    #[test]
    fn five_field_row() {
        let fields = parse_csv_line("svc,user,pass,notes,https://example.com").unwrap();
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0], "svc");
        assert_eq!(fields[4], "https://example.com");
    }

    #[test]
    fn newline_inside_quotes() {
        let fields = parse_csv_line("\"line1\nline2\",b").unwrap();
        assert_eq!(fields[0], "line1\nline2");
        assert_eq!(fields[1], "b");
    }
}
