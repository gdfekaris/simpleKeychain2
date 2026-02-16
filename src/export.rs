use rusqlite::Connection;
use std::io::Write;
use std::process;
use zeroize::Zeroizing;

use crate::constants::*;
use crate::db;
use crate::vault;

fn csv_escape(field: &str) -> String {
    format!("\"{}\"", field.replace('"', "\"\""))
}

fn restrict_file_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(path, perms) {
            eprintln!("Warning: could not set file permissions: {e}");
        }
    }
}

pub(crate) fn export_credentials(conn: &Connection, key: &[u8; KEY_LEN], output: &str) -> Result<(), String> {
    // Check that GPG is available
    let gpg_check = process::Command::new("gpg")
        .arg("--version")
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status();
    match gpg_check {
        Ok(status) if status.success() => {}
        _ => return Err("GPG is not installed or not found in PATH. Install GPG to use export.".into()),
    }

    let services = db::list_services(conn);
    if services.is_empty() {
        println!("No credentials to export.");
        return Ok(());
    }

    // Pre-export warning
    println!("WARNING: This will export ALL stored credentials into a GPG-encrypted file.");
    println!("The file can be decrypted with: gpg -d {output}");
    println!("Anyone with the export passphrase can read your passwords.");
    println!();
    let answer = vault::prompt("Type 'yes' to continue: ");
    if answer != "yes" {
        return Err("Export cancelled.".into());
    }

    // Build CSV in memory (zeroized on drop)
    let mut csv = Zeroizing::new(String::from("name,username,password\n"));
    for service in &services {
        match db::get_credential(conn, key, service) {
            Some((username, password)) => {
                let password = Zeroizing::new(password);
                csv.push_str(&csv_escape(service));
                csv.push(',');
                csv.push_str(&csv_escape(&username));
                csv.push(',');
                csv.push_str(&csv_escape(&password));
                csv.push('\n');
            }
            None => {
                eprintln!("Warning: could not decrypt credential for '{service}', skipping.");
            }
        }
    }

    // Spawn GPG with piped stdin
    let output_path = std::path::Path::new(output);
    let mut child = process::Command::new("gpg")
        .arg("--symmetric")
        .arg("--cipher-algo")
        .arg("AES256")
        .arg("--output")
        .arg(output)
        .stdin(process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start GPG: {e}"))?;

    // Pipe CSV to GPG's stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(csv.as_bytes())
            .map_err(|e| format!("Failed to write to GPG: {e}"))?;
        // stdin is dropped here, closing the pipe
    }

    let status = child.wait().map_err(|e| format!("Failed to wait for GPG: {e}"))?;
    if !status.success() {
        return Err("GPG encryption failed.".into());
    }

    // Set output file permissions to 0o600
    restrict_file_permissions(output_path);

    let count = services.len();
    println!();
    println!("Exported {count} credential(s) to: {output}");
    println!("Permissions set to owner-read/write only (0600).");
    println!();
    println!("To decrypt: gpg -d {output}");
    println!("REMINDER: Delete this file once you no longer need it.");

    Ok(())
}
