#[cfg(feature = "export")]
use rand::RngCore;
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::constants::*;
use crate::crypto;
use crate::db;

pub(crate) const BACKUP_MAGIC: [u8; 4] = [0x53, 0x4B, 0x32, 0x42]; // "SK2B"
pub(crate) const BACKUP_VERSION: u8 = 0x01;

const HEADER_LEN: usize = 4 + 1 + 16 + 24; // magic + version + salt + nonce = 45

#[cfg(feature = "export")]
fn csv_escape(field: &str) -> String {
    format!("\"{}\"", field.replace('"', "\"\""))
}

#[cfg(feature = "import")]
fn parse_csv_records(text: &str) -> Result<Vec<Vec<String>>, String> {
    let mut records = Vec::new();
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();

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
            if current.trim().is_empty() {
                current.clear();
                in_quotes = true;
            } else {
                return Err("unexpected quote in unquoted field".into());
            }
        } else if ch == ',' {
            fields.push(std::mem::take(&mut current));
        } else if ch == '\n' {
            fields.push(std::mem::take(&mut current));
            records.push(std::mem::take(&mut fields));
        } else if ch == '\r' {
            // skip \r, the \n will end the record
        } else {
            current.push(ch);
        }
    }

    if in_quotes {
        return Err("unterminated quoted field".into());
    }

    if !current.is_empty() || !fields.is_empty() {
        fields.push(current);
        records.push(fields);
    }

    Ok(records)
}

#[cfg(feature = "export")]
pub(crate) fn export_vault(
    conn: &Connection,
    key: &[u8; KEY_LEN],
    backup_passphrase: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if backup_passphrase.is_empty() {
        return Err("Backup passphrase cannot be empty.".into());
    }

    let rows = db::get_all_credentials_raw(conn);

    let mut csv = Zeroizing::new(String::from("name,username,password,notes,url\n"));
    for (service, nonce, ciphertext) in &rows {
        let (username, password, notes, url) = crypto::decrypt(key, service, nonce, ciphertext)
            .map_err(|()| format!("Failed to decrypt credential for '{service}'."))?;
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

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let backup_key = crypto::derive_key(backup_passphrase, &salt);

    let (nonce, ciphertext) = crypto::encrypt_raw(&backup_key, csv.as_bytes());

    let mut output = Zeroizing::new(Vec::with_capacity(HEADER_LEN + ciphertext.len()));
    output.extend_from_slice(&BACKUP_MAGIC);
    output.push(BACKUP_VERSION);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

#[cfg(feature = "import")]
pub(crate) fn import_vault(
    conn: &Connection,
    key: &[u8; KEY_LEN],
    encrypted_blob: &[u8],
    backup_passphrase: &str,
) -> Result<u32, String> {
    if backup_passphrase.is_empty() {
        return Err("Backup passphrase cannot be empty.".into());
    }

    if encrypted_blob.len() < HEADER_LEN {
        return Err("Backup file too short.".into());
    }

    if encrypted_blob[0..4] != BACKUP_MAGIC {
        return Err("Not an sk2 backup file (bad magic bytes).".into());
    }

    if encrypted_blob[4] != BACKUP_VERSION {
        return Err(format!(
            "Unsupported backup version: {:#x}.",
            encrypted_blob[4]
        ));
    }

    let salt = &encrypted_blob[5..21];
    let nonce = &encrypted_blob[21..45];
    let ciphertext = &encrypted_blob[45..];

    let backup_key = crypto::derive_key(backup_passphrase, salt);

    let plaintext_bytes = crypto::decrypt_raw(&backup_key, nonce, ciphertext)
        .map_err(|()| "Backup decryption failed — wrong passphrase or corrupt file.".to_string())?;
    let plaintext = Zeroizing::new(
        String::from_utf8(plaintext_bytes).map_err(|_| "Invalid UTF-8 in backup payload.")?,
    );

    let records =
        parse_csv_records(&plaintext).map_err(|e| format!("CSV parse error in backup: {e}"))?;

    let mut iter = records.iter();

    let header = iter.next().ok_or("Empty backup payload.")?;
    let header_str = header.join(",");
    if header_str != "name,username,password,notes,url" && header_str != "name,username,password" {
        return Err(format!("Invalid CSV header: {header_str}"));
    }

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| format!("Failed to begin transaction: {e}"))?;

    let mut imported = 0u32;
    let outcome = (|| -> Result<(), String> {
        for fields in iter {
            if fields.len() == 1 && fields[0].trim().is_empty() {
                continue;
            }
            if fields.len() != 3 && fields.len() != 5 {
                return Err(format!("Expected 3 or 5 fields, got {}.", fields.len()));
            }
            let service = &fields[0];
            let username = &fields[1];
            let password = &fields[2];
            let notes = fields.get(3).map(|s| s.as_str()).unwrap_or("");
            let url = fields.get(4).map(|s| s.as_str()).unwrap_or("");

            if service.is_empty() {
                continue;
            }

            db::upsert_credential_tx(&tx, key, service, username, password, notes, url)
                .map_err(|e| format!("Failed to insert '{service}': {e}"))?;
            imported += 1;
        }
        Ok(())
    })();

    match outcome {
        Ok(()) => {
            tx.commit()
                .map_err(|e| format!("Failed to commit transaction: {e}"))?;
            Ok(imported)
        }
        Err(e) => {
            // Transaction rolls back on drop.
            Err(e)
        }
    }
}

#[cfg(all(test, feature = "export", feature = "import"))]
mod tests {
    use super::*;

    const TEST_KEY: [u8; KEY_LEN] = [0xAA; KEY_LEN];

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        db::init_db(&conn);
        conn
    }

    #[test]
    fn m1_export_magic_and_version() {
        let conn = setup();
        db::add_credential(&conn, &TEST_KEY, "svc", "u", "p", "", "");
        let blob = export_vault(&conn, &TEST_KEY, "backup_pass").unwrap();
        assert_eq!(&blob[0..4], &BACKUP_MAGIC);
        assert_eq!(blob[4], BACKUP_VERSION);
    }

    #[test]
    fn m2_export_import_roundtrip() {
        let conn = setup();
        let credentials = [
            (
                "GitHub",
                "octocat",
                "gh-pass-123",
                "2FA enabled",
                "https://github.com",
            ),
            (
                "Gmail",
                "user@gmail.com",
                "gm@il!pass",
                "",
                "https://mail.google.com",
            ),
            (
                "日本語サービス",
                "ユーザー",
                "密码🔑",
                "笔记📝",
                "https://例え.jp",
            ),
            ("Quotes\"Here", "user", "p\"word", "note\"s", ""),
            ("Commas,Here", "u,ser", "p,ass", "", "https://example.com"),
        ];
        for (svc, u, p, n, url) in &credentials {
            db::add_credential(&conn, &TEST_KEY, svc, u, p, n, url);
        }

        let blob = export_vault(&conn, &TEST_KEY, "roundtrip_pass").unwrap();

        let conn2 = setup();
        let count = import_vault(&conn2, &TEST_KEY, &blob, "roundtrip_pass").unwrap();
        assert_eq!(count, 5);

        for (svc, u, p, n, url) in &credentials {
            let (got_u, got_p, got_n, got_url, _) = db::get_credential(&conn2, &TEST_KEY, svc)
                .unwrap_or_else(|| panic!("missing credential for '{svc}'"));
            assert_eq!(&got_u, u, "username mismatch for {svc}");
            assert_eq!(&got_p, p, "password mismatch for {svc}");
            assert_eq!(&got_n, n, "notes mismatch for {svc}");
            assert_eq!(&got_url, url, "url mismatch for {svc}");
        }
    }

    #[test]
    fn m3_import_wrong_passphrase() {
        let conn = setup();
        db::add_credential(&conn, &TEST_KEY, "svc", "u", "p", "", "");
        let blob = export_vault(&conn, &TEST_KEY, "correct_pass").unwrap();

        let conn2 = setup();
        let err = import_vault(&conn2, &TEST_KEY, &blob, "wrong_pass").unwrap_err();
        assert!(err.contains("Backup decryption failed"), "got: {err}");
    }

    #[test]
    fn m4_import_corrupted_ciphertext() {
        let conn = setup();
        db::add_credential(&conn, &TEST_KEY, "svc", "u", "p", "", "");
        let mut blob = export_vault(&conn, &TEST_KEY, "pass").unwrap().to_vec();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;

        let conn2 = setup();
        let err = import_vault(&conn2, &TEST_KEY, &blob, "pass").unwrap_err();
        assert!(err.contains("Backup decryption failed"), "got: {err}");
    }

    #[test]
    fn m5_import_truncated() {
        let conn = setup();
        db::add_credential(&conn, &TEST_KEY, "svc", "u", "p", "", "");
        let blob = export_vault(&conn, &TEST_KEY, "pass").unwrap();
        let truncated = &blob[..30];

        let conn2 = setup();
        let err = import_vault(&conn2, &TEST_KEY, truncated, "pass").unwrap_err();
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn m6_import_wrong_magic() {
        let mut blob = vec![0u8; 50];
        blob[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        blob[4] = BACKUP_VERSION;

        let conn = setup();
        let err = import_vault(&conn, &TEST_KEY, &blob, "pass").unwrap_err();
        assert!(err.contains("bad magic"), "got: {err}");
    }

    #[test]
    fn m7_import_wrong_version() {
        let mut blob = vec![0u8; 50];
        blob[0..4].copy_from_slice(&BACKUP_MAGIC);
        blob[4] = 0x02;

        let conn = setup();
        let err = import_vault(&conn, &TEST_KEY, &blob, "pass").unwrap_err();
        assert!(err.contains("Unsupported backup version"), "got: {err}");
    }

    #[test]
    fn m8_import_overwrites_existing() {
        let conn = setup();
        db::add_credential(&conn, &TEST_KEY, "github", "old_user", "old_pass", "", "");

        let source = setup();
        db::add_credential(
            &source,
            &TEST_KEY,
            "github",
            "new_user",
            "new_pass",
            "imported",
            "https://github.com",
        );
        let blob = export_vault(&source, &TEST_KEY, "pass").unwrap();

        let target = conn;
        let count = import_vault(&target, &TEST_KEY, &blob, "pass").unwrap();
        assert_eq!(count, 1);

        let (u, p, n, url, _) = db::get_credential(&target, &TEST_KEY, "github").unwrap();
        assert_eq!(u, "new_user");
        assert_eq!(p, "new_pass");
        assert_eq!(n, "imported");
        assert_eq!(url, "https://github.com");
    }

    #[test]
    fn m9_import_leaves_unmentioned_untouched() {
        let conn = setup();
        db::add_credential(&conn, &TEST_KEY, "private", "me", "secret", "keep", "");

        let source = setup();
        db::add_credential(&source, &TEST_KEY, "other", "u", "p", "", "");
        let blob = export_vault(&source, &TEST_KEY, "pass").unwrap();

        let target = conn;
        let count = import_vault(&target, &TEST_KEY, &blob, "pass").unwrap();
        assert_eq!(count, 1);

        let (u, p, n, _, _) = db::get_credential(&target, &TEST_KEY, "private").unwrap();
        assert_eq!(u, "me");
        assert_eq!(p, "secret");
        assert_eq!(n, "keep");
    }

    #[test]
    fn m10_export_empty_vault_import_noop() {
        let conn = setup();
        let blob = export_vault(&conn, &TEST_KEY, "pass").unwrap();
        assert_eq!(&blob[0..4], &BACKUP_MAGIC);

        let target = setup();
        db::add_credential(&target, &TEST_KEY, "existing", "u", "p", "", "");

        let count = import_vault(&target, &TEST_KEY, &blob, "pass").unwrap();
        assert_eq!(count, 0);

        let (u, _, _, _, _) = db::get_credential(&target, &TEST_KEY, "existing").unwrap();
        assert_eq!(u, "u");
    }

    #[test]
    fn m11_empty_passphrase_rejected() {
        let conn = setup();
        let err_export = export_vault(&conn, &TEST_KEY, "").unwrap_err();
        assert!(err_export.contains("empty"), "got: {err_export}");

        let blob = export_vault(&conn, &TEST_KEY, "real_pass").unwrap();
        let target = setup();
        let err_import = import_vault(&target, &TEST_KEY, &blob, "").unwrap_err();
        assert!(err_import.contains("empty"), "got: {err_import}");
    }

    #[test]
    fn m12_import_corrupt_row_rolls_back() {
        // Build a backup blob whose CSV has one valid row followed by a
        // malformed row. The import must fail and roll back — the valid
        // row must NOT persist, and pre-existing rows must be untouched.
        let csv = "name,username,password,notes,url\n\
                   good_svc,user,pass,notes,url\n\
                   bad_svc,only_two_fields\n";

        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let backup_key = crypto::derive_key("bp", &salt);
        let (nonce, ciphertext) = crypto::encrypt_raw(&backup_key, csv.as_bytes());

        let mut blob = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        blob.extend_from_slice(&BACKUP_MAGIC);
        blob.push(BACKUP_VERSION);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);

        let target = setup();
        db::add_credential(&target, &TEST_KEY, "existing", "eu", "ep", "", "");

        let err = import_vault(&target, &TEST_KEY, &blob, "bp").unwrap_err();
        assert!(err.contains("Expected 3 or 5"), "got: {err}");

        assert!(
            db::get_credential(&target, &TEST_KEY, "good_svc").is_none(),
            "good_svc should not exist after rollback"
        );
        let (u, p, _, _, _) = db::get_credential(&target, &TEST_KEY, "existing").unwrap();
        assert_eq!(u, "eu");
        assert_eq!(p, "ep");
    }

    #[test]
    fn csv_leading_whitespace_before_quoted_field() {
        let csv = "service, \"user name\", \"pass word\",notes,url\n";
        let records = parse_csv_records(csv).expect("should tolerate leading whitespace");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0][0], "service");
        assert_eq!(records[0][1], "user name");
        assert_eq!(records[0][2], "pass word");
        assert_eq!(records[0][3], "notes");
        assert_eq!(records[0][4], "url");
    }
}
