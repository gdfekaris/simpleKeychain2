use argon2::{Argon2, Algorithm, Version, Params};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, Key};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::constants::*;

#[derive(Serialize, Deserialize)]
struct Credential {
    username: String,
    password: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

pub(crate) fn derive_key(master_password: &str, salt: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(KEY_LEN))
        .expect("Invalid Argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut *key)
        .expect("Key derivation failed");
    key
}

#[derive(Clone, clap::ValueEnum)]
pub(crate) enum Charset {
    /// Letters, digits, and symbols (default)
    Default,
    /// Letters and digits only, no symbols
    Alphanumeric,
    /// RFC 3986 unreserved characters — safe in URLs and HTML forms
    Websafe,
    /// Lowercase hex digits (0–9, a–f)
    Hex,
    /// DNA alphabet (A, C, G, T)
    Dna,
}

pub(crate) fn generate_password(length: usize, charset: &Charset) -> Zeroizing<String> {
    let chars: &[u8] = match charset {
        Charset::Default      => b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_=+?",
        Charset::Alphanumeric => b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        Charset::Websafe      => b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~",
        Charset::Hex          => b"0123456789abcdef",
        Charset::Dna          => b"ACGT",
    };
    let mut rng = rand::thread_rng();
    let password: String = (0..length)
        .map(|_| chars[rng.gen_range(0..chars.len())] as char)
        .collect();
    Zeroizing::new(password)
}

pub(crate) fn password_entropy(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_other = false;
    for c in password.chars() {
        if c.is_ascii_lowercase()      { has_lower = true; }
        else if c.is_ascii_uppercase() { has_upper = true; }
        else if c.is_ascii_digit()     { has_digit = true; }
        else                           { has_other = true; }
    }
    let mut alphabet = 0u32;
    if has_lower { alphabet += 26; }
    if has_upper { alphabet += 26; }
    if has_digit { alphabet += 10; }
    if has_other { alphabet += 32; }
    if alphabet == 0 { return 0.0; }
    password.len() as f64 * (alphabet as f64).log2()
}

pub(crate) fn encrypt_raw(key: &[u8; KEY_LEN], plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("Encryption failed");
    (nonce_bytes.to_vec(), ciphertext)
}

pub(crate) fn decrypt_raw(key: &[u8; KEY_LEN], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext).map_err(|_| ())
}

pub(crate) fn verify_key(key: &[u8; KEY_LEN], nonce: &[u8], ciphertext: &[u8]) -> bool {
    match decrypt_raw(key, nonce, ciphertext) {
        Ok(plaintext) => plaintext == VERIFY_PLAINTEXT,
        Err(()) => false,
    }
}

pub(crate) fn encrypt(key: &[u8; KEY_LEN], service: &str, username: &str, password: &str, notes: &str, url: &str) -> (Vec<u8>, Vec<u8>) {
    let cred = Credential {
        username: username.to_string(),
        password: password.to_string(),
        notes: if notes.is_empty() { None } else { Some(notes.to_string()) },
        url: if url.is_empty() { None } else { Some(url.to_string()) },
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

pub(crate) fn decrypt(key: &[u8; KEY_LEN], service: &str, nonce: &[u8], ciphertext: &[u8]) -> Result<(String, String, String, String), ()> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce);

    let plaintext = cipher.decrypt(nonce, Payload {
        msg: ciphertext,
        aad: service.as_bytes(),
    }).map_err(|_| ())?;

    let cred: Credential =
        serde_json::from_slice(&plaintext).map_err(|_| ())?;
    Ok((
        cred.username,
        cred.password,
        cred.notes.unwrap_or_default(),
        cred.url.unwrap_or_default(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; KEY_LEN] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    const WRONG_KEY: [u8; KEY_LEN] = [0xff; KEY_LEN];

    // -- derive_key (3 tests) --

    #[test]
    fn derive_key_deterministic() {
        let salt = b"fixed_salt_16byt";
        let k1 = derive_key("password", salt);
        let k2 = derive_key("password", salt);
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn derive_key_different_password() {
        let salt = b"fixed_salt_16byt";
        let k1 = derive_key("password1", salt);
        let k2 = derive_key("password2", salt);
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn derive_key_different_salt() {
        let k1 = derive_key("password", b"salt_aaaaaaaaaa16");
        let k2 = derive_key("password", b"salt_bbbbbbbbbb16");
        assert_ne!(*k1, *k2);
    }

    // -- encrypt_raw / decrypt_raw (4 tests) --

    #[test]
    fn raw_roundtrip() {
        let plaintext = b"hello world";
        let (nonce, ct) = encrypt_raw(&TEST_KEY, plaintext);
        let result = decrypt_raw(&TEST_KEY, &nonce, &ct).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn raw_wrong_key() {
        let (nonce, ct) = encrypt_raw(&TEST_KEY, b"secret");
        assert!(decrypt_raw(&WRONG_KEY, &nonce, &ct).is_err());
    }

    #[test]
    fn raw_corrupted_ciphertext() {
        let (nonce, mut ct) = encrypt_raw(&TEST_KEY, b"secret");
        ct[0] ^= 0xff;
        assert!(decrypt_raw(&TEST_KEY, &nonce, &ct).is_err());
    }

    #[test]
    fn raw_wrong_nonce() {
        let (mut nonce, ct) = encrypt_raw(&TEST_KEY, b"secret");
        nonce[0] ^= 0xff;
        assert!(decrypt_raw(&TEST_KEY, &nonce, &ct).is_err());
    }

    // -- verify_key (2 tests) --

    #[test]
    fn verify_key_correct() {
        let (nonce, ct) = encrypt_raw(&TEST_KEY, VERIFY_PLAINTEXT);
        assert!(verify_key(&TEST_KEY, &nonce, &ct));
    }

    #[test]
    fn verify_key_wrong() {
        let (nonce, ct) = encrypt_raw(&TEST_KEY, VERIFY_PLAINTEXT);
        assert!(!verify_key(&WRONG_KEY, &nonce, &ct));
    }

    // -- encrypt / decrypt with AAD (5 tests) --

    #[test]
    fn aad_roundtrip() {
        let (nonce, ct) = encrypt(&TEST_KEY, "github", "user", "pass", "my notes", "https://github.com");
        let (u, p, n, url) = decrypt(&TEST_KEY, "github", &nonce, &ct).unwrap();
        assert_eq!(u, "user");
        assert_eq!(p, "pass");
        assert_eq!(n, "my notes");
        assert_eq!(url, "https://github.com");
    }

    #[test]
    fn aad_empty_notes_url() {
        let (nonce, ct) = encrypt(&TEST_KEY, "svc", "user", "pass", "", "");
        let (u, p, n, url) = decrypt(&TEST_KEY, "svc", &nonce, &ct).unwrap();
        assert_eq!(u, "user");
        assert_eq!(p, "pass");
        assert_eq!(n, "");
        assert_eq!(url, "");
    }

    #[test]
    fn aad_wrong_service() {
        let (nonce, ct) = encrypt(&TEST_KEY, "github", "user", "pass", "", "");
        assert!(decrypt(&TEST_KEY, "gitlab", &nonce, &ct).is_err());
    }

    #[test]
    fn aad_wrong_key() {
        let (nonce, ct) = encrypt(&TEST_KEY, "svc", "user", "pass", "", "");
        assert!(decrypt(&WRONG_KEY, "svc", &nonce, &ct).is_err());
    }

    #[test]
    fn aad_different_nonces() {
        let (n1, _) = encrypt(&TEST_KEY, "svc", "user", "pass", "", "");
        let (n2, _) = encrypt(&TEST_KEY, "svc", "user", "pass", "", "");
        assert_ne!(n1, n2);
    }

    // -- generate_password (6 tests) --

    #[test]
    fn generate_correct_length() {
        for len in [8, 16, 32, 64, 128] {
            let pw = generate_password(len, &Charset::Default);
            assert_eq!(pw.len(), len);
        }
    }

    #[test]
    fn generate_default_charset() {
        let valid: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_=+?";
        let pw = generate_password(200, &Charset::Default);
        for c in pw.bytes() {
            assert!(valid.contains(&c), "unexpected char: {}", c as char);
        }
    }

    #[test]
    fn generate_alphanumeric_charset() {
        let pw = generate_password(200, &Charset::Alphanumeric);
        for c in pw.chars() {
            assert!(c.is_ascii_alphanumeric(), "unexpected char: {c}");
        }
    }

    #[test]
    fn generate_hex_charset() {
        let valid: &[u8] = b"0123456789abcdef";
        let pw = generate_password(200, &Charset::Hex);
        for c in pw.bytes() {
            assert!(valid.contains(&c), "unexpected char: {}", c as char);
        }
    }

    #[test]
    fn generate_dna_charset() {
        let valid: &[u8] = b"ACGT";
        let pw = generate_password(200, &Charset::Dna);
        for c in pw.bytes() {
            assert!(valid.contains(&c), "unexpected char: {}", c as char);
        }
    }

    #[test]
    fn generate_non_deterministic() {
        let a = generate_password(32, &Charset::Default);
        let b = generate_password(32, &Charset::Default);
        assert_ne!(*a, *b);
    }

    // -- password_entropy (3 tests) --

    #[test]
    fn entropy_empty() {
        assert_eq!(password_entropy(""), 0.0);
    }

    #[test]
    fn entropy_lowercase_only() {
        let e = password_entropy("abcdefgh");
        let expected = 8.0 * 26_f64.log2();
        assert!((e - expected).abs() < 0.01);
    }

    #[test]
    fn entropy_mixed() {
        let e = password_entropy("aA1!");
        let expected = 4.0 * 94_f64.log2();
        assert!((e - expected).abs() < 0.01);
    }

    // -- unicode (1 test) --

    #[test]
    fn unicode_credential_fields() {
        let (nonce, ct) = encrypt(&TEST_KEY, "日本語", "用户名", "密码🔑", "笔记📝", "https://例え.jp");
        let (u, p, n, url) = decrypt(&TEST_KEY, "日本語", &nonce, &ct).unwrap();
        assert_eq!(u, "用户名");
        assert_eq!(p, "密码🔑");
        assert_eq!(n, "笔记📝");
        assert_eq!(url, "https://例え.jp");
    }
}
