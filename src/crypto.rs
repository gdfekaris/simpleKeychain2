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

pub(crate) fn encrypt(key: &[u8; KEY_LEN], service: &str, username: &str, password: &str) -> (Vec<u8>, Vec<u8>) {
    let cred = Credential {
        username: username.to_string(),
        password: password.to_string(),
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

pub(crate) fn decrypt(key: &[u8; KEY_LEN], service: &str, nonce: &[u8], ciphertext: &[u8]) -> Result<(String, String), ()> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce);

    let plaintext = cipher.decrypt(nonce, Payload {
        msg: ciphertext,
        aad: service.as_bytes(),
    }).map_err(|_| ())?;

    let cred: Credential =
        serde_json::from_slice(&plaintext).map_err(|_| ())?;
    Ok((cred.username, cred.password))
}
