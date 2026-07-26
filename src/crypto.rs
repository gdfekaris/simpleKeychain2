use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
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

/// Argon2id cost parameters for a single key derivation.
///
/// Constructible only via [`KdfParams::CURRENT`], [`KdfParams::SK2B_V1`], or
/// [`KdfParams::validated`], so a combination Argon2 would reject can never reach
/// [`derive_key`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct KdfParams {
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
}

impl KdfParams {
    /// What this build writes into new vaults, and what `change-password` migrates an
    /// existing vault to.
    ///
    /// Safe to raise. Every vault records the parameters it was created with, and
    /// `vault::unlock_vault` derives using *those* (via `db::load_params`) rather than
    /// these — so raising them locks nobody out. Users pick up the stronger parameters
    /// by running `change-password`.
    pub(crate) const CURRENT: Self = Self {
        time_cost: TIME_COST,
        memory_cost: MEMORY_COST,
        parallelism: PARALLELISM,
    };

    /// Parameters frozen into the SK2B v1 container format.
    ///
    /// Deliberately written as literals rather than as `CURRENT`. The SK2B header is
    /// magic + version + salt + nonce — it has **no parameter field** — so these values
    /// are part of the format itself. Every `.sk2backup` ever written and the iOS
    /// `sk2-core` build assume exactly these.
    ///
    /// Changing them would silently make existing backups undecryptable, which is the
    /// same trap `CURRENT` was just freed from. Raising the KDF cost for backups
    /// requires `BACKUP_VERSION` 0x02 carrying the parameters in the header, plus a
    /// matching change on iOS.
    ///
    /// Gated like the `backup` module itself — with neither feature there is no SK2B
    /// container to derive keys for.
    #[cfg(any(feature = "export", feature = "import"))]
    pub(crate) const SK2B_V1: Self = Self {
        time_cost: 4,
        memory_cost: 128 * 1024,
        parallelism: 4,
    };

    /// Parameters read back out of a vault's metadata row.
    ///
    /// Rejects values Argon2 cannot accept, so a corrupt or hand-edited row produces a
    /// diagnosable error instead of a panic inside `derive_key`.
    pub(crate) fn validated(
        time_cost: u32,
        memory_cost: u32,
        parallelism: u32,
    ) -> Result<Self, String> {
        Params::new(memory_cost, time_cost, parallelism, Some(KEY_LEN)).map_err(|e| {
            format!(
                "Vault metadata holds Argon2 parameters this build cannot use \
                 (time_cost={time_cost}, memory_cost={memory_cost}, parallelism={parallelism}): {e}"
            )
        })?;
        Ok(Self {
            time_cost,
            memory_cost,
            parallelism,
        })
    }

    pub(crate) fn time_cost(&self) -> u32 {
        self.time_cost
    }

    pub(crate) fn memory_cost(&self) -> u32 {
        self.memory_cost
    }

    pub(crate) fn parallelism(&self) -> u32 {
        self.parallelism
    }
}

/// Derive a 256-bit key. `kdf` is explicit at every call site so that the choice
/// between "this vault's recorded parameters" and "the parameters this format pins"
/// is always a conscious one — see [`KdfParams`].
pub(crate) fn derive_key(password: &str, salt: &[u8], kdf: KdfParams) -> Zeroizing<[u8; KEY_LEN]> {
    // Infallible: a KdfParams value only exists if Params::new already accepted it.
    let params = Params::new(
        kdf.memory_cost,
        kdf.time_cost,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .expect("KdfParams invariant violated");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *key)
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

/// The alphabet a charset draws from. Single source of truth: `generate_password`
/// samples from it and `main::validated_generate` takes `.len()` for the entropy
/// estimate, so the two cannot disagree.
///
/// They previously did. `validated_generate` restated the sizes as `74/62/66/16/4`
/// and the default alphabet is **75** characters, so every entropy figure for the
/// default charset was quietly understated.
pub(crate) fn charset_bytes(charset: &Charset) -> &'static [u8] {
    match charset {
        Charset::Default => {
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_=+?"
        }
        Charset::Alphanumeric => b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        Charset::Websafe => b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~",
        Charset::Hex => b"0123456789abcdef",
        Charset::Dna => b"ACGT",
    }
}

pub(crate) fn generate_password(length: usize, charset: &Charset) -> Zeroizing<String> {
    let chars: &[u8] = charset_bytes(charset);
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
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_other = true;
        }
    }
    let mut alphabet = 0u32;
    if has_lower {
        alphabet += 26;
    }
    if has_upper {
        alphabet += 26;
    }
    if has_digit {
        alphabet += 10;
    }
    if has_other {
        alphabet += 32;
    }
    if alphabet == 0 {
        return 0.0;
    }
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

pub(crate) fn decrypt_raw(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ()> {
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

pub(crate) fn encrypt(
    key: &[u8; KEY_LEN],
    service: &str,
    username: &str,
    password: &str,
    notes: &str,
    url: &str,
) -> (Vec<u8>, Vec<u8>) {
    let cred = Credential {
        username: username.to_string(),
        password: password.to_string(),
        notes: if notes.is_empty() {
            None
        } else {
            Some(notes.to_string())
        },
        url: if url.is_empty() {
            None
        } else {
            Some(url.to_string())
        },
    };
    let plaintext = serde_json::to_vec(&cred).expect("Failed to serialize credential");

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_ref(),
                aad: service.as_bytes(),
            },
        )
        .expect("Encryption failed");
    (nonce_bytes.to_vec(), ciphertext)
}

pub(crate) fn decrypt(
    key: &[u8; KEY_LEN],
    service: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<(String, String, String, String), ()> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: service.as_bytes(),
            },
        )
        .map_err(|_| ())?;

    let cred: Credential = serde_json::from_slice(&plaintext).map_err(|_| ())?;
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
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    const WRONG_KEY: [u8; KEY_LEN] = [0xff; KEY_LEN];

    // -- derive_key (3 tests) --

    #[test]
    fn derive_key_deterministic() {
        let salt = b"fixed_salt_16byt";
        let k1 = derive_key("password", salt, KdfParams::CURRENT);
        let k2 = derive_key("password", salt, KdfParams::CURRENT);
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn derive_key_different_password() {
        let salt = b"fixed_salt_16byt";
        let k1 = derive_key("password1", salt, KdfParams::CURRENT);
        let k2 = derive_key("password2", salt, KdfParams::CURRENT);
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn derive_key_different_salt() {
        let k1 = derive_key("password", b"salt_aaaaaaaaaa16", KdfParams::CURRENT);
        let k2 = derive_key("password", b"salt_bbbbbbbbbb16", KdfParams::CURRENT);
        assert_ne!(*k1, *k2);
    }

    // -- KdfParams (6 tests) --

    /// Pins the SK2B v1 format. These values are not free to change: the container
    /// header has no parameter field, so every existing `.sk2backup` and the iOS
    /// `sk2-core` build assume exactly these. If this test fails, the format changed —
    /// which requires a BACKUP_VERSION bump, not an edit to this assertion.
    #[test]
    #[cfg(any(feature = "export", feature = "import"))]
    fn sk2b_v1_params_are_pinned() {
        assert_eq!(KdfParams::SK2B_V1.time_cost(), 4);
        assert_eq!(KdfParams::SK2B_V1.memory_cost(), 128 * 1024);
        assert_eq!(KdfParams::SK2B_V1.parallelism(), 4);
    }

    #[test]
    fn current_params_match_constants() {
        assert_eq!(KdfParams::CURRENT.time_cost(), TIME_COST);
        assert_eq!(KdfParams::CURRENT.memory_cost(), MEMORY_COST);
        assert_eq!(KdfParams::CURRENT.parallelism(), PARALLELISM);
    }

    #[test]
    fn validated_accepts_stored_params() {
        let p = KdfParams::validated(3, 64 * 1024, 2).unwrap();
        assert_eq!(
            (p.time_cost(), p.memory_cost(), p.parallelism()),
            (3, 64 * 1024, 2)
        );
    }

    /// A corrupt or hand-edited metadata row must not reach `derive_key`, where bad
    /// parameters would panic instead of producing a diagnosable error.
    #[test]
    fn validated_rejects_impossible_params() {
        // time_cost = 0 and parallelism = 0 are both outside what Argon2 accepts.
        assert!(KdfParams::validated(0, 64 * 1024, 1).is_err());
        assert!(KdfParams::validated(1, 64 * 1024, 0).is_err());
        // Memory below 8 KiB per lane is rejected too.
        assert!(KdfParams::validated(1, 1, 1).is_err());
    }

    /// F2: the whole point of storing parameters per vault. A key derived under one
    /// set of parameters must still be reproducible after the build's constants move
    /// on — otherwise raising MEMORY_COST would brick every existing vault.
    #[test]
    fn key_is_reproducible_under_its_own_params() {
        let salt = b"fixed_salt_16byt";
        let old = KdfParams::validated(2, 32 * 1024, 1).unwrap();

        let at_creation = derive_key("password", salt, old);
        // Simulates a later build whose CURRENT has moved on but which loaded `old`
        // back out of the vault's metadata row.
        let at_unlock = derive_key("password", salt, old);
        assert_eq!(*at_creation, *at_unlock);

        // And the same password under this build's parameters is a *different* key —
        // which is exactly why unlock must use the stored ones.
        let under_current = derive_key("password", salt, KdfParams::CURRENT);
        assert_ne!(*at_creation, *under_current);
    }

    #[test]
    fn different_params_give_different_keys() {
        let salt = b"fixed_salt_16byt";
        let a = derive_key(
            "password",
            salt,
            KdfParams::validated(2, 32 * 1024, 1).unwrap(),
        );
        let b = derive_key(
            "password",
            salt,
            KdfParams::validated(3, 32 * 1024, 1).unwrap(),
        );
        assert_ne!(*a, *b);
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
        let (nonce, ct) = encrypt(
            &TEST_KEY,
            "github",
            "user",
            "pass",
            "my notes",
            "https://github.com",
        );
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
        let valid: &[u8] =
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_=+?";
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

    /// `main::validated_generate` reports entropy as `length * log2(charset.len())`.
    /// That is only honest if each alphabet is duplicate-free — a repeated character
    /// would make the true entropy lower than the figure shown to the user.
    #[test]
    fn charsets_contain_no_duplicate_characters() {
        for charset in [
            Charset::Default,
            Charset::Alphanumeric,
            Charset::Websafe,
            Charset::Hex,
            Charset::Dna,
        ] {
            let bytes = charset_bytes(&charset);
            let mut seen = std::collections::HashSet::new();
            for b in bytes {
                assert!(
                    seen.insert(b),
                    "duplicate character {:?} would overstate reported entropy",
                    *b as char
                );
            }
        }
    }

    /// F7a: the entropy estimate is derived from this table rather than restating it.
    /// The default alphabet is 75 characters — it was previously hardcoded as 74.
    #[test]
    fn default_charset_is_75_characters() {
        assert_eq!(charset_bytes(&Charset::Default).len(), 75);
        assert_eq!(charset_bytes(&Charset::Alphanumeric).len(), 62);
        assert_eq!(charset_bytes(&Charset::Websafe).len(), 66);
        assert_eq!(charset_bytes(&Charset::Hex).len(), 16);
        assert_eq!(charset_bytes(&Charset::Dna).len(), 4);
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
        let (nonce, ct) = encrypt(
            &TEST_KEY,
            "日本語",
            "用户名",
            "密码🔑",
            "笔记📝",
            "https://例え.jp",
        );
        let (u, p, n, url) = decrypt(&TEST_KEY, "日本語", &nonce, &ct).unwrap();
        assert_eq!(u, "用户名");
        assert_eq!(p, "密码🔑");
        assert_eq!(n, "笔记📝");
        assert_eq!(url, "https://例え.jp");
    }
}
