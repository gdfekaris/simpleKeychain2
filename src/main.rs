use argon2::{Argon2, Algorithm, Version, Params};
use rand::RngCore;

fn main() {
    let password = rpassword::read_password_from_tty(Some("Enter master password: "))
        .expect("Failed to read password");

    if password.is_empty() {
        eprintln!("Password cannot be empty.");
        std::process::exit(1);
    }

    // Generate a random 16-byte salt
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    // Argon2id parameters: 3 iterations, 64 MiB memory, 4 threads
    let params = Params::new(64 * 1024, 3, 4, Some(32))
        .expect("Invalid Argon2 params");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Derive 256-bit key
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .expect("Key derivation failed");

    println!("Salt:        {}", hex(&salt));
    println!("Derived key: {}", hex(&key));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
