// Argon2id cost parameters for NEW vaults, and the target `change-password` migrates
// an existing vault to. Reached via `crypto::KdfParams::CURRENT`.
//
// Safe to raise. Each vault stores the parameters it was created with, and
// `vault::unlock_vault` derives its key from those (`db::load_params`) rather than from
// these constants, so raising them cannot lock an existing vault out.
//
// They do NOT govern SK2B backups. That format pins its own parameters because its
// header has nowhere to record them — see `crypto::KdfParams::SK2B_V1` before assuming
// a change here is free.
pub(crate) const TIME_COST: u32 = 4;
pub(crate) const MEMORY_COST: u32 = 128 * 1024; // 128 MiB
pub(crate) const PARALLELISM: u32 = 4;

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const VERIFY_PLAINTEXT: &[u8] = b"sk2-vault-ok";
pub(crate) const CLIPBOARD_CLEAR_SECONDS: u64 = 10;
