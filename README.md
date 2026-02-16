# simpleKeychain2 (sk2)

A lightweight, local-only CLI password manager. No servers, no sync, no network. Your credentials stay on your machine, encrypted with your master password.

## How It Works

- Your master password is run through **Argon2id** to derive a 256-bit encryption key.
- Each credential (username + password) is encrypted with **XChaCha20-Poly1305** using a unique random nonce.
- The service name is bound as **authenticated associated data (AAD)**, preventing ciphertext from being swapped between database rows.
- Everything is stored in a local **SQLite** database (`~/.sk2/vault.db`).

## Installation

Requires [Rust](https://www.rust-lang.org/tools/install) (1.85+).

```bash
git clone <repo-url>
cd sk2-dev
cargo build --release
```

### Linux / macOS

```bash
cp target/release/simpleKeychain2 ~/.local/bin/sk2
```

### Windows

Requires [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (for compiling the bundled SQLite C library).

```powershell
copy target\release\simpleKeychain2.exe C:\Users\%USERNAME%\bin\sk2.exe
```

Make sure `C:\Users\%USERNAME%\bin` is in your `PATH`, or choose another directory that is.

## Usage

### Initialize the vault

Run this once to set your master password:

```bash
sk2 init
```

You'll be asked to enter and confirm your master password.

### Add a credential

```bash
sk2 add github
```

Prompts for username and password. If the service already exists, it will be overwritten.

### Retrieve a credential

```bash
sk2 get github
```

Prints the service name and username. The password is copied to your clipboard and automatically cleared after 10 seconds.

### Delete a credential

```bash
sk2 delete github
```

### List all services

```bash
sk2 list
```

### Change master password

```bash
sk2 change-password
```

Re-encrypts all stored credentials under the new password. The vault remains intact if anything fails mid-way.

All commands require your master password.

## Security

- **Encryption** — Credentials are encrypted with XChaCha20-Poly1305 with per-service AAD. The encryption key is derived from your master password using Argon2id (4 iterations, 128 MiB).
- **Memory** — Secrets (master password, derived key, decrypted passwords) are zeroed in memory as soon as they're no longer needed.
- **Clipboard** — Copied passwords are automatically cleared from the clipboard after 10 seconds.
- **File permissions** — On Linux/macOS, `~/.sk2/` is set to `0700` and `vault.db` to `0600` (owner-only access) on every run.
- **Vault location** — The vault is always stored at `~/.sk2/vault.db`, so it works the same regardless of your current directory.

## Platform Support

Works on **Linux**, **macOS**, and **Windows**. Clipboard support is provided by [arboard](https://github.com/1Password/arboard) (maintained by 1Password).
