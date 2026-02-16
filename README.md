# simpleKeychain2 (sk2)

**Version 0.2.2**

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

Prompts for username and password (you must provide your own password). If the service already exists, it will be overwritten.

To generate a random password instead:

```bash
sk2 add github --generate
```

This creates a 16-character random password (letters, digits, and symbols) using a cryptographically secure random number generator (ChaCha12 CSPRNG seeded from the OS entropy source via `getrandom`). The generated password is never printed to the terminal — use `sk2 get github` to copy it to your clipboard.

To specify a custom length (4–64):

```bash
sk2 add github --generate --length 24
```

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

## Creating Backups

sk2 can export all your credentials into a GPG-encrypted CSV file. The plaintext is never written to disk — it is piped directly from sk2 to GPG in memory.

Requires [GPG](https://gnupg.org/) to be installed and in your `PATH`.

### Basic export

```bash
sk2 export
```

This creates `sk2-export.csv.gpg` in your current directory. GPG will prompt you to set a passphrase for the export file.

To choose a different output path:

```bash
sk2 export -o /mnt/usb/backup.csv.gpg
```

### Decrypting the backup

No sk2 needed — just GPG:

```bash
gpg -d sk2-export.csv.gpg > credentials.csv
```

The CSV has three columns: `name`, `username`, `password`. This format can be imported into most other password managers.

### Extra precautions

If you want to be thorough about minimizing exposure:

- **Decrypt to a RAM-backed filesystem.** Decrypting to RAM avoids writing plaintext to a physical disk where it could be recovered after deletion.

  Linux/macOS (`/tmp` is often a tmpfs):
  ```bash
  gpg -d sk2-export.csv.gpg > /tmp/credentials.csv
  # use the file, then:
  shred -u /tmp/credentials.csv
  ```
  Windows (requires a RAM disk tool like [ImDisk](https://sourceforge.net/projects/imdisk-toolkit/)):
  ```powershell
  gpg -d sk2-export.csv.gpg > R:\credentials.csv
  # use the file, then delete it — or simply unmount the RAM disk
  ```

- **Securely delete the decrypted file.** Regular deletion only removes the directory entry — the data remains on disk until overwritten.

  Linux/macOS:
  ```bash
  shred -u credentials.csv
  ```
  Windows (built-in `cipher /w` wipes free space in a directory after you delete the file):
  ```powershell
  del credentials.csv
  cipher /w:C:\path\to\directory
  ```
  Note: secure deletion is ineffective on copy-on-write filesystems (ZFS, Btrfs) and SSDs with wear leveling, which is why decrypting to a RAM-backed filesystem is the safer option.

- **Export directly to removable media.** Write the `.gpg` file to a USB drive, then physically disconnect it:
  ```bash
  sk2 export -o /mnt/usb/sk2-export.csv.gpg        # Linux/macOS
  sk2 export -o E:\sk2-export.csv.gpg               # Windows
  ```
- **Verify the backup.** After exporting, confirm you can decrypt it before relying on it:
  ```bash
  gpg -d sk2-export.csv.gpg | head -2               # Linux/macOS
  ```
  ```powershell
  gpg -d sk2-export.csv.gpg | Select-Object -First 2   # Windows (PowerShell)
  ```
- **Use a different passphrase.** GPG will prompt you to choose a passphrase for the export file. Don't reuse your vault master password — if someone obtains both the vault file and the export file, one password shouldn't unlock both.

### Disabling export

The export feature is included by default. If you don't want the export command in your binary at all (e.g., to eliminate bulk credential extraction as an attack surface), compile without it:

```bash
cargo build --release --no-default-features
```

This removes the `export` subcommand entirely — it won't appear in `--help` and the code is excluded from the binary.

## Security

- **Encryption** — Credentials are encrypted with XChaCha20-Poly1305 with per-service AAD. The encryption key is derived from your master password using Argon2id (4 iterations, 128 MiB).
- **Memory** — Secrets (master password, derived key, decrypted passwords) are zeroed in memory when no longer needed, including on error paths (e.g. wrong password, empty input).
- **Clipboard** — Copied passwords are automatically cleared from the clipboard after 10 seconds.
- **File permissions** — On Linux/macOS, `~/.sk2/` is set to `0700` and `vault.db` to `0600` (owner-only access) on every run.
- **Vault location** — The vault is always stored at `~/.sk2/vault.db` (`C:\Users\<USERNAME>\.sk2\vault.db` on Windows), so it works the same regardless of your current directory.

## Platform Support

Works on **Linux**, **macOS**, and **Windows**. Clipboard support is provided by [arboard](https://github.com/1Password/arboard) (maintained by 1Password).
