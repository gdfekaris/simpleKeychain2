# simpleKeychain2 (sk2)

**Version 0.2.6 beta**

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

To attach a URL to the credential:

```bash
sk2 add github --url https://github.com
```

To attach notes (recovery codes, security question answers, etc.):

```bash
sk2 add github --notes
```

The `--notes` flag triggers an interactive prompt rather than accepting an inline value, so sensitive notes are never passed as a command-line argument and never appear in shell history. Both flags can be combined with each other and with `--generate`:

```bash
sk2 add github --generate --notes --url https://github.com
```

To generate a random password instead:

```bash
sk2 add github --generate
```

This creates a 16-character random password (letters, digits, and symbols) using a cryptographically secure random number generator (ChaCha12 CSPRNG seeded from the OS entropy source via `getrandom`). The generated password is never printed to the terminal — use `sk2 get github` to copy it to your clipboard.

To specify a custom length (4–64):

```bash
sk2 add github --generate --length 24
```

To restrict the character set (useful when a site has password rules):

```bash
sk2 add github --generate --charset alphanumeric   # letters and digits only
sk2 add github --generate --charset websafe        # RFC 3986 unreserved chars, safe in URLs and forms
sk2 add github --generate --charset hex            # 0–9, a–f
sk2 add github --generate --charset dna            # A, C, G, T
```

The default charset (`default`) uses letters, digits, and symbols. For small character sets like `hex` or `dna`, consider increasing `--length` to maintain adequate entropy — sk2 will warn you if generated entropy falls below 64 bits.

### Retrieve a credential

```bash
sk2 get github
```

Prints the service name, username, and how long ago the password was last set. If a URL or notes are stored for the credential, they are displayed below the username. The password is copied to your clipboard and automatically cleared after 10 seconds.

If no exact match is found, sk2 falls back to a case-insensitive substring search. A single match is used automatically; multiple matches are shown as a numbered list to pick from.

### Edit a credential

```bash
sk2 edit github
```

Prompts for a new username and password. Press Enter on either field to keep the current value. The password prompt is a blind TTY read — leave it blank to leave the password unchanged.

To update only specific fields, use flags:

```bash
sk2 edit github --username           # prompts for username only
sk2 edit github --password           # prompts for password only
sk2 edit github --notes              # prompts for notes only
sk2 edit github --url                # prompts for URL only
sk2 edit github --notes --url        # prompts for notes and URL
```

When editing notes or URL, the current value is shown in brackets — press Enter to keep it. This is also how you add notes or a URL to a credential that was created without them.

The last-updated timestamp is only refreshed when the password itself changes. Editing only the username, notes, or URL leaves the timestamp untouched.

### Rename a credential

```bash
sk2 rename github github-personal
```

Renames a stored service without a delete and re-add round-trip. The credential is decrypted and re-encrypted under the new name, preserving the AAD binding. The new name must not already exist in the vault.

This is also useful for introducing sub-key naming conventions after the fact:

```bash
sk2 rename gmail gmail:personal
sk2 add gmail:work
```

### Delete a credential

```bash
sk2 delete github
```

Like `get`, partial matching applies if no exact service name is found.

### List all services

```bash
sk2 list
```

To find credentials whose password hasn't been changed recently, use `--stale`:

```bash
sk2 list --stale
```

This lists every credential not updated within the last 90 days.

To use a different threshold:

```bash
sk2 list --stale --days 180    # flag anything older than 6 months
sk2 list --stale --days 30     # stricter 30-day policy
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

The CSV has five columns: `name`, `username`, `password`, `notes`, `url`. Notes and URL fields will be empty for credentials that have none set.

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

## Restoring from Backup

sk2 can import credentials from a GPG-encrypted CSV file (the same format `export` produces). Requires [GPG](https://gnupg.org/) in your `PATH`.

The expected CSV format is `name,username,password,notes,url`. Files exported by older versions of sk2 with only three columns (`name,username,password`) are also accepted — notes and URL will be left empty for those rows.

### Basic import

```bash
sk2 import sk2-export.csv.gpg
```

GPG will prompt for the passphrase used when the file was exported. You'll then be asked to confirm before any credentials are written.

If a service in the CSV already exists in your vault, it will be silently overwritten. Services not mentioned in the CSV are left untouched.

### Round-trip example

```bash
sk2 export -o backup.csv.gpg    # export from old vault
rm ~/.sk2/vault.db               # start fresh (or move to a new machine)
sk2 init                         # set up a new vault
sk2 import backup.csv.gpg       # restore all credentials
```

### Security during import

- **Decryption happens in GPG** — sk2 invokes `gpg --decrypt` and reads the output. The encrypted file is never parsed directly by sk2.
- **Plaintext is held in zeroed memory** — The decrypted CSV is wrapped in `Zeroizing<String>` and automatically wiped from memory when the import completes (or on any error).
- **Each credential is re-encrypted individually** — Imported credentials are encrypted with fresh random nonces and AAD-bound to their service name, exactly like `sk2 add`. They are not stored as-is from the CSV.
- **Master password required** — The vault must be unlocked before import begins, same as every other command.
- **Timestamps reset on import** — Imported credentials receive a last-updated timestamp of the moment of import. The CSV format does not carry age information, so sk2 has no way to know when each password was originally set. This means `sk2 list --stale` will measure staleness from the import date, not from when the passwords were created. If you are importing old credentials and care about rotation tracking, update the passwords after importing.

### Disabling import

Like export, the import feature can be excluded at compile time:

```bash
cargo build --release --no-default-features --features export   # export only, no import
cargo build --release --no-default-features                     # neither export nor import
```

## Security

- **Encryption** — Credentials are encrypted with XChaCha20-Poly1305 with per-service AAD. The encryption key is derived from your master password using Argon2id (4 iterations, 128 MiB).
- **Memory** — Secrets (master password, derived key, decrypted passwords) are zeroed in memory when no longer needed, including on error paths (e.g. wrong password, empty input).
- **Clipboard** — Copied passwords are automatically cleared from the clipboard after 10 seconds.
- **File permissions** — On Linux/macOS, `~/.sk2/` is set to `0700` and `vault.db` to `0600` (owner-only access) on every run.
- **Vault location** — The vault is always stored at `~/.sk2/vault.db` (`C:\Users\<USERNAME>\.sk2\vault.db` on Windows), so it works the same regardless of your current directory.

## Platform Support

Works on **Linux**, **macOS**, and **Windows**. Clipboard support is provided by [arboard](https://github.com/1Password/arboard) (maintained by 1Password).
