# simpleKeychain2 (sk2)

A lightweight, local-only CLI password manager. No servers, no sync, no network. Your credentials stay on your machine, encrypted with your master password.

> This README tracks the `main` branch and may describe features newer than the latest release. Each release archive ships the README that matches it; released versions are listed in [CHANGELOG.md](CHANGELOG.md) and on the [releases page](https://github.com/gdfekaris/simpleKeychain2/releases).

## How It Works

- Your master password is run through **Argon2id** to derive a 256-bit encryption key.
- Each credential (username, password, and any notes/URL) is encrypted as one blob with **XChaCha20-Poly1305** using a unique random nonce.
- The service name is bound as **authenticated associated data (AAD)**, preventing ciphertext from being swapped between database rows.
- Everything is stored in a local **SQLite** database (`~/.sk2/vault.db` by default).

## Installation

### Option 1 — download a release

Prebuilt binaries for Linux (x86_64, fully static), macOS (Apple silicon and Intel), and Windows
(x86_64) are on the [releases page](https://github.com/gdfekaris/simpleKeychain2/releases). Each
archive contains the binary already named `sk2` plus this documentation.

**Verify before running** — every release ships signed checksums and a build provenance
attestation; the commands are in [SECURITY.md](SECURITY.md#verifying-downloads). The short version:

```bash
minisign -Vm SHA256SUMS -P RWS11s9lPe0uHbOvhlPE8TLPZGoW14AjTY+K1WK+RvTalQhyd+coaEwj
sha256sum -c SHA256SUMS --ignore-missing    # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
tar xzf sk2-<version>-<target>.tar.gz
sudo cp sk2-*/sk2 /usr/local/bin/           # or any directory on your PATH — see the per-platform notes below
```

Two platform warnings to expect, because sk2's binaries are not enrolled in the paid Apple/Microsoft
code-signing programs (this is unrelated to the verification above): macOS quarantines the binary
until `xattr -d com.apple.quarantine sk2`, and Windows SmartScreen needs "More info → Run anyway".

### Option 2 — build from source

Requires [Rust](https://www.rust-lang.org/tools/install) 1.88 or newer, plus a C compiler for the bundled SQLite — on Linux install your distro's build tools (e.g. `sudo apt install build-essential`), on macOS the Xcode Command Line Tools (`xcode-select --install`).

```bash
git clone https://github.com/gdfekaris/simpleKeychain2.git
cd simpleKeychain2
cargo build --release --locked
```

`--locked` builds the exact dependency versions committed in `Cargo.lock` — the same tree CI tests and audits, and the one the release binaries are built from.

#### Linux

```bash
mkdir -p ~/.local/bin
cp target/release/simpleKeychain2 ~/.local/bin/sk2
```

Most distros put `~/.local/bin` on your `PATH` automatically — but often only if the directory existed when your session started, so if `sk2` isn't found, log out and back in (or add `export PATH="$HOME/.local/bin:$PATH"` to your shell profile).

#### macOS

```bash
sudo cp target/release/simpleKeychain2 /usr/local/bin/sk2
```

`/usr/local/bin` is on the default `PATH` on both Apple silicon and Intel Macs. If you prefer a no-`sudo` install, copy the binary anywhere you like and add that directory to `PATH` in `~/.zshrc` — macOS does not put `~/.local/bin` on `PATH` by default.

#### Windows

Requires [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (for compiling the bundled SQLite C library).

```powershell
copy target\release\simpleKeychain2.exe $env:USERPROFILE\bin\sk2.exe
```

Make sure `%USERPROFILE%\bin` is in your `PATH`, or choose another directory that is.

## Usage

Every command that touches the vault asks for your master password first. The one exception is `generate`, which neither reads nor writes the vault.

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

`--length` and `--charset` are only meaningful together with `--generate`; supplying either without it is rejected immediately, before you are asked for your master password.

### Generate a password without storing it

```bash
sk2 generate
```

Generates a random password and prints it to your terminal. Unlike `add --generate`, nothing is stored — no vault access or master password is required.

> **Security note:** Because the password is printed directly to your terminal, it will be visible in your terminal scroll-back history. Only use `generate` for throwaway passwords. To generate and store a password without it ever appearing on screen, use `sk2 add --generate` instead.

The same length and character set options from `add --generate` are available:

```bash
sk2 generate --length 24
sk2 generate --charset alphanumeric
sk2 generate --length 32 --charset websafe
```

The generated password is also copied to your clipboard and cleared after 10 seconds.

### Retrieve a credential

```bash
sk2 get github
```

Prints the service name, username, and how long ago the password was last set. If a URL or notes are stored for the credential, they are displayed below the username. The password is copied to your clipboard and automatically cleared after 10 seconds.

To copy the username to clipboard instead:

```bash
sk2 get github --username
```

On a machine with no clipboard — a headless server, an SSH session without forwarding — the clipboard is unavailable and `get` fails rather than silently changing where the secret goes. To display the value instead, opt in explicitly:

```bash
sk2 get github --print
```

`--print` writes the bare password (and nothing else) to stdout, prints a warning to stderr, and skips the clipboard entirely, so `PASS=$(sk2 get github --print)` captures exactly the secret. Be aware of what you are trading: printed output has no 10-second clear — it stays in your terminal scrollback and any session logs until you clear them. Prefer the clipboard when you have one. Combined with `--username`, `--print` outputs the username instead. The master password prompt still requires a real terminal, so `get` remains interactive even with `--print`.

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

When editing notes or URL, the current value is shown in brackets — press Enter to keep it. This is also how you add notes or a URL to a credential that was created without them. Like `get`, partial matching applies if no exact service name is found.

The last-updated timestamp is only refreshed when the password itself changes. Editing only the username, notes, or URL leaves the timestamp untouched.

### Rename a credential

```bash
sk2 rename github github-personal
```

Renames a stored service without a delete and re-add round-trip. The credential is decrypted and re-encrypted under the new name, preserving the AAD binding. The new name must not already exist in the vault. Like `get`, partial matching applies to the current name.

This is also useful for introducing sub-key naming conventions after the fact:

```bash
sk2 rename gmail gmail:personal
sk2 add gmail:work
```

### Delete a credential

```bash
sk2 delete github
```

You will be asked to confirm before the credential is removed. Like `get`, partial matching applies if no exact service name is found.

### List all services

```bash
sk2 list
```

To narrow the list to a substring:

```bash
sk2 list github
```

To find credentials whose password hasn't been changed recently, use `--stale`:

```bash
sk2 list --stale
```

This lists every credential not updated within the last 90 days. The filter and `--stale` can be combined:

```bash
sk2 list github --stale        # stale credentials matching 'github'
```

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

### Verify vault integrity

```bash
sk2 verify
```

Attempts to decrypt every credential and prints a per-service ✓/✗. Run it after an unexpected crash, a filesystem event, or before an export. The exit code is non-zero if any credential fails, so it can gate scripts. If an entry fails: restore it from a backup with `sk2 import` (see [Restoring from Backup](#restoring-from-backup)), or `sk2 delete <service>` and reset that password on the affected site.

### Custom vault path

By default, sk2 stores the vault at `~/.sk2/vault.db`. To use a different location, set the `SK2_VAULT` environment variable or pass the `--vault` flag (the flag takes precedence).

```bash
# Using the environment variable
export SK2_VAULT=~/vaults/work.db
sk2 init
sk2 add github

# Using the flag
sk2 --vault ~/vaults/personal.db list

# One-off override
SK2_VAULT=~/vaults/work.db sk2 list
```

This is useful for maintaining separate vaults (work vs. personal), scripting, or non-standard home directory setups. Parent directories are created automatically.

### Shell completion

sk2 can complete subcommands, flags, and **stored service names** on Tab. `sk2 completions <shell>` prints the script; where you put it depends on the shell.

```bash
# bash — either of these
mkdir -p ~/.bash_completion.d && sk2 completions bash > ~/.bash_completion.d/sk2
echo 'source <(sk2 completions bash)' >> ~/.bashrc

# zsh — a directory on your $fpath, with the leading underscore in the filename
mkdir -p ~/.zsh/completions && sk2 completions zsh > ~/.zsh/completions/_sk2
# then in ~/.zshrc, BEFORE compinit:
#   fpath=(~/.zsh/completions $fpath)

# fish
sk2 completions fish > ~/.config/fish/completions/sk2.fish

# PowerShell
sk2 completions powershell >> $PROFILE
```

Start a new shell afterwards (or `. $PROFILE` on PowerShell). Service names are completed for `get`, `delete`, `edit`, and `rename`'s *first* argument. They are deliberately **not** completed for `sk2 add`, `rename`'s second argument, or `sk2 list` — the first two are names you are coining rather than choosing, and `list` takes a substring filter, so offering exact names would imply the filter has to match one.

**No master password is involved.** Completion calls a hidden `sk2 --list-services`, which reads only the service-name column — the one field sk2 stores in plaintext by design, so that lookups work without decrypting anything. It never prompts, never prints usernames or secrets, and exits silently if there is no vault. It also never *creates* anything: pressing Tab on a machine with no vault leaves the disk untouched.

If the vault lives somewhere non-standard, completion honours `SK2_VAULT`, so exporting it in your shell profile is enough.

## Creating Backups

sk2 can export all your credentials into an encrypted backup file. Two formats are supported:

- **SK2B** (default) — native sk2 backup using Argon2id + XChaCha20-Poly1305. Self-contained, needs no external tools, and is byte-compatible with the iOS sk2 mobile app.
- **GPG** (legacy) — GPG-encrypted CSV. Requires [GPG](https://gnupg.org/) in your `PATH`. Uses a weaker KDF than SK2B; kept for compatibility with older exports.

Plaintext is never written to disk in either format — the output file is opened with `O_EXCL | O_CREAT` at mode `0600`, and the decrypted credentials live only in zeroed memory.

### Basic export

```bash
sk2 export
```

This creates `sk2-export.sk2backup` in your current directory and prompts you (twice) for a backup passphrase — you're also asked to type `yes` to confirm before anything is written.

To choose a different output path:

```bash
sk2 export -o /mnt/usb/backup.sk2backup
```

If the output file already exists, the command fails rather than clobbering it. Pass `--overwrite` to replace an existing file (the old file is unlinked and recreated with `O_EXCL`, so a planted symlink cannot survive the race):

```bash
sk2 export -o backup.sk2backup --overwrite
```

### Choosing a format

Use `--format` to pick explicitly, or let sk2 infer it from the output extension:

```bash
sk2 export                                   # SK2B, default filename
sk2 export --format sk2b                     # SK2B, default filename
sk2 export --format gpg                      # legacy GPG, default is sk2-export.csv.gpg
sk2 export -o backup.sk2backup               # inferred: SK2B
sk2 export -o backup.csv.gpg                 # inferred: GPG
```

If `--output` has an unrecognized extension and `--format` isn't set, sk2 refuses to guess.

### Decrypting the backup

**SK2B** files can only be restored with sk2 itself (or the iOS sk2 mobile app):

```bash
sk2 import sk2-export.sk2backup
```

There is no standalone decryptor for `.sk2backup` — the format is sk2-specific. If you need a human-readable export, use `--format gpg` instead.

**GPG** files can be decrypted with GPG directly, no sk2 required:

```bash
gpg -d sk2-export.csv.gpg > credentials.csv
```

The CSV has five columns: `name`, `username`, `password`, `notes`, `url`. Notes and URL fields will be empty for credentials that have none set.

### Extra precautions

If you want to be thorough about minimizing exposure:

- **Prefer SK2B when you don't need a human-readable CSV.** The plaintext only ever exists inside `sk2 import`, which holds it in zeroed memory. The GPG path produces a plaintext CSV the moment you decrypt it, and from that point on secure deletion is your problem.

- **If you decrypt a GPG export, decrypt to a RAM-backed filesystem.** Decrypting to RAM avoids writing plaintext to a physical disk where it could be recovered after deletion.

  Linux (`/tmp` is usually a tmpfs — confirm with `df -T /tmp` before relying on it; on macOS `/tmp` is ordinary disk, so prefer SK2B or create a RAM disk there):
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

- **Securely delete any decrypted CSV.** Regular deletion only removes the directory entry — the data remains on disk until overwritten.

  Linux:
  ```bash
  shred -u credentials.csv
  ```
  macOS ships no `shred`; install GNU coreutils (`brew install coreutils`, then `gshred -u`) — or avoid needing it by decrypting only to RAM.
  Windows (built-in `cipher /w` wipes free space in a directory after you delete the file):
  ```powershell
  del credentials.csv
  cipher /w:C:\path\to\directory
  ```
  Note: secure deletion is ineffective on copy-on-write filesystems (ZFS, Btrfs) and SSDs with wear leveling, which is why decrypting to a RAM-backed filesystem is the safer option.

- **Export directly to removable media.** Write the backup file to a USB drive, then physically disconnect it:
  ```bash
  sk2 export -o /mnt/usb/sk2-export.sk2backup      # Linux/macOS
  sk2 export -o E:\sk2-export.sk2backup             # Windows
  ```
- **Verify the backup.** After exporting, confirm you can restore it before relying on it. For SK2B, do a dry run against a throwaway vault:
  ```bash
  SK2_VAULT=/tmp/verify.db sk2 init
  SK2_VAULT=/tmp/verify.db sk2 import sk2-export.sk2backup
  rm /tmp/verify.db
  ```
  For GPG:
  ```bash
  gpg -d sk2-export.csv.gpg | head -2               # Linux/macOS
  ```
  ```powershell
  gpg -d sk2-export.csv.gpg | Select-Object -First 2   # Windows (PowerShell)
  ```
- **Use a different passphrase.** Whether you pick SK2B or GPG, the backup passphrase is independent of your vault master password. Don't reuse them — if someone obtains both the vault file and the backup file, one password shouldn't unlock both.

### Disabling export

The export feature is included by default. If you don't want the export command in your binary at all (e.g., to eliminate bulk credential extraction as an attack surface), compile without it:

```bash
cargo build --release --no-default-features --features import   # import only, no export
cargo build --release --no-default-features                     # neither export nor import
```

This removes the `export` subcommand entirely — it won't appear in `--help` and the code is excluded from the binary.

## Restoring from Backup

sk2 can import credentials from either backup format `export` produces. The format is autodetected by reading the first four bytes of the file — files starting with the `SK2B` magic go through the native importer; anything else is treated as a GPG-encrypted CSV and handed to `gpg --decrypt` (requires [GPG](https://gnupg.org/) in your `PATH`).

Both formats accept the 5-column schema `name,username,password,notes,url` and older 3-column exports (`name,username,password`) — notes and URL are left empty for 3-column rows. Export always writes 5 columns; 3-column support exists only for reading backups made by older versions of sk2.

The two importers differ in how strictly they treat a bad row, not in which schemas they accept — see [Transactional vs. best-effort](#transactional-vs-best-effort) below.

### Basic import

```bash
sk2 import sk2-export.sk2backup        # SK2B (native)
sk2 import sk2-export.csv.gpg          # legacy GPG CSV
```

For SK2B, sk2 prompts directly for the backup passphrase (`rpassword`, never echoed). For GPG, decryption happens in `gpg` and its own pinentry handles the prompt. In both cases you must type `yes` to confirm before any credentials are written.

If a service in the backup already exists in your vault, it will be silently overwritten. Services not mentioned in the backup are left untouched.

Import can also be used to recover corrupt credentials found by `sk2 verify` — you don't need to wipe the vault first. Be aware of the granularity, though: **every service present in the backup is overwritten**, not just the corrupt ones, so any credential you have changed since taking the backup will revert to its backed-up value. Only services absent from the backup are left as they are.

### Transactional vs. best-effort

- **SK2B imports are transactional.** All rows are inserted inside a single SQLite transaction; if any row fails to parse or insert, the transaction rolls back and your vault is left exactly as it was. Partial imports never land.
- **GPG imports are best-effort within a valid file.** Rows with the wrong number of fields or an empty service name are reported and skipped, and the rest are imported. This preserves the behavior of older sk2 exports, which may contain stray lines from hand-edited CSVs.

  A *malformed quote* is the exception: because notes may legitimately contain newlines, a stray or unterminated quote misaligns every record after it, so it cannot be attributed to a single row. The whole import aborts with an error and nothing is written. Either way a rejected file never leaves the vault half-populated: GPG imports validate the entire file before writing anything, and SK2B imports run inside a transaction that rolls back on the first bad row.

- **Exports are all-or-nothing in both formats.** If any credential fails to decrypt, the export aborts and no file is written — you are told which entry failed and pointed at `sk2 verify`. A backup exists to be trusted later, and one that silently omits entries is worse than no backup at all, because you stop looking for the missing data. Nothing is lost by failing: the unreadable credential was already unreadable, and the fix is to repair it (`sk2 import` from an older backup) or drop it (`sk2 delete`) and reset that password upstream. A credential *deleted* while the export is running is a different case and is simply reported and omitted — there is no data to lose.

### Round-trip example

```bash
sk2 export -o backup.sk2backup       # export from old vault
rm ~/.sk2/vault.db                    # start fresh (or move to a new machine)
sk2 init                              # set up a new vault
sk2 import backup.sk2backup          # restore all credentials
```

### Security during import

- **Decryption stays in trusted code paths.** SK2B is decrypted in-process with `XChaCha20-Poly1305` after deriving the backup key via Argon2id; authentication failure aborts the import. GPG backups are handed to `gpg --decrypt`, and sk2 never parses the encrypted bytes itself.
- **Plaintext is held in zeroed memory** — The decrypted CSV (and, for SK2B, the entire decrypted blob) is wrapped in `Zeroizing` and automatically wiped from memory when the import completes (or on any error). As everywhere in sk2, this is best-effort — the caveat in the Memory bullet under [Security](#security) applies here too.
- **Each credential is re-encrypted individually** — Imported credentials are encrypted with fresh random nonces and AAD-bound to their service name, exactly like `sk2 add`. They are not stored as-is from the backup.
- **Master password required** — The vault must be unlocked before import begins, same as every other command.
- **Timestamps reset on import** — Imported credentials receive a last-updated timestamp of the moment of import. Neither backup format carries age information, so sk2 has no way to know when each password was originally set. This means `sk2 list --stale` will measure staleness from the import date, not from when the passwords were created. If you are importing old credentials and care about rotation tracking, update the passwords after importing.

### Disabling import

Like export, the import feature can be excluded at compile time:

```bash
cargo build --release --no-default-features --features export   # export only, no import
cargo build --release --no-default-features                     # neither export nor import
```

## Security

For the threat model — what sk2 is and is not designed to protect against — plus known limitations
and how to report a vulnerability, see **[SECURITY.md](SECURITY.md)**. Release-by-release changes are
in **[CHANGELOG.md](CHANGELOG.md)**.

- **Encryption** — Credentials are encrypted with XChaCha20-Poly1305 with per-service AAD. The encryption key is derived from your master password using Argon2id (4 iterations, 128 MiB).
- **Key-derivation parameters** — Each vault records the Argon2id parameters it was created with, and is always unlocked using its own recorded values. A future release can raise the cost without locking existing vaults out; run `sk2 change-password` to re-key an existing vault under the newer, stronger parameters. Backups are separate: the `.sk2backup` format fixes its parameters as part of the container, so backups stay readable by any version of sk2 and by the iOS app.
- **Memory** — Secrets (master password, derived key, decrypted passwords and notes) are held in `Zeroizing` wrappers and wiped when they go out of scope, including on error paths (e.g. wrong password, empty input) and on panics, since those unwind. This now covers the credential struct itself and the JSON buffers inside encryption and decryption, which were previously ordinary unwiped allocations. It remains best-effort rather than a guarantee: a wrapper wipes the allocation it holds at the moment it drops, so it cannot reach a copy left behind when a buffer grew and moved, nor scratch allocations inside third-party parsers. A memory dump or swap file could still contain plaintext. See `SECURITY.md`.
- **Clipboard** — Copied passwords are automatically cleared from the clipboard after 10 seconds. `get` never prints a password unless you explicitly pass `--print`; if the clipboard is unavailable (headless machine, SSH without forwarding), `get` fails with a message naming that flag rather than printing on its own initiative. `generate` — which prints by design — treats a clipboard failure as a warning, not an error. Note that `--print` output has no equivalent of the 10-second clear: it persists in terminal scrollback and session logs.
- **File permissions** — On Linux/macOS, sk2 applies a process-wide `umask` of `0077` before touching the filesystem, so everything it creates is owner-only from the moment it exists. `~/.sk2/` is created directly at `0700`, `vault.db` inherits `0600`, and backup files are opened with an explicit `0600` mode. Permissions are established at creation time rather than tightened afterward, which removes the window in which a newly created file would be briefly readable by others. On Windows, files inherit default ACLs — there is no equivalent hardening.
- **Vault location** — By default, the vault is stored at `~/.sk2/vault.db` (`C:\Users\<USERNAME>\.sk2\vault.db` on Windows). Override with `--vault` or the `SK2_VAULT` environment variable (flag takes precedence). Parent directories are created automatically.
- **Password strength feedback** — When you manually enter a password during `add`, `edit`, or `change-password`, or choose a backup passphrase during `export`, sk2 estimates the entropy in bits and displays a strength label (Weak / Fair / Strong / Very strong). This is informational only — no password is rejected. Entropy is estimated conservatively by detecting which character classes are present (lowercase, uppercase, digits, symbols) rather than assuming the full character set.
- **Vault integrity check** — `sk2 verify` attempts to decrypt every credential with the current master password and reports which pass and which fail. Run it after an unexpected crash, a filesystem event, or before an export to confirm the vault is intact. Exits with a non-zero status code if any credential fails, making it suitable for use in scripts. If a credential fails: restore it from a backup with `sk2 import`, or delete it with `sk2 delete <service>` and reset the password on the affected site if no backup exists.

## Testing

The suite has two layers: unit tests alongside each module (cryptography, database, backup container, CSV parsing, CLI helpers) and — on Linux/macOS — end-to-end tests that drive the real binary through a pseudo-terminal, covering the interactive flows (init, add, edit, rename, change-password, export/import round-trip) that piped stdin cannot reach. No external dependencies or vault setup required; the end-to-end tests create and clean up their own scratch vaults.

```bash
cargo test                         # all tests (default features)
cargo test --no-default-features   # without export/import
cargo test --test cli              # just the end-to-end suite (Unix only)
```

To run tests for a specific module:

```bash
cargo test crypto::tests
cargo test db::tests
cargo test backup::tests
cargo test import::tests
cargo test export::tests
```

## Platform Support

Works on **Linux**, **macOS**, and **Windows**. Clipboard support is provided by [arboard](https://github.com/1Password/arboard) (maintained by 1Password) and requires a display server; on headless machines use `sk2 get <service> --print` to retrieve a password (`generate` works everywhere, warning if it cannot copy).
