# simpleKeychain2 (sk2)

**v1.3.0** · A lightweight, local-only CLI password manager. No servers, no sync, no network. Your credentials stay on your machine, encrypted with your master password. Works on **Linux**, **macOS**, and **Windows**.

> This README tracks the `main` branch and may describe features newer than the latest release. Each release archive ships the README that matches it; released versions are listed in [CHANGELOG.md](CHANGELOG.md) and on the [releases page](https://github.com/gdfekaris/simpleKeychain2/releases).

## Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Shell Completion](#shell-completion)
- [Backup & Restore](#backup--restore)
- [Security Model](#security-model)
- [Testing](#testing)
- [License](#license)

## Quick Start

```bash
sk2 init                 # set your master password (run once)
sk2 add github           # store a credential (prompts for username/password)
sk2 get github           # copy the password to your clipboard
```

That's the core workflow. Everything else below is detail.

## Installation

### Option 1 — download a release

Prebuilt binaries for Linux (x86_64, fully static), macOS (Apple silicon and Intel), and Windows (x86_64) are on the [releases page](https://github.com/gdfekaris/simpleKeychain2/releases). Each archive contains the binary already named `sk2` plus this documentation.

**Verify before running** — every release ships signed checksums and a build provenance attestation; the full commands are in [SECURITY.md](SECURITY.md#verifying-downloads). The short version:

```bash
minisign -Vm SHA256SUMS -P RWS11s9lPe0uHbOvhlPE8TLPZGoW14AjTY+K1WK+RvTalQhyd+coaEwj
sha256sum -c SHA256SUMS --ignore-missing    # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
tar xzf sk2-<version>-<target>.tar.gz
sudo cp sk2-*/sk2 /usr/local/bin/           # or any directory on your PATH
```

Expect two platform warnings, because sk2's binaries are not enrolled in the paid Apple/Microsoft code-signing programs (this is unrelated to the verification above): macOS quarantines the binary until `xattr -d com.apple.quarantine sk2`, and Windows SmartScreen needs "More info → Run anyway".

### Option 2 — build from source

Requires [Rust](https://www.rust-lang.org/tools/install) **1.88 or newer**, plus a C compiler for the bundled SQLite — on Linux install your distro's build tools (e.g. `sudo apt install build-essential`), on macOS the Xcode Command Line Tools (`xcode-select --install`).

**Prefer a verified source tarball where the release offers one.** Releases that ship `sk2-X.Y.Z-src.tar.gz` list it in `SHA256SUMS`, so it verifies against the maintainer's minisign signature exactly like the binaries do — see [SECURITY.md](SECURITY.md#verifying-downloads). A `git clone` is authenticated by nothing but TLS to GitHub. Releases up to and including v1.3.0 ship none.

To build from a clone instead:

```bash
git clone --branch v1.3.0 --depth 1 https://github.com/gdfekaris/simpleKeychain2.git
cd simpleKeychain2
cargo build --release --locked
```

**Build from the tag, not from `main`.** `main` is the only long-lived branch in this repository, so it is also where in-progress work lands — including work that may be revised or reverted before it ships. Cloning without `--branch` puts you on whatever was pushed most recently, which is not a release and has not been through the release checklist. The tag above is the exact tree that release's binaries were built from; substitute the latest version from the [releases page](https://github.com/gdfekaris/simpleKeychain2/releases).

`--locked` builds the exact dependency versions committed in `Cargo.lock` — the same tree CI tests and audits, and the one the release binaries are built from.

If you *want* the development tip, drop the `--branch` and `--depth` flags deliberately. Everything in this README applies to `main`; see the note at the top about features that may not be in a release yet.

#### Linux

```bash
mkdir -p ~/.local/bin
cp target/release/simpleKeychain2 ~/.local/bin/sk2
```

Most distributions put `~/.local/bin` on your `PATH` automatically, but often only if the directory existed when your session started. If `sk2` isn't found, log out and back in — or add `export PATH="$HOME/.local/bin:$PATH"` to your shell profile.

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

### Compile-time features

sk2 has three optional features — `export`, `import`, and `completion` — all enabled by default. Any of them can be left out of the binary entirely. An excluded subcommand doesn't appear in `--help`, is rejected as unknown, and its code isn't compiled in at all.

```bash
# keep backups, drop the completion surface (see "The trade you are accepting")
cargo build --release --locked --no-default-features --features export,import

# import only — no bulk credential extraction
cargo build --release --locked --no-default-features --features import

# export only
cargo build --release --locked --no-default-features --features export

# none of the three
cargo build --release --locked --no-default-features
```

Dropping `export` removes bulk credential extraction as an attack surface. Dropping `completion` removes the one path that reveals service names without a master password — see [The trade you are accepting](#the-trade-you-are-accepting).

## Usage

Every command that touches the vault asks for your master password first. Two commands never touch it and so never ask: `generate`, which produces a password without storing it, and `completions`, which prints a shell script. Tab completion is a third case and a deliberate exception — it reads service names without a password, for the reasons set out in [The trade you are accepting](#the-trade-you-are-accepting).

Clipboard support is provided by [arboard](https://github.com/1Password/arboard), maintained by 1Password.

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

Prompts for a username and a password that you supply yourself. If the service already exists, `add` overwrites it without asking.

To attach a URL to the credential:

```bash
sk2 add github --url https://github.com
```

To attach notes (recovery codes, security question answers, etc.):

```bash
sk2 add github --notes
```

`--notes` prompts you instead of taking a value on the command line, so recovery codes and security answers never reach your shell history. Both flags combine with each other and with `--generate`:

```bash
sk2 add github --generate --notes --url https://github.com
```

To generate a random password instead:

```bash
sk2 add github --generate
```

This creates a 16-character password drawn from letters, digits, and symbols. The randomness comes from a ChaCha12 CSPRNG seeded by the operating system via `getrandom`. The password is never printed to the terminal — use `sk2 get github` to copy it to your clipboard.

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

`default` uses letters, digits, and symbols. For small character sets like `hex` or `dna`, increase `--length` to keep the entropy adequate — sk2 warns you if it falls below 64 bits.

`--length` and `--charset` only apply to `--generate`. Passing either without it is rejected immediately — before sk2 asks for your master password.

### Generate a password without storing it

```bash
sk2 generate
```

Generates a random password and prints it to your terminal. Unlike `add --generate`, nothing is stored — no vault access or master password is required.

> **Security note:** The password is printed to your terminal, so it stays in your scroll-back history. Only use `generate` for throwaway passwords. To generate and store one without it ever appearing on screen, use `sk2 add --generate` instead.

The same length and character set options from `add --generate` are available:

```bash
sk2 generate --length 24
sk2 generate --charset alphanumeric
sk2 generate --length 32 --charset websafe
```

The generated password is also copied to your clipboard and cleared after 10 seconds. The clipboard is an enhancement here, not a requirement: if it is unavailable, `generate` warns and still exits 0, since the password is already on screen.

### Retrieve a credential

```bash
sk2 get github
```

Prints the service name, username, and how long ago the password was last set. If a URL or notes are stored for the credential, they are displayed below the username. The password is copied to your clipboard and automatically cleared after 10 seconds.

To copy the username to clipboard instead:

```bash
sk2 get github --username
```

On a headless server, or in an SSH session without forwarding, there is no clipboard to copy to. `get` fails rather than silently changing where the secret goes. To display the value instead, opt in explicitly:

```bash
sk2 get github --print
```

`--print` writes the bare password (and nothing else) to stdout, prints a warning to stderr, and skips the clipboard entirely, so `PASS=$(sk2 get github --print)` captures exactly the secret. The trade: printed output has no 10-second clear. It stays in your terminal scrollback and any session logs until you clear them, so prefer the clipboard when you have one. Combined with `--username`, `--print` outputs the username instead. The master password prompt still requires a real terminal, so `get` remains interactive even with `--print`.

If no exact match is found, sk2 falls back to a case-insensitive substring search. A single match is used automatically; multiple matches are shown as a numbered list to pick from.

### Edit a credential

```bash
sk2 edit github
```

Prompts for a new username and password. Press Enter at either prompt to keep the current value. Nothing is echoed while you type the password, so an empty entry is how you keep the existing one.

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

### Verify vault integrity

```bash
sk2 verify
```

Attempts to decrypt every credential with the current master password and prints a per-service ✓/✗. Run it after an unexpected crash, a filesystem event, or before an export to confirm the vault is intact. The exit code is non-zero if any credential fails, so it can gate scripts.

If a credential fails: restore it from a backup with `sk2 import` (only the services present in the backup are overwritten — no need to wipe the vault first), or delete it with `sk2 delete <service>` and reset the password on the affected site if no backup exists.

### Change master password

```bash
sk2 change-password
```

Re-encrypts all stored credentials under the new password. The vault remains intact if anything fails mid-way.

### Custom vault path

By default, sk2 stores the vault at `~/.sk2/vault.db` (`C:\Users\<USERNAME>\.sk2\vault.db` on Windows). To use a different location, set the `SK2_VAULT` environment variable or pass the `--vault` flag (the flag takes precedence).

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

Use this for separate work and personal vaults, for scripting, or for a non-standard home directory. Parent directories are created automatically.

## Shell Completion

sk2 can complete subcommands, flags, and **stored service names** on Tab. `sk2 completions <shell>` prints the script; where you put it depends on the shell.

```bash
# bash — regenerates on every shell start, so upgrades are picked up
echo 'command -v sk2 >/dev/null && source <(sk2 completions bash)' >> ~/.bashrc

# fish — same idea; add this line to ~/.config/fish/config.fish
type -q sk2 && sk2 completions fish | source
```

Those two re-run sk2 each time a shell opens, so the completion always matches the installed binary. The `command -v` / `type -q` guard is not decoration: without it, uninstalling sk2 or reordering `PATH` so `sk2` is not yet visible when the file runs makes **every new shell** print an error at startup. Put the bash line after whatever sets your `PATH`.

If you would rather install a file, these work too — but the file is a **snapshot**, so re-run the command after every sk2 upgrade:

```bash
# bash (needs the bash-completion package)
# (not ~/.bash_completion.d/ — bash-completion reads no such directory)
mkdir -p ~/.local/share/bash-completion/completions
sk2 completions bash > ~/.local/share/bash-completion/completions/sk2

# fish
mkdir -p ~/.config/fish/completions
sk2 completions fish > ~/.config/fish/completions/sk2.fish

# zsh — a directory on your $fpath, with the leading underscore in the filename.
# zsh has no regenerating form: compinit has to autoload the script, so a file it is.
mkdir -p ~/.zsh/completions && sk2 completions zsh > ~/.zsh/completions/_sk2
# then in ~/.zshrc, BEFORE compinit:
#   fpath=(~/.zsh/completions $fpath)

# PowerShell — see the verification note below before relying on this one
sk2 completions powershell > ~\sk2-completion.ps1
# then add this line to $PROFILE, once:
#   . ~\sk2-completion.ps1
```

**Why the distinction matters.** A file copy keeps working after you upgrade sk2, but it keeps working *as it was*: a subcommand added in a later release will not complete, and one that was removed will still be offered. Nothing warns you, because a completion script is forbidden from printing anything. The regenerating forms above have no such gap.

> **The PowerShell script has never been run.** The bash, zsh and fish scripts have each been driven through their own shell's completion machinery and behave as described here. The PowerShell script is written to the same specification, but no machine available to the maintainer runs PowerShell, so nothing has confirmed it works — it may complete correctly, or it may fail to load. Treat it as provisional until a release says otherwise. If you try it, a report either way is genuinely useful. The other three shells are unaffected.

Start a new shell afterwards (or `. $PROFILE` on PowerShell). Service names are completed for `get`, `delete`, `edit`, and `rename`'s *first* argument. They are deliberately **not** completed for `sk2 add`, `rename`'s second argument, or `sk2 list` — the first two are names you are coining rather than choosing, and `list` takes a substring filter, so offering exact names would imply the filter has to match one.

If the vault lives somewhere non-standard, completion honours `SK2_VAULT`, so exporting it in your shell profile is enough.

### The trade you are accepting

Completion calls a hidden `sk2 --list-services`, which reads only the service-name column — the one field sk2 stores in plaintext by design, so lookups work without decrypting anything. It prints no usernames, passwords, notes, or URLs, exits silently when there is no vault, and never *creates* anything: pressing Tab on a machine with no vault leaves the disk untouched.

**But it does not ask for your master password, and it cannot — nothing can prompt during a Tab press.** That is a deliberate exception to sk2's usual rule, and it is worth understanding before you install it:

- `sk2 list` prompts for your master password before showing service names. Tab completion shows the same names without one. So anyone at your unlocked terminal can enumerate your accounts by pressing Tab, and your service list appears on screen during a screen share, a recording, or over someone's shoulder.
- Service names are metadata worth protecting: they reveal which bank, employer, or exchange you hold accounts with, which is exactly what a targeted phishing attempt needs. Your credentials remain encrypted and are never exposed by completion.
- This grants no *new* access. Anyone who can run `sk2 --list-services` can already read `~/.sk2/vault.db` directly — it is your own file. What changes is how easily those names are surfaced, and to whom they are visible.

If that trade does not suit your situation — a shared machine, a workstation you screen-share from, an environment where the account list itself is sensitive — do not install the completion script. To remove the capability from the binary entirely, build with `--no-default-features --features export,import` (see [Compile-time features](#compile-time-features)). The resulting binary has no `completions` subcommand and no `--list-services` flag, and the scripts are not compiled in at all. Service names are then reachable only through `sk2 list`, behind the master password.

## Backup & Restore

sk2 can export all your credentials into an encrypted backup file and restore from it later. Two formats are supported:

- **SK2B** (default) — native sk2 backup using Argon2id + XChaCha20-Poly1305. Self-contained, needs no external tools, and is byte-compatible with the iOS sk2 mobile app.
- **GPG** (legacy) — GPG-encrypted CSV. Requires [GPG](https://gnupg.org/) in your `PATH`. Uses a weaker KDF than SK2B; kept for compatibility with older exports.

Plaintext is never written to disk in either format — the output file is opened with `O_EXCL | O_CREAT` at mode `0600`, and the decrypted credentials live only in zeroed memory.

For operational hardening — RAM-backed decryption, secure deletion, removable media, and backup verification — see [docs/backup-security.md](docs/backup-security.md).

### Exporting

```bash
sk2 export
```

This creates `sk2-export.sk2backup` in your current directory. sk2 first states what the export will contain and asks you to type `yes` to continue, then prompts twice for a backup passphrase. Nothing is written to disk until both steps are complete. Use a passphrase that is **different from your vault master password** — if someone obtains both the vault file and the backup file, one password shouldn't unlock both.

To choose a different output path:

```bash
sk2 export -o /mnt/usb/backup.sk2backup
```

If the output file already exists, the command fails rather than clobbering it. Pass `--overwrite` to replace an existing file (the old file is unlinked and recreated with `O_EXCL`, so a planted symlink cannot survive the race):

```bash
sk2 export -o backup.sk2backup --overwrite
```

Use `--format` to pick a format explicitly, or let sk2 infer it from the output extension:

```bash
sk2 export                                   # SK2B, default filename
sk2 export --format sk2b                     # SK2B, default filename
sk2 export --format gpg                      # legacy GPG, default is sk2-export.csv.gpg
sk2 export -o backup.sk2backup               # inferred: SK2B
sk2 export -o backup.csv.gpg                 # inferred: GPG
```

If `--output` has an unrecognized extension and `--format` isn't set, sk2 refuses to guess.

**Exports are all-or-nothing in both formats.** If any credential fails to decrypt, the export aborts and no file is written — you are told which entry failed and pointed at `sk2 verify`. A backup exists to be trusted later, and one that silently omits entries is worse than no backup at all, because you stop looking for the missing data. Nothing is lost by failing: the unreadable credential was already unreadable, and the fix is to repair it (`sk2 import` from an older backup) or drop it (`sk2 delete`) and reset that password upstream. A credential *deleted* while the export is running is a different case and is simply reported and omitted — there is no data to lose.

### Importing

```bash
sk2 import sk2-export.sk2backup        # SK2B (native)
sk2 import sk2-export.csv.gpg          # legacy GPG CSV
```

The format is autodetected by reading the first four bytes of the file — files starting with the `SK2B` magic go through the native importer; anything else is treated as a GPG-encrypted CSV and handed to `gpg --decrypt` (requires [GPG](https://gnupg.org/) in your `PATH`).

For SK2B, sk2 prompts directly for the backup passphrase (`rpassword`, never echoed). For GPG, decryption happens in `gpg` and its own pinentry handles the prompt. In both cases you must type `yes` to confirm before any credentials are written.

If a service in the backup already exists in your vault, it will be silently overwritten. Services not mentioned in the backup are left untouched.

Import also repairs corrupt credentials found by `sk2 verify`, with no need to wipe the vault first. Mind the granularity: **every service present in the backup is overwritten**, not just the corrupt ones, so any credential you have changed since taking the backup reverts to its backed-up value. Only services absent from the backup are left as they are.

**Both formats accept both schemas.** The 5-column `name,username,password,notes,url` is what export always writes; older 3-column exports (`name,username,password`) are also accepted by both importers, with notes and URL left empty. 3-column support exists only for reading backups made by older versions of sk2.

**Transactional vs. best-effort:**

- **SK2B imports are transactional.** All rows are inserted inside a single SQLite transaction; if any row fails to parse or insert, the transaction rolls back and your vault is left exactly as it was. Partial imports never land.
- **GPG imports are best-effort within a valid file.** Rows with the wrong number of fields or an empty service name are reported and skipped, and the rest are imported. This preserves the behavior of older sk2 exports, which may contain stray lines from hand-edited CSVs.

  A *malformed quote* is the exception: because notes may legitimately contain newlines, a stray or unterminated quote misaligns every record after it, so it cannot be attributed to a single row. The whole import aborts with an error and nothing is written.

Either way, a rejected file never leaves the vault half-populated: GPG imports validate the entire file before writing anything, and SK2B imports run inside a transaction that rolls back on the first bad row.

**Timestamps reset on import.** Imported credentials receive a last-updated timestamp of the moment of import — neither backup format carries age information, so `sk2 list --stale` will measure staleness from the import date, not from when the passwords were originally set. If you are importing old credentials and care about rotation tracking, update the passwords after importing.

### Decrypting a backup outside sk2

**SK2B** files can only be restored with sk2 itself (or the iOS sk2 mobile app). There is no standalone decryptor for `.sk2backup` — the format is sk2-specific. If you need a human-readable export, use `--format gpg` instead.

**GPG** files can be decrypted with GPG directly, no sk2 required:

```bash
gpg -d sk2-export.csv.gpg > credentials.csv
```

The CSV has five columns: `name`, `username`, `password`, `notes`, `url`. Unset notes and URLs appear as empty fields. Once decrypted, secure handling of the plaintext CSV is your responsibility — see [docs/backup-security.md](docs/backup-security.md).

### Round-trip example

```bash
sk2 export -o backup.sk2backup       # export from old vault
rm ~/.sk2/vault.db                    # start fresh (or move to a new machine)
sk2 init                              # set up a new vault
sk2 import backup.sk2backup          # restore all credentials
```

## Security Model

For the threat model — what sk2 is and is not designed to protect against — plus known limitations and how to report a vulnerability, see **[SECURITY.md](SECURITY.md)**. Release-by-release changes are in **[CHANGELOG.md](CHANGELOG.md)**.

### Encryption

- Your master password is run through **Argon2id** (4 iterations, 128 MiB) to derive a 256-bit encryption key.
- Each credential (username, password, and any notes/URL) is encrypted as one blob with **XChaCha20-Poly1305** using a unique random nonce.
- The service name is bound as **authenticated associated data (AAD)**, preventing ciphertext from being swapped between database rows.
- Everything is stored in a local **SQLite** database (`~/.sk2/vault.db` by default; see [Custom vault path](#custom-vault-path)).
- **Key-derivation parameters are recorded per vault.** Each vault is always unlocked using its own recorded Argon2id values, so a future release can raise the cost without locking existing vaults out; run `sk2 change-password` to re-key an existing vault under the newer, stronger parameters. Backups are separate: the `.sk2backup` format fixes its parameters as part of the container, so backups stay readable by any version of sk2 and by the iOS app.

### Runtime protections

- **Memory** — The master password, the derived key, and decrypted passwords and notes are held in `Zeroizing` wrappers and wiped when they go out of scope, including on error paths and on panics, which unwind. Coverage includes the credential struct and the JSON buffers inside encryption and decryption. It is still best-effort, not a guarantee: a wrapper wipes only the allocation it holds when it drops, so it cannot reach a copy left behind by a buffer that grew and moved, or scratch space inside a third-party parser. A memory dump or swap file could still contain plaintext. See [SECURITY.md](SECURITY.md).
- **Clipboard** — Copied passwords are automatically cleared from the clipboard after 10 seconds. `get` never prints a password unless you explicitly pass `--print`; if the clipboard is unavailable (headless machine, SSH without forwarding), `get` fails with a message naming that flag rather than printing on its own initiative. `generate` — which prints by design — treats a clipboard failure as a warning, not an error. Note that `--print` output has no equivalent of the 10-second clear: it persists in terminal scrollback and session logs.
- **File permissions** — On Linux/macOS, sk2 applies a process-wide `umask` of `0077` before touching the filesystem, so everything it creates is owner-only from the moment it exists. `~/.sk2/` is created directly at `0700`, `vault.db` inherits `0600`, and backup files are opened with an explicit `0600` mode. Permissions are established at creation time rather than tightened afterward, which removes the window in which a newly created file would be briefly readable by others. On Windows, files inherit default ACLs — there is no equivalent hardening.
- **Password strength feedback** — When you manually enter a password during `add`, `edit`, or `change-password`, or choose a backup passphrase during `export`, sk2 estimates the entropy in bits and displays a strength label (Weak / Fair / Strong / Very strong). This is informational only — no password is rejected. Entropy is estimated conservatively by detecting which character classes are present (lowercase, uppercase, digits, symbols) rather than assuming the full character set.
- **Vault integrity check** — `sk2 verify` decrypts every credential with the current master password and reports which pass and which fail, exiting non-zero if any fails. See [Verify vault integrity](#verify-vault-integrity).

### Backup and import security

- **Decryption stays in trusted code paths.** SK2B is decrypted in-process with XChaCha20-Poly1305 after deriving the backup key via Argon2id; authentication failure aborts the import. GPG backups are handed to `gpg --decrypt`, and sk2 never parses the encrypted bytes itself.
- **Plaintext is held in zeroed memory.** The decrypted CSV (and, for SK2B, the entire decrypted blob) is wrapped in `Zeroizing` and cleared when the import completes or fails. The best-effort caveat in the Memory bullet above applies here too.
- **Each credential is re-encrypted individually.** Imported credentials are encrypted with fresh random nonces and AAD-bound to their service name, exactly like `sk2 add`. They are not stored as-is from the backup.
- **Master password required.** The vault must be unlocked before import begins, same as every other command.

## Testing

The suite has two layers. Unit tests sit alongside each module, covering cryptography, the database, the backup container, CSV parsing, and the CLI helpers. On Linux and macOS, end-to-end tests drive the real binary through a pseudo-terminal — the only way to reach the interactive flows (init, add, edit, rename, change-password, export/import round-trip), since piped stdin cannot answer a password prompt. Nothing external is required; the end-to-end tests create and clean up their own scratch vaults.

```bash
cargo test                         # all tests (default features)
cargo test --no-default-features   # without export/import/completion
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

## License

MIT — see [LICENSE](LICENSE).
