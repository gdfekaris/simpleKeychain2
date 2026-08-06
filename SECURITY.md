# Security Policy

sk2 is a local-only password manager maintained by one person in their spare time. This document
describes what it does and does not protect against, how to report a problem, and what you can
realistically expect in response.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability**
(<https://github.com/gdfekaris/simpleKeychain2/security/advisories/new>)

That channel is private between you and the maintainer until an advisory is published.

Useful things to include: the version or commit, your operating system, what you expected, what
happened instead, and the smallest set of steps that reproduces it. If a proof of concept touches a
real vault, please reproduce it against a scratch vault instead — `sk2 --vault /tmp/scratch.db …`
keeps your own credentials out of it.

### What to expect

This is a single-maintainer project with no funding and no on-call rotation. Being honest about that
is more useful than promising turnaround times that will not be met:

- **Acknowledgement:** within about 7 days.
- **Assessment:** within about 30 days, including a decision on whether it will be fixed and roughly
  when.
- **Disclosure:** coordinated with you. If a fix will take a while, we can agree a date. If you have
  a preferred embargo period or plan to publish, say so — you will not be asked to wait indefinitely.

There is no bug bounty.

## Supported versions

| Version | Supported |
|---|---|
| 1.2.x | Yes |
| 1.1.x | No — never released; upgrade to 1.2.x |
| 1.0.x | No — predates the file-permission hardening and a data-loss fix in GPG import |

Only the latest release receives fixes. There is no long-term-support line.

## Threat model

sk2 has no server, no sync, and makes no network connections. Everything lives in one SQLite file,
by default `~/.sk2/vault.db`.

### What sk2 is designed to protect against

- **Offline access to your vault file.** Someone who copies `vault.db` — from a backup, a stolen
  disk, a shared filesystem — cannot read your credentials without your master password. Usernames,
  passwords, notes, and URLs are encrypted with XChaCha20-Poly1305 under a key derived from your
  master password using Argon2id (128 MiB, 4 passes). The per-credential ciphertext is bound to its
  service name, so entries cannot be transplanted between records.
- **Offline access to a backup file.** `.sk2backup` files are independently encrypted under a
  passphrase you choose at export time.
- **Other local users on a Unix machine.** The vault directory is created `0700` and files `0600`,
  established at creation time so there is no window in which a new file is world-readable.
- **Undetected tampering.** Both formats are authenticated; modified ciphertext fails to decrypt
  rather than yielding garbage. `sk2 verify` checks every entry and exits non-zero if any fails.

### What sk2 does not protect against

- **A compromised machine.** Malware running as your user can read your keystrokes, your clipboard,
  and this process's memory. No password manager that decrypts on your behalf can defend against
  this, and sk2 does not try.
- **Anyone with root or Administrator access** on the machine holding the vault.
- **A weak master password.** Argon2id makes guessing expensive, not impossible. sk2 shows a
  strength estimate when you set one, but never rejects your choice.
- **A weak backup passphrase.** A `.sk2backup` file is only as strong as the passphrase you chose for
  it, and it is designed to leave your machine. Treat it as at least as sensitive as the vault.
- **Someone reading over your shoulder,** or a terminal with scrollback. `sk2 generate` prints a
  password by design and warns that it does.
- **Loss of your master password.** There is no recovery mechanism, no backdoor, and no reset. This
  is intentional.

## Known limitations

These are deliberate trade-offs or accepted gaps, documented so you can judge them yourself.

- **Service names are stored in plaintext.** Only the credential contents are encrypted. Anyone with
  read access to `vault.db` can see *which* services you have accounts with, though not the
  credentials. This is a queryability trade-off.
- **Windows has no equivalent file-permission hardening.** The `umask` and `0600` modes described
  above are Unix-only. On Windows, the vault and backup files inherit default ACLs.
- **In-memory secret handling is best-effort.** Secrets are held in wrappers that wipe on drop,
  including on error paths and panics. However, some intermediate buffers — notably the JSON
  serialization used inside encryption and decryption — are ordinary allocations that are not wiped.
  A memory dump, a swap file, or a hibernation image could therefore still contain plaintext.
- **Clipboard contents are cleared unconditionally after 10 seconds,** not selectively. Whatever is
  on the clipboard at that moment is wiped, including something you copied yourself in the interim.
  Clipboard managers may also retain history that sk2 cannot reach.
- **The `--vault` flag and `SK2_VAULT` variable accept any path.** sk2 does not check whether the
  path is a symlink before SQLite opens it.
- **GPG backups depend on your GPG installation** for their encryption and passphrase handling. The
  `.sk2backup` format is self-contained and uses a stronger KDF; prefer it for new backups.

## Verifying downloads

Release binaries (v1.2.0 and later) ship with two independent verification mechanisms. They prove
different things, and they fail independently: the checksum signature is made on the maintainer's
machine with a key that is never given to CI, while the attestation is made by GitHub's
infrastructure with no long-lived key at all. Check both if you can; either alone is far better
than neither.

Anything predating v1.2.0, or any prebuilt "sk2" binary found elsewhere, is unsigned and should be
treated as untrusted — build from source instead.

### 1. Signed checksums (minisign)

Every release includes `SHA256SUMS` and a detached signature `SHA256SUMS.minisig`, made with the
maintainer's [minisign](https://jedisct1.github.io/minisign/) key. This proves the checksums were
approved by the holder of the key — not by whoever happened to control the GitHub repository.

The public key, which should be identical everywhere it appears (here, `RELEASING.md`, and the
maintainer's GitHub profile — if the copies disagree, trust none of them and open an issue):

```
RWS11s9lPe0uHbOvhlPE8TLPZGoW14AjTY+K1WK+RvTalQhyd+coaEwj
```

Verify the signature, then the file you downloaded:

```bash
minisign -Vm SHA256SUMS -P RWS11s9lPe0uHbOvhlPE8TLPZGoW14AjTY+K1WK+RvTalQhyd+coaEwj
# or, with the Rust implementation:  rsign verify SHA256SUMS -P <same key>

sha256sum -c SHA256SUMS --ignore-missing
```

### 2. Build provenance attestation

Each archive is attested with [GitHub build provenance](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations),
which proves it was built by this repository's release workflow, from this repository's code, at
the tagged commit — not built elsewhere and uploaded. Requires the `gh` CLI:

```bash
gh attestation verify sk2-1.2.0-x86_64-unknown-linux-musl.tar.gz \
    --repo gdfekaris/simpleKeychain2
```

### What verification does not prove

Both mechanisms establish *where the bytes came from*, not that the code is free of defects. And
platform code-signing is a separate, unrelated system: sk2 binaries are **not** Apple-notarized or
Windows-Authenticode-signed (both are paid programs), so macOS Gatekeeper and Windows SmartScreen
will warn on first run even for a fully verified download. On macOS:
`xattr -d com.apple.quarantine sk2` after verifying.

## Cryptography

For reviewers, the primitives in use:

| Purpose | Algorithm |
|---|---|
| Key derivation | Argon2id — 128 MiB, 4 passes, parallelism 4, 32-byte output |
| Credential encryption | XChaCha20-Poly1305, random 24-byte nonce per write, service name as AAD |
| Backup encryption | XChaCha20-Poly1305 over the whole CSV payload, key derived from the backup passphrase with a fresh 16-byte salt |
| Randomness (nonces) | Operating-system CSPRNG directly, via `getrandom` |
| Randomness (salts, generated passwords) | `rand`'s thread-local ChaCha-based CSPRNG, seeded from the operating system and periodically reseeded |

Each vault stores the Argon2 parameters it was created with and is unlocked using those, so the cost
can be raised in future releases without locking existing vaults out. The `.sk2backup` container
fixes its parameters as part of the format, so backups remain readable across versions and by the
iOS app.

No cryptographic primitive is implemented in this project; all come from the `argon2`,
`chacha20poly1305`, and `getrandom` crates of the RustCrypto ecosystem.
