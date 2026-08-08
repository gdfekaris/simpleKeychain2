# Changelog

All notable changes to sk2 are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). sk2 is a command-line application
rather than a library, so "breaking" refers to changes in CLI behaviour, the on-disk vault format, or
backup compatibility — not to a Rust API.

## [Unreleased] — will be 1.3.0

Nothing here is released yet. `Cargo.toml` still reads 1.2.0 deliberately: the version bump is a
*precondition of tagging* (see `RELEASING.md`), not something to carry around between releases, so
it happens when a release is actually cut. This section is the running record of what that release
will contain. Everything below is on `main` and CI-verified.

Three themes so far. sk2 now works on headless machines — servers, SSH sessions without display
forwarding, containers — where `get` previously could not retrieve a password at all and
`generate` exited with an error after printing. Decrypted credentials are wiped from memory more
thoroughly. And backups are now all-or-nothing, so an export can no longer quietly omit a
credential it could not read.

### Added

- **`get --print`** displays the password instead of copying it, as an explicit opt-in. The bare
  value is written to stdout with nothing else, so `PASS=$(sk2 get github --print)` captures
  exactly the secret; a warning goes to stderr, and the clipboard is skipped entirely. Combined
  with `--username`, it prints the username instead. Deliberately *not* an automatic fallback:
  when the clipboard is unavailable, plain `get` still fails — with a message naming `--print` —
  rather than letting the environment silently decide whether a stored password appears on screen.
  Note the trade: printed output has no 10-second clear and stays in terminal scrollback and
  session logs.

### Fixed

- **`generate` no longer exits with an error when the clipboard is unavailable.** The password is
  printed before the clipboard is touched, so the failure was purely cosmetic — but the non-zero
  exit broke `set -e` scripts. It now warns that the password was not copied and exits 0.

### Changed

- **A GPG export now aborts if any credential fails to decrypt, instead of skipping it.** This
  matches the `.sk2backup` format, which has always failed on the first unreadable row. Previously
  the entry was reported and left out, and the export was reported as a success — the reasoning
  being that a partial backup beats none. The problem is that the omission is invisible in the
  artifact: the `.csv.gpg` carries no record of what is missing, so the warning exists only in a
  terminal you will not have when you come to restore. You are now told which entry failed and
  pointed at `sk2 verify`; no file is written, so an existing backup at that path is not replaced
  by an incomplete one. Nothing is lost by failing — the unreadable credential was already
  unreadable, and the repair path (`sk2 import` from an older backup, or `sk2 delete` and reset the
  password upstream) is unchanged.

  A credential *deleted* while the export runs is a different case and still just reported and
  omitted, since there is nothing to lose.

- **The GPG export's success line now reports the number of credentials actually written.** It
  previously reported the number found before the file was built, which — combined with the
  skipping described above — could announce more credentials than the backup contained.

### Security

- **Decrypted credentials are now wiped from memory more thoroughly.** Passwords and notes were
  previously copied into ordinary allocations at three points — the JSON buffer inside encryption,
  the JSON buffer inside decryption, and the values handed back from the database layer — and
  released to the allocator without being overwritten. All three are now wiped, as is the
  credential struct itself. Usernames and URLs are unchanged: both are displayed in plaintext by
  design, so wrapping them would protect nothing.

  This narrows the window rather than closing it, and the documentation says so. A wrapper wipes
  the allocation it holds at the moment it drops, so it cannot reach a copy left behind when a
  buffer grew and moved, nor scratch allocations inside third-party parsers. `SECURITY.md` and the
  README describe the remaining limitation. There is no change to the vault format, the backup
  format, or any command's behaviour.

### Documentation

- **A full accuracy audit of the README fixed 17 defects**, several of which were instructions that
  did not work as written. The install steps copied the binary into a directory that may not exist
  (`cp` does not create parents), pointed macOS users at a path that is not on the default `PATH`,
  omitted the C-toolchain requirement for the bundled SQLite on platforms other than Windows, did
  not build with `--locked`, and used `sha256sum`, which stock macOS does not have. Other
  corrections: `generate` was covered by a blanket "all commands require your master password"
  claim (it does not); the backup-repair section implied only damaged credentials are overwritten
  by an import, when every service present in the backup is; a PowerShell example used cmd-style
  `%USERNAME%`; and `/tmp`-is-tmpfs and `shred` advice was presented as applying to macOS. `verify`
  gained the usage section it never had.

### Internal

- Test suite grew from 119 to 123, covering the memory-wiping types, the export counts, and the
  new abort-on-corrupt-row behaviour along with its deliberate exception for a credential deleted
  mid-export. The GPG export's CSV construction moved into a testable helper; previously that path
  could only be exercised by running `gpg` against a real terminal.

## [1.2.0] — 2026-08-05

The headline item is a data-loss fix in the legacy GPG import path. If you keep multi-line notes and
have ever restored from a `.csv.gpg` backup, please read the first entry under *Fixed*.

This is also the first release with prebuilt binaries. Each archive ships with two independent
verification mechanisms — minisign-signed checksums and GitHub build provenance attestation — and
`SECURITY.md` explains how to check both.

### Fixed

- **GPG import silently discarded credentials whose notes contained a line break.** `export` writes a
  newline inside a quoted CSV field, which is valid RFC 4180, but `import` split the decrypted text
  into lines *before* parsing. A single credential with a three-line note therefore arrived as three
  unparseable fragments, all skipped — losing the username and password as well as the note — while
  the command reported success. Both importers now share one whole-text CSV parser that tracks quote
  state across newlines. The `.sk2backup` format was never affected.
- **A corrupt credential caused a panic instead of an error.** `get`, `edit`, `rename`, `export` and
  `change-password` now report which entry failed to decrypt and what to do about it, matching the
  guidance `verify` already gave. Previously the natural follow-up to a failed `verify` was a raw
  Rust panic.
- **`change-password` now genuinely leaves the vault untouched if a credential fails to decrypt.**
  This was always the documented behaviour, but it was reached by a panic rather than by the
  rollback path.
- **The strength estimate for the default character set was slightly understated** — it assumed a
  74-character alphabet where the real one is 75. Estimates were conservative, never optimistic.
- **The documented minimum Rust version was wrong.** The README said 1.85; the code has in fact
  required 1.88 since the `--vault` flag was added. `Cargo.toml` now declares `rust-version = "1.88"`,
  so cargo reports the requirement plainly instead of failing with an unexplained parse error.

### Added

- **Prebuilt, verifiable release binaries** for Linux (x86_64, fully static), macOS (Apple silicon
  and Intel), and Windows (x86_64), each archive containing the binary already named `sk2`. Every
  release publishes a `SHA256SUMS` file signed with the maintainer's minisign key — the signature is
  made on the maintainer's machine, never in CI — plus a per-archive build provenance attestation.
  Verification instructions are in `SECURITY.md`.
- **Password-strength feedback when choosing a backup passphrase** during `export`, matching what
  `add`, `edit` and `change-password` already did. That passphrase protects every credential at once
  in a file meant to leave your machine, so it is the one most worth getting right.
- **Vaults now record and re-use their own key-derivation parameters.** A future release can raise
  the Argon2 cost without locking existing vaults out; run `sk2 change-password` to re-key an
  existing vault under the newer parameters. Backups are unaffected — the `.sk2backup` container
  fixes its parameters as part of the format, so backups stay readable by any version of sk2 and by
  the iOS app.

### Changed

- **`--length` and `--charset` without `--generate` are rejected immediately.** Previously the error
  appeared only after you had entered your master password and a username.
- **A malformed quote in a GPG CSV import now aborts the import** rather than skipping a single row.
  Once fields may contain newlines, a stray quote misaligns every record that follows, so skipping
  one row was never actually safe — it silently mis-attributed the data after it. Rows with the wrong
  field count or an empty service name still produce a warning and are skipped, as before.
- **Both importers now parse and validate the entire file before writing anything**, so a rejected
  file cannot leave a half-populated vault.
- Dependencies updated: `rpassword` 5 → 7 (the 5.x API used for every password prompt was
  deprecated), `rusqlite` 0.31 → 0.39, `rand` 0.8.5 → 0.8.7.

### Security

- `rand` 0.8.5 was subject to [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097).
  **sk2 was not affected.** The advisory requires a custom logging implementation that itself calls
  the thread RNG; sk2 defines no logger and does not enable `rand`'s `log` feature. The dependency was
  updated regardless. Note that the advisory describes undefined behaviour under a specific
  reentrancy pattern — not a weakness in randomness quality. No salt or generated password produced by
  any version of sk2 was predictable.
- The README's description of in-memory secret handling was overstated and has been corrected. Secrets
  are wiped when they go out of scope, but some intermediate buffers are not; see `SECURITY.md`.

### Internal

- Test suite grew from 80 to 118, covering the multi-line-note round trip, per-vault key-derivation
  parameters, corrupt-row handling, and the first tests for `main.rs` — plus a new end-to-end suite
  that drives the real binary through a pseudo-terminal, finally exercising every interactive
  prompt (`init`, `add`, `edit`, `rename`, `change-password`, export/import) exactly as a user
  types them.
- CI now lints test code (`--all-targets`), verifies the minimum supported Rust version, and runs
  `cargo audit` weekly as well as on push.
- Development consolidated onto a single `main` branch.

## [1.1.0] — 2026-04-17

**Never tagged as a release.** The version existed in `Cargo.toml` and the code was reachable by
cloning `main`, but no release was published. Recorded here for completeness.

### Added

- **The SK2B backup format** (`.sk2backup`): Argon2id + XChaCha20-Poly1305 in a self-contained
  container, byte-compatible with the iOS sk2 app. `export` defaults to it; `import` autodetects the
  format from the file's magic bytes and still accepts legacy GPG CSV backups.
- SK2B imports are transactional — if any row fails, the whole import rolls back.

### Changed

- File permissions are now established at creation time, via a process-wide `umask` and explicit
  modes, rather than by changing permissions after the fact. This removes the window in which a
  newly created vault or backup file was briefly readable by other users.

## [1.0.0] — 2026-02-27

First tagged release, and the last version before the changes above. Tagged retroactively on
2026-07-25 so that users of this version have a stable reference point.

Core feature set: `init`, `add`, `get`, `edit`, `rename`, `delete`, `list` (with filtering and
`--stale`), `generate`, `verify`, `change-password`, and GPG-based `export` / `import`. Local-only —
no server, no sync, no network. Credentials encrypted with XChaCha20-Poly1305 under a key derived
from the master password with Argon2id.

If you are still on this version, prefer 1.2.0: 1.0.0 predates the file-permission hardening, the
SK2B backup format, and the GPG import fix described above.

[Unreleased]: https://github.com/gdfekaris/simpleKeychain2/compare/v1.2.0...main
[1.2.0]: https://github.com/gdfekaris/simpleKeychain2/releases/tag/v1.2.0
[1.1.0]: https://github.com/gdfekaris/simpleKeychain2/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/gdfekaris/simpleKeychain2/releases/tag/v1.0.0
