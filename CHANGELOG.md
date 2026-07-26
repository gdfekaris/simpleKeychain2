# Changelog

All notable changes to sk2 are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). sk2 is a command-line application
rather than a library, so "breaking" refers to changes in CLI behaviour, the on-disk vault format, or
backup compatibility — not to a Rust API.

## [1.2.0] — 2026-07-25

The headline item is a data-loss fix in the legacy GPG import path. If you keep multi-line notes and
have ever restored from a `.csv.gpg` backup, please read the first entry under *Fixed*.

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

- Test suite grew from 80 to 107, covering the multi-line-note round trip, per-vault key-derivation
  parameters, corrupt-row handling, and the first tests for `main.rs`.
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

[1.2.0]: https://github.com/gdfekaris/simpleKeychain2/releases/tag/v1.2.0
[1.1.0]: https://github.com/gdfekaris/simpleKeychain2/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/gdfekaris/simpleKeychain2/releases/tag/v1.0.0
