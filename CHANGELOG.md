# Changelog

All notable changes to sk2 are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). sk2 is a command-line application
rather than a library, so "breaking" refers to changes in CLI behaviour, the on-disk vault format, or
backup compatibility — not to a Rust API.

## [Unreleased]

### Fixed

- **The bash completion install instructions pointed at a directory nothing reads, so Tab completed
  filenames instead of service names.** `README.md` and the header of `completions/sk2.bash` both
  gave `~/.bash_completion.d/sk2` as the first of two options. bash-completion does not source that
  directory — it loads `${XDG_DATA_HOME:-~/.local/share}/bash-completion/completions/`,
  `/etc/bash_completion.d/`, and the single *file* `~/.bash_completion`. A script left in
  `~/.bash_completion.d/` is read by nobody, leaving `sk2` on bash-completion's `_minimal` fallback,
  which offers filenames. Following the documented instructions exactly produced a shell that looked
  like completion had simply never been implemented.

  Both now give `~/.local/share/bash-completion/completions/sk2`, and say that the
  `source <(sk2 completions bash)` alternative needs no bash-completion package at all, and both
  carry a line saying that `~/.bash_completion.d/` is not read — it is a common enough belief to be
  worth naming at the point where someone might substitute it for the correct path. The fish line
  gained the `mkdir -p` it needed for a config directory that may not exist yet. **The scripts themselves were correct and are unchanged** — only where users were told
  to put them.

- **`completions/verify` now checks the install path, not just the completion function.** Every
  assertion in `bash-check.sh` ran after `source <(sk2 completions bash)`, which proves `_sk2`
  behaves and says nothing about whether following `README.md` registers it. That is how the bug
  above shipped behind 35 green assertions. A new check copies the script to the documented location
  under a scratch `HOME` and requires a fresh `bash --norc` to report `complete -F _sk2 sk2`; against
  the old path it reports `complete -F _minimal sk2` and fails. Same lesson as the
  `gh attestation verify` defect found before the 1.3.0 release, in a different place.

- **The PowerShell completion install appended to `$PROFILE` instead of replacing.** The documented
  command was `sk2 completions powershell >> $PROFILE`, so re-running it after an sk2 upgrade — the
  only way to refresh a completion script — left two copies of the script in the profile, and one
  more with every upgrade after that. It now writes `~\sk2-completion.ps1` and has `$PROFILE`
  dot-source that file once, so refreshing means rewriting one file. The PowerShell script itself
  remains unexecuted and unverified, as documented.

### Changed

- **Completion install instructions now lead with the forms that survive an sk2 upgrade.** An
  installed completion file is a snapshot: upgrading replaces the binary and never touches the file,
  so it goes on offering whichever subcommands existed when it was written — a subcommand added in a
  later release will not complete, one removed will still be offered, and nothing says so, because a
  completion script is forbidden from printing. `README.md` now leads with
  `source <(sk2 completions bash)` and `sk2 completions fish | source`, which regenerate on every
  shell start, and marks the file-based installs as needing a re-run after each upgrade. Both
  regenerating forms were run before being documented. **zsh deliberately has no such form** and says
  why: compinit must autoload the script from `fpath`, and the trailing `_sk2 "$@"` that autoloading
  requires fails when the file is sourced directly.

  This corrects a claim that appeared in three places (`CLAUDE.md`, `next-steps.md`, and the doc
  comment on `completion_script`): that embedding the scripts in the binary means they "cannot drift
  from the CLI". That holds for the script `sk2 completions <shell>` *returns*, not for a copy on a
  user's disk. Embedding did not remove the drift — it moved it somewhere harder to notice, since
  the stale artifact is no longer a versioned file sitting beside the binary.

### Documentation

- **`SECURITY.md` now says that attestation verification requires a GitHub account.** It previously
  said only "Requires the `gh` CLI", so a reader could install `gh`, follow the instructions exactly,
  and meet an unexplained login prompt — with no hint of why checking a *public* download needs an
  account. The likely response is to skip the check, which loses the mechanism for exactly the people
  most inclined to use it. Found by running the *Verifying downloads* section against the published
  1.3.0 release as an unauthenticated user would.

  The section now states which mechanism needs an account and which does not: signed checksums can be
  verified by anyone with no account and no GitHub tooling, so a reader without one still has a
  complete verification path — and it is the one whose key never touches GitHub. It also records two
  things about the output that are easy to misread: `gh` prints its summary only to a terminal, so
  piped or redirected a success is completely silent, and a genuine verification failure surfaces as
  `HTTP 404` rather than as a message about signatures.

## [1.3.0] — 2026-08-08

**Why 1.3.0 and not 2.0.0** (settled 2026-08-07, so it is not re-argued at tag time). The preamble
above counts a change in CLI behaviour as breaking, and the GPG export abort is one: an export that
previously exited 0 now exits non-zero. It is still a minor release, because the changed behaviour
appears only against an already-corrupt vault — a state that was never working, and where the old
"success" *was* the defect. No command that succeeded before fails now.

Three themes. sk2 now works on headless machines — servers, SSH sessions without display
forwarding, containers — where `get` previously could not retrieve a password at all and
`generate` exited with an error after printing. Decrypted credentials are wiped from memory more
thoroughly. And backups are now all-or-nothing, so an export can no longer quietly omit a
credential it could not read.

### Added

- **Shell completion for bash, zsh, fish and PowerShell**, including Tab-completion of stored
  service names. `sk2 completions <shell>` prints the script; the README has the one-liner for each
  shell. Names are completed for `get`, `delete`, `edit` and `rename`'s first argument, and
  deliberately not for `sk2 add`, `rename`'s second argument, or `sk2 list` — the first two are
  names you are coining rather than choosing, and `list` takes a substring filter.

  **The bash, zsh and fish scripts are verified; the PowerShell script is not.** The first three
  were each driven through their own shell's completion machinery and behave exactly as described
  above. The PowerShell script is written to the same specification but has never been executed —
  no machine available to the maintainer runs PowerShell — so it may work or may fail to load. The
  README says so at the point of installation rather than leaving all four looking equally tested.
  Verifying it is on the list for the next release.

  Completion reads only the service-name column, which sk2 stores in plaintext by design so that
  lookups work without decrypting anything. It prints no usernames or secrets, stays silent when
  there is no vault, and creates nothing — pressing Tab on a machine with no vault leaves the disk
  untouched. `SK2_VAULT` is honoured, so a non-standard vault location still completes.

  **Know the trade before installing it.** Completion cannot ask for your master password —
  nothing can prompt during a Tab press — so it shows service names without one, where `sk2 list`
  requires it. Anyone at your unlocked terminal can therefore enumerate your accounts by pressing
  Tab, and your service list appears during a screen share. No credentials are exposed and no new
  access is granted (anyone who can run it can already read your `0600` vault file), but service
  names identify the institutions you bank with and work for. It is opt-in — you get it only by
  installing the script — and **`completion` is now a Cargo feature**, so
  `--no-default-features --features export,import` produces a binary with no `completions`
  subcommand, no `--list-services` flag, and no completion scripts compiled in. The README and
  `SECURITY.md` both spell this out.

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

- **Two further README claims corrected, both of which the audit above had already fixed once and
  later work falsified again.** Worth stating plainly, because the failure mode is not carelessness
  but drift: a summary sentence is written accurately, a feature lands somewhere else in the
  codebase, and nothing forces the two to be reconciled.

  "Every command that touches the vault asks for your master password first. The one exception is
  `generate`" was true until `completions` shipped in this release — it also touches nothing and
  also does not prompt. This is the identical sentence the audit had corrected for `generate`. The
  README now names both, and separately names Tab completion as a third and deliberately different
  case, since that one *does* read the vault without a password.

  The `export` walkthrough also described its prompts in the wrong order, reading as though the
  passphrase came first and the `yes` confirmation were an afterthought. sk2 states what the export
  will contain, requires `yes`, and only then asks for the passphrase twice; the output file is
  opened after both.

- **A style pass over `README.md` and `SECURITY.md`.** No described behaviour changed — this is
  sentence construction only, concentrated in the procedural sections where a first-time user
  spends their time. Self-cancelling sentences, redundant acronym glosses, jargon left unexplained
  ("a blind TTY read"), and parentheticals that buried the actionable step were removed, and the
  three longest sentences were split. "Zeroed memory" became "memory that is wiped when the command
  finishes", which is what actually happens and matches the best-effort framing used everywhere
  else.

### Internal

- **`completions/verify/run.sh` verifies the completion scripts against real shells.** The thing
  under test is whether bash, zsh and fish interpret sk2's scripts as intended, which can only be
  observed by running those shells — so it is shell scripts rather than `cargo test`, which already
  covers the half that is sk2. 35 assertions against a scratch vault. A shell that is not installed
  is reported SKIPPED and fails the run, so an absent shell is never mistaken for a verified one.

- Test suite grew from 119 to 126, covering the memory-wiping types, the export counts, and the
  new abort-on-corrupt-row behaviour along with its deliberate exception for a credential deleted
  mid-export. The GPG export's CSV construction moved into a testable helper; previously that path
  could only be exercised by running `gpg` against a real terminal. Three of the new tests are
  end-to-end and pin shell completion's non-negotiables: that it emits a script for every shell,
  that it lists service names without prompting, and that pressing Tab on a machine with no vault
  creates nothing on disk.

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

[Unreleased]: https://github.com/gdfekaris/simpleKeychain2/compare/v1.3.0...main
[1.3.0]: https://github.com/gdfekaris/simpleKeychain2/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/gdfekaris/simpleKeychain2/releases/tag/v1.2.0
[1.1.0]: https://github.com/gdfekaris/simpleKeychain2/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/gdfekaris/simpleKeychain2/releases/tag/v1.0.0
