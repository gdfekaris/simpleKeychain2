# Releasing sk2

The release pipeline has two halves. `release.yml` does the mechanical part: pushing a version tag
builds all four targets, attests provenance, and assembles a **draft** release with a `SHA256SUMS`
file. The maintainer does the part that must not live in CI: signing `SHA256SUMS` with the minisign
key that never leaves the maintainer's machine, then publishing. Keeping the signature out of CI is
what makes the two verification mechanisms independent — forging a release would require
compromising both GitHub Actions *and* the local key.

## Preconditions

All of these before tagging, on `main`:

- [ ] `git fetch origin` first, then confirm the working tree is clean and `main` matches
      `origin/main`. (Fetch before trusting `origin/*` — see project-assessment.md §7 for the time
      that lesson was learned.)
- [ ] Version bumped in `Cargo.toml`, `Cargo.lock` regenerated with **`cargo build --release
      --offline`**, both committed. Then check the diff: it must touch **exactly one line**, this
      crate's own `version`. A plain `cargo build` is allowed to update every semver-compatible
      dependency at once, which would bundle an unreviewed dependency change into a commit whose
      message says "version bump" and whose changelog says nothing about it. `--offline` cannot
      reach the registry, so it can only rewrite the version. If you *want* dependency updates, do
      them in their own commit, before this one, where they can be seen and audited.
      The workflow refuses a tag that disagrees with `Cargo.toml`.
- [ ] `CHANGELOG.md` has a section for this version, with a real date rather than "Unreleased".
- [ ] `README.md` names this version in **both** places: the opening line, and the `git clone
      --branch vX.Y.Z` in *Option 2 — build from source*. `grep -n 'v\?[0-9]\+\.[0-9]\+\.[0-9]\+'
      README.md` catches both. These are the version strings in the repo that nothing enforces — the
      workflow checks the tag against `Cargo.toml` and cannot see prose. A stale marker is how the
      README came to describe 1.1.0 while `main` was on 1.3.0; a stale clone command is worse,
      because it silently builds the *previous* release for anyone following the instructions.
      The grep also matches "up to and including v1.3.0 ship none", in the source-tarball note here
      and in `SECURITY.md`. **Leave that one alone** — it is a statement about which releases lack a
      source tarball, and it stays true forever. Bumping it would make it a lie.
- [ ] CI green on the commit being tagged — all three platforms, MSRV, and audit jobs. **Check that
      steps actually executed**, not just the run-level colour: a cancelled job reports a failure
      indistinguishable from a real one, and an infrastructure outage can produce either. `gh run
      view <id> --json jobs --jq '.jobs[] | "\(.conclusion) \([.steps[]|select(.conclusion!=null)]
      |length)/\(.steps|length) \(.name)"'` shows both at once.
- [ ] Locally: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings`
- [ ] Locally: `cargo test` (the PTY suite needs a real machine; CI's Linux runner covers it too)
- [ ] Locally, with the **previous release binary** on hand:
      `SK2_OLD_BINARY=<path to previous release> cargo test --test cli vault_from_an_older_release`

      This is the only check that a vault created by the last release still opens under this one. It
      drives the real old binary through a PTY to create a vault and store a credential, then makes
      the new build decrypt it *and* re-key it with `change-password` — exercising the per-vault
      Argon2 parameter path (F2) end to end rather than at the storage layer only.

      **It fails open.** With `SK2_OLD_BINARY` unset the test prints a `SKIPPED` line and reports
      `ok`, indistinguishable from a pass in `cargo test`'s summary. Confirm it ran: a real run takes
      seconds (Argon2) and prints no `SKIPPED` line; a skip takes 0.00s. 1.3.0 shipped without this
      having been run for exactly that reason — it was counted as green.

      Keep the previous release binary somewhere stable. On this machine `~/.local/bin/sk2` is the
      1.2.0 build; if it is ever upgraded in place, copy it aside first or this check loses its
      fixture and silently reverts to skipping.
- [ ] Locally: `cargo audit --deny warnings`
- [ ] If anything under `completions/` changed: `completions/verify/run.sh`. It drives each script
      through its own shell, because whether bash/zsh/fish interpret them correctly is not something
      `cargo test` can observe. A shell that is not installed is reported SKIPPED and fails the run
      — decide deliberately whether to ship a script no one has executed, and if so, say so in the
      README as `completions/sk2.ps1` already does.
- [ ] **Before 1.4.0, once:** confirm `docs/` actually lands in the archive. `release.yml`'s Package
      step gained `cp -r docs "$dir/"` in 325f75e, and nothing has exercised it — packaging only runs
      on a tag or a dispatch, so a released archive is the first place the mistake would show. Run
      the dry run (Actions tab → Release → *Run workflow*; `workflow_dispatch` builds the full matrix
      and packages, but skips attestation and the draft release, so nothing is published), download
      one `sk2-main-<target>` artifact, and check `docs/backup-security.md` is inside it.

      Not a cosmetic check: `README.md` links to that file with a relative path. On GitHub the link
      resolves against the repository, so a browser reader cannot see the breakage — only someone who
      downloaded the archive can, which is the audience least likely to report it. Once a dry run has
      confirmed this, delete this item; it is a one-time check of a step, not a per-release one.

## Tag and build

Examples below use `vX.Y.Z`. Substitute the version you are releasing — deliberately not a real
version number, so these commands cannot go stale and be copied verbatim into the wrong release.

```bash
git tag -a vX.Y.Z -m "sk2 X.Y.Z"
git push origin vX.Y.Z
```

Wait for the **Release** workflow to finish. It creates a *draft* release containing the four
archives and `SHA256SUMS`. If any target fails to build, no draft appears — fix, delete the tag
locally and remotely (`git tag -d vX.Y.Z && git push origin :vX.Y.Z`), and start over. Never reuse
a tag name that shipped; if a published release is broken, ship the next patch version instead.

## Verify the draft

Sign nothing you have not checked. From the draft release page, download `SHA256SUMS` and at least
one archive, then:

```bash
# The checksums match the artifact actually served
sha256sum -c SHA256SUMS --ignore-missing

# The artifact was built by this repo's release workflow at the tagged commit
# (needs the gh CLI; can be run on any machine)
gh attestation verify sk2-X.Y.Z-x86_64-unknown-linux-musl.tar.gz \
    --repo gdfekaris/simpleKeychain2
```

**`gh` prints its summary only to a terminal.** Redirected or piped, a *successful* verification
produces no output at all and exits 0 — which reads exactly like a command that did nothing. Trust
the exit code, or pass `--format json` for a result you can actually see.

That exit code is worth something; checked 2026-08-08 against the published v1.2.0 artifact rather
than assumed. The JSON records the signer as
`https://github.com/gdfekaris/simpleKeychain2/.github/workflows/release.yml@refs/tags/v1.2.0` — the
right workflow at the right tag — while the same archive checked against a different repository, and
an unattested file checked against this one, both exit 1 with an HTTP 404. So a pass is not vacuous.

If `gh` is missing, it needs no root: it ships as a static tarball, and `~/.local/bin` is usually
already on `PATH`. Verifying by hand instead — fetching the Sigstore bundle from
`api.github.com/repos/OWNER/REPO/attestations/sha256:<digest>` and checking it with `cosign` or
`sigstore-python` — is possible but a poor trade. The work is not the download, it is pinning the
certificate identity to the workflow above *and* the issuer to
`https://token.actions.githubusercontent.com`. Omit either and you have confirmed only that some
valid Sigstore signature exists, which anyone can produce — a check that looks passed and pins
nothing, right before you vouch for those bytes with a key that never touches CI.

## Add the source tarball

Someone who builds from source gets no verification from either mechanism above — the binaries are
signed and attested, a `git clone` is neither. Tag signatures do not fill the gap: commits and tags
here are GPG-signed, but that key is published nowhere, so it proves nothing to a user. A source
tarball with its hash in the signed `SHA256SUMS` closes that, reusing the key users already have.

Generate it **locally**, not in CI, and do it now — before signing, so its hash is covered:

```bash
git archive --format=tar.gz --prefix=sk2-X.Y.Z/ vX.Y.Z > sk2-X.Y.Z-src.tar.gz
sha256sum sk2-X.Y.Z-src.tar.gz >> SHA256SUMS
```

`git archive` reads the tag out of the object database, so the working tree is irrelevant — a dirty
checkout, a stale build directory, and anything in `.gitignore` cannot leak in. Run it anywhere the
tag exists.

Local generation is the point, not an accident of convenience. The workflow never touches this file,
so the "compromise CI *and* the maintainer's key" property covers source as well as binaries. Do not
move this into `release.yml` to save a step: that would put the artifact and its hash on the same
side of the trust boundary, and the signature would stop meaning anything independent.

## Sign

Sign the checksum file — now including the source tarball's line. The trusted comment (`-t`) is
covered by the signature and pins which release these sums belong to:

```bash
rsign sign SHA256SUMS -s ~/.minisign/sk2-release.key -x SHA256SUMS.minisig \
    -t "sk2 vX.Y.Z"
```

Upload the source tarball, the amended `SHA256SUMS`, and the signature. `--clobber` is required:
`SHA256SUMS` already exists on the draft, and the copy CI generated does not have the source line.

```bash
gh release upload vX.Y.Z sk2-X.Y.Z-src.tar.gz SHA256SUMS SHA256SUMS.minisig --clobber
```

Confirm the uploaded sums are the amended ones — a signature over a file the release does not
actually serve verifies fine locally and fails for every user:

```bash
gh release download vX.Y.Z -p SHA256SUMS -O - | grep src
```

## Publish

Publish the draft. Then check the result the way a user would, following the *Verifying downloads*
section of `SECURITY.md` verbatim against the now-public URLs — that section is a promise, and this
is the moment it is tested.

## The signing key

- Secret key: `~/.minisign/sk2-release.key`, password-encrypted, exists on the maintainer's machine
  plus one offline backup. It is used for every release; it is **never** uploaded anywhere, never
  put in a GitHub secret, never used in CI.
- Public key: `RWS11s9lPe0uHbOvhlPE8TLPZGoW14AjTY+K1WK+RvTalQhyd+coaEwj`, published in
  `SECURITY.md` and on the maintainer's GitHub profile. Two places, so tampering with one is
  visible in the other.
- If the secret key is lost or suspected compromised: generate a new pair, update the public key in
  both places, and say so prominently in the next release's notes. Users who pinned the old key
  must be able to see that the change was announced, not silent.
