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
- [ ] CI green on the commit being tagged — all three platforms, MSRV, and audit jobs. **Check that
      steps actually executed**, not just the run-level colour: a cancelled job reports a failure
      indistinguishable from a real one, and an infrastructure outage can produce either. `gh run
      view <id> --json jobs --jq '.jobs[] | "\(.conclusion) \([.steps[]|select(.conclusion!=null)]
      |length)/\(.steps|length) \(.name)"'` shows both at once.
- [ ] Locally: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings`
- [ ] Locally: `cargo test` (the PTY suite needs a real machine; CI's Linux runner covers it too)
- [ ] Locally: `cargo audit --deny warnings`
- [ ] If anything under `completions/` changed: `completions/verify/run.sh`. It drives each script
      through its own shell, because whether bash/zsh/fish interpret them correctly is not something
      `cargo test` can observe. A shell that is not installed is reported SKIPPED and fails the run
      — decide deliberately whether to ship a script no one has executed, and if so, say so in the
      README as `completions/sk2.ps1` already does.

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

## Verify, then sign

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

Then sign the checksum file. The trusted comment (`-t`) is covered by the signature and pins which
release these sums belong to:

```bash
rsign sign SHA256SUMS -s ~/.minisign/sk2-release.key -x SHA256SUMS.minisig \
    -t "sk2 vX.Y.Z"
```

Upload `SHA256SUMS.minisig` to the draft release (web UI, or
`gh release upload vX.Y.Z SHA256SUMS.minisig`).

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
