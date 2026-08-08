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
- [ ] Version bumped in `Cargo.toml`, `Cargo.lock` regenerated (`cargo build`), both committed.
      The workflow refuses a tag that disagrees with `Cargo.toml`.
- [ ] `CHANGELOG.md` has a section for this version.
- [ ] CI green on the commit being tagged — all three platforms, MSRV, and audit jobs.
- [ ] Locally: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings`
- [ ] Locally: `cargo test` (the PTY suite needs a real machine; CI's Linux runner covers it too)
- [ ] Locally: `cargo audit --deny warnings`

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
