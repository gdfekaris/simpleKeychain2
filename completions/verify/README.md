# Verifying the completion scripts

```
completions/verify/run.sh
```

Builds a scratch vault, puts the built binary on `PATH` as `sk2`, and drives each completion script
through its own shell's real completion machinery. Run it before any release that touches
`completions/`.

Nothing here can reach a real vault: every check runs with `SK2_VAULT` pointed at a fixture in a
temporary directory, which is removed on exit.

To check a release artifact rather than a local build:

```bash
SK2_BIN=/path/to/sk2 completions/verify/run.sh
```

## Why this is shell scripts and not `cargo test`

The thing under test is not sk2 — it is whether **bash, zsh and fish** interpret sk2's scripts the
way the spec intends. That can only be observed by running those shells. `tests/cli.rs` already
covers the half that *is* sk2: that `--list-services` prints names, never prompts, and creates
nothing when there is no vault.

A shell that is not installed is reported **SKIPPED** and makes the run fail, rather than passing
quietly. An absent shell must never be mistaken for a verified one.

## What is asserted

Every rule in `shell-completion-spec.md`, for each shell:

- subcommand completion, and prefix filtering of it
- service names on the **first** positional of `get`, `delete`, `edit`, `rename`
- **nothing** for `sk2 add`, `rename`'s second argument, or `sk2 list` — the first two are names the
  user is coining, and `list` takes a substring filter
- `--vault <path>` skipped when locating the subcommand, so its value is not mistaken for it
- `completions` offering the four shell names
- a service name containing a space (`my bank`) surviving intact

That last one is the fixture's whole reason for including an awkward name, and it is the case each
shell is most likely to get wrong on insertion.

Plus, for bash only, the thing all of the above assumes:

- **that the documented install path actually registers the completion.** The script is copied to
  `~/.local/share/bash-completion/completions/sk2` under a scratch `HOME`, exactly as `README.md`
  instructs, and a fresh `bash --norc` that sources only bash-completion must then report
  `complete -F _sk2 sk2`.

### Why that last check exists

Every other assertion here runs after `source <(sk2 completions bash)` at the top of the checker.
That proves `_sk2` is correct. It cannot prove a user ends up with `_sk2` registered, because no user
was told to run that command as the primary route — and the two are separate claims.

They came apart in 1.3.0. The documented location was `~/.bash_completion.d/`, which bash-completion
**does not read** (it loads the XDG directory above, `/etc/bash_completion.d/`, and the single file
`~/.bash_completion`). A user following the instructions exactly got `complete -F _minimal sk2` —
filename completion — while 35 assertions here reported everything green. Nothing was wrong with the
script; the instructions pointed at a directory nothing sources.

This is the same failure mode as the `gh attestation verify` defect found while verifying the 1.3.0
release: **instructions have to be walked the way the audience walks them, not the way the author
already has their machine set up.** A checker that skips the install step is testing the half that
was never in doubt.

### Why each checker starts with a positive control

Three of the assertions expect a completion to offer **nothing**. A harness that is itself broken
also produces nothing, so those three would pass for the wrong reason — which is how a test ends up
guarding an empty pipeline instead of the behaviour it names. This was not hypothetical: an early
version of these checks reported `ok` for all three while `grep` was missing from `PATH`.

So each checker first runs a case that must be non-empty and aborts if it is not, and `run.sh`
checks up front that the tools the pipelines depend on actually exist.

## PowerShell is not covered

There is no PowerShell checker, and the script in `completions/sk2.ps1` **has never been executed**.
The README tells users so at the point of installation. Closing this needs either a Windows machine
or `pwsh` on Linux — and note that `pwsh` is PowerShell 7 while many Windows users run Windows
PowerShell 5.1, so a pass under `pwsh` should be recorded as "verified on PowerShell 7" rather than
as unqualified verification.

## Shell behaviours that are not sk2's to fix

Found while writing these checks; do not "correct" the scripts to change them.

- **fish matches substrings, not just prefixes.** `sk2 g` offers `change-password`, because it
  contains a `g`. A completion declared with no sk2 involvement behaves identically, so this is
  fish-wide.
- **fish sorts the candidate list itself**, so these checks assert the set of candidates, not their
  order. Asserting order would pin fish's internals rather than sk2's contract.
- **zsh rings the terminal bell when there are no matches.** Harmless, and in fact the signal that
  `sk2 add <TAB>` correctly offers nothing — but the `\a` byte has to be stripped before parsing or
  it defeats a trailing-whitespace trim.
