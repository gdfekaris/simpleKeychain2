#!/usr/bin/env bash
#
# Verify sk2's shell completion scripts against the shells they target.
#
#   completions/verify/run.sh
#
# Builds a scratch vault, puts the built binary on PATH as `sk2`, and runs one
# checker per shell. A shell that is not installed is SKIPPED loudly rather than
# passing silently -- an absent shell must never look like a verified one.
#
# Nothing here touches a real vault: every checker runs with SK2_VAULT pointed
# at the scratch fixture, which is removed on exit.
#
# PowerShell has no checker. See README.md in this directory.

set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

# The binary under test. Override to check a release artifact instead:
#   SK2_BIN=/path/to/sk2 completions/verify/run.sh
SK2_BIN="${SK2_BIN:-$repo/target/release/simpleKeychain2}"
if [[ ! -x "$SK2_BIN" ]]; then
    echo "Building $SK2_BIN ..."
    (cd "$repo" && cargo build --release --locked) || exit 1
fi

# The completion feature is optional; without it there is nothing to verify and
# saying so beats twelve confusing failures.
if ! "$SK2_BIN" completions bash >/dev/null 2>&1; then
    echo "FAIL: '$SK2_BIN completions bash' failed."
    echo "      Built without the 'completion' feature? Nothing to verify."
    exit 1
fi

# The checkers pipe completion output through these. If one is missing the
# pipeline yields nothing, and an empty result is indistinguishable from a
# correct "this must offer nothing" -- so the three most important assertions
# would pass for the wrong reason. Fail here instead.
for tool in grep sort tr sed cut; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "FAIL: required tool '$tool' not found; results would be meaningless." >&2
        exit 1
    }
done

scratch="$(mktemp -d "${TMPDIR:-/tmp}/sk2-comp-verify.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

mkdir -p "$scratch/bin"
ln -sf "$SK2_BIN" "$scratch/bin/sk2"

# A vault holding known service names. Only the plaintext `service` column is
# read by --list-services, so no master password and no encryption are involved
# -- which is why this fixture can be built without driving the real CLI.
#
# "my bank" is load-bearing: a name containing a space is the case each shell is
# most likely to mishandle on insertion.
services=(github gitlab gmail "my bank" zoom)
if command -v sqlite3 >/dev/null 2>&1; then
    {
        echo "CREATE TABLE credentials (service TEXT PRIMARY KEY, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, updated_at INTEGER);"
        for s in "${services[@]}"; do
            echo "INSERT INTO credentials VALUES ('${s//\'/\'\'}', X'00', X'00', 0);"
        done
    } | sqlite3 "$scratch/vault.db"
elif command -v python3 >/dev/null 2>&1; then
    python3 - "$scratch/vault.db" "${services[@]}" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
conn.execute("CREATE TABLE credentials (service TEXT PRIMARY KEY, nonce BLOB NOT NULL,"
             " ciphertext BLOB NOT NULL, updated_at INTEGER)")
for name in sys.argv[2:]:
    conn.execute("INSERT INTO credentials VALUES (?, X'00', X'00', 0)", (name,))
conn.commit()
PY
else
    echo "FAIL: need sqlite3 or python3 to build the fixture vault." >&2
    exit 1
fi

export SK2_COMP_SCRATCH="$scratch"

failed=0
run_or_skip() {
    local shell="$1" checker="$2"
    if command -v "$shell" >/dev/null 2>&1; then
        "$here/$checker" || failed=1
    else
        echo "$shell:"
        echo "  SKIPPED -- $shell is not installed. NOT verified on this machine."
        failed=1
    fi
}

run_or_skip bash bash-check.sh
run_or_skip fish fish-check.sh
run_or_skip zsh  zsh-check.zsh

echo
echo "powershell:"
echo "  NOT VERIFIED -- no checker exists. See completions/verify/README.md."

echo
if (( failed )); then
    echo "RESULT: not every shell was verified (see above)."
else
    echo "RESULT: bash, zsh and fish all pass. PowerShell remains unverified."
fi
exit $failed
