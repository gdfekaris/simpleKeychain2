#!/usr/bin/env bash
# Drive sk2's bash completion through bash's own machinery and assert the rules
# in shell-completion-spec.md. Invoked by run.sh, which sets SK2_COMP_SCRATCH.
set -u
SCRATCH="${SK2_COMP_SCRATCH:?run via completions/verify/run.sh}"
export PATH="$SCRATCH/bin:$PATH" SK2_VAULT="$SCRATCH/vault.db"

source <(sk2 completions bash)

pass=0; fail=0

# complete_for <expected> <words...>  -- the last word is the one being completed
complete_for() {
    local expected="$1"; shift
    COMP_WORDS=("$@")
    COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 ))
    COMPREPLY=()
    _sk2
    local got
    got="$(printf '%s\n' "${COMPREPLY[@]+"${COMPREPLY[@]}"}" \
        | grep -v '^$' | sort | tr '\n' ' ' | sed 's/ $//')"
    if [[ "$got" == "$expected" ]]; then
        printf '  ok    %-40s -> [%s]\n' "$*" "$got"; (( pass++ ))
    else
        printf '  FAIL  %-40s\n        expected [%s]\n        got      [%s]\n' \
            "$*" "$expected" "$got"
        (( fail++ ))
    fi
}

SERVICES='github gitlab gmail my\ bank zoom'

echo "bash:"

# Positive control. Three assertions below expect NOTHING, and a harness that is
# itself broken also produces nothing -- so those would pass vacuously. Prove the
# machinery can produce a result at all before trusting any empty one.
COMP_WORDS=(sk2 get ""); COMP_CWORD=2; COMPREPLY=(); _sk2
if (( ${#COMPREPLY[@]} == 0 )); then
    echo "  ABORT -- positive control returned nothing; the harness is broken,"
    echo "           so the 'must offer nothing' cases cannot be trusted."
    exit 2
fi

complete_for "add change-password completions delete edit export generate get help import init list rename verify" sk2 ""
complete_for "generate get" sk2 "g"

# Service names on the first positional of get/delete/edit/rename.
complete_for "$SERVICES" sk2 get ""
complete_for "github gitlab" sk2 get "git"
complete_for "$SERVICES" sk2 delete ""
complete_for "$SERVICES" sk2 edit ""
complete_for "$SERVICES" sk2 rename ""

# Deliberately NOT completed: names being coined, and a substring filter.
complete_for "" sk2 add ""
complete_for "" sk2 rename github ""
complete_for "" sk2 list ""

# --vault takes a value, so it must not be mistaken for the subcommand.
complete_for "$SERVICES" sk2 --vault /tmp/v.db get ""

complete_for "bash fish powershell zsh" sk2 completions ""

echo "  ---- bash: $pass passed, $fail failed"
exit $(( fail > 0 ))
