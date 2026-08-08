#!/usr/bin/env bash
# fish exposes `complete -C '<line>'`, which returns exactly what Tab would
# offer, so no pseudo-terminal is needed. Invoked by run.sh.
#
# stderr is asserted empty as well as the candidates: output during completion
# lands in the middle of the user's half-typed command line, which the spec
# forbids outright.
set -u
SCRATCH="${SK2_COMP_SCRATCH:?run via completions/verify/run.sh}"
export PATH="$SCRATCH/bin:$PATH" SK2_VAULT="$SCRATCH/vault.db"

sk2 completions fish > "$SCRATCH/sk2.fish"

pass=0; fail=0

complete_for() {
    local expected="$1" line="$2" got err
    got="$(fish --no-config -c "
        set -gx PATH '$SCRATCH/bin' \$PATH
        set -gx SK2_VAULT '$SCRATCH/vault.db'
        source '$SCRATCH/sk2.fish'
        complete -C '$line'
    " 2>"$SCRATCH/fish.err" | cut -f1 | grep -v '^$' | sort | tr '\n' ' ' | sed 's/ $//')"
    err="$(cat "$SCRATCH/fish.err")"
    if [[ "$got" == "$expected" && -z "$err" ]]; then
        printf '  ok    %-40s -> [%s]\n' "$line" "$got"; (( pass++ ))
    else
        printf '  FAIL  %-40s\n        expected [%s]\n        got      [%s]\n' \
            "$line" "$expected" "$got"
        [[ -n "$err" ]] && printf '        stderr   [%s]  <- must be empty\n' "$err"
        (( fail++ ))
    fi
}

SERVICES='github gitlab gmail my bank zoom'

echo "fish:"

# Positive control -- see the note in bash-check.sh. Three assertions below
# expect nothing, and a broken harness also produces nothing.
if [[ -z "$(fish --no-config -c "
        set -gx PATH '$SCRATCH/bin' \$PATH
        set -gx SK2_VAULT '$SCRATCH/vault.db'
        source '$SCRATCH/sk2.fish'
        complete -C 'sk2 get '" 2>/dev/null)" ]]; then
    echo "  ABORT -- positive control returned nothing; the harness is broken,"
    echo "           so the 'must offer nothing' cases cannot be trusted."
    exit 2
fi

complete_for "add change-password completions delete edit export generate get import init list rename verify" "sk2 "

# fish matches substrings as well as prefixes, so `chan(g)e-password` is offered
# for `g`. That is fish-wide behaviour -- a completion declared with no sk2
# involvement does the same -- and is not something this script controls. fish
# also sorts the candidate list itself, so only the SET is asserted here;
# asserting order would pin fish's internals rather than sk2's contract.
complete_for "change-password generate get" "sk2 g"

complete_for "$SERVICES" "sk2 get "
complete_for "github gitlab" "sk2 get git"
complete_for "$SERVICES" "sk2 delete "
complete_for "$SERVICES" "sk2 edit "
complete_for "$SERVICES" "sk2 rename "

complete_for "" "sk2 add "
complete_for "" "sk2 rename github "
complete_for "" "sk2 list "

complete_for "$SERVICES" "sk2 --vault /tmp/v.db get "
complete_for "bash fish powershell zsh" "sk2 completions "

echo "  ---- fish: $pass passed, $fail failed"
exit $(( fail > 0 ))
