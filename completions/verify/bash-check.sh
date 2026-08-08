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

# The install path itself, not just the function.
#
# Every assertion above runs after `source <(sk2 completions bash)` at the top of
# this file. That proves `_sk2` behaves, and proves nothing at all about whether a
# user who follows README.md ends up with `_sk2` registered. The gap shipped a bug
# in 1.3.0: the documented location was ~/.bash_completion.d/, which
# bash-completion never reads, so following the instructions exactly produced
# filename completion and 35 green assertions said otherwise.
#
# Same lesson as the `gh attestation` defect found before the 1.3.0 release --
# instructions have to be walked the way the audience walks them.
bc_main=""
for candidate in /usr/share/bash-completion/bash_completion \
                 /usr/local/share/bash-completion/bash_completion \
                 /etc/bash_completion; do
    [[ -r "$candidate" ]] && { bc_main="$candidate"; break; }
done

if [[ -z "$bc_main" ]]; then
    echo "  SKIPPED -- bash-completion is not installed, so the documented XDG"
    echo "            install path cannot be verified on this machine."
    (( fail++ ))
else
    fake_home="$SCRATCH/install-home"
    mkdir -p "$fake_home/.local/share/bash-completion/completions"
    # Exactly the command README.md gives.
    sk2 completions bash > "$fake_home/.local/share/bash-completion/completions/sk2"

    # A fresh bash that knows only bash-completion and that directory: no `source`
    # of our own, so registration has to come from the install path or not at all.
    got="$(HOME="$fake_home" XDG_DATA_HOME="$fake_home/.local/share" \
        bash --norc -c '
            source "$1" >/dev/null 2>&1
            if declare -F _comp_load >/dev/null; then _comp_load sk2 2>/dev/null
            else _completion_loader sk2 2>/dev/null; fi
            complete -p sk2 2>/dev/null
        ' _ "$bc_main")"

    if [[ "$got" == *"-F _sk2"*" sk2" ]]; then
        printf '  ok    %-40s -> [%s]\n' "install to XDG completions dir" "$got"
        (( pass++ ))
    else
        printf '  FAIL  %-40s\n        expected [complete -F _sk2 sk2]\n        got      [%s]\n' \
            "install to XDG completions dir" "$got"
        (( fail++ ))
    fi
fi

echo "  ---- bash: $pass passed, $fail failed"
exit $(( fail > 0 ))
