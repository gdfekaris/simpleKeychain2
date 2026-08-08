#!/usr/bin/env zsh
# zsh has no `complete -C` equivalent, so drive a real interactive zsh over a
# pseudo-terminal and read back what Tab actually offers -- the technique zsh's
# own test suite uses. Invoked by run.sh.
#
# Three things here are load-bearing and were each found the hard way:
#
#   * COLUMNS=200. Too narrow and zsh wraps the echoed command line, whose
#     fragments then contaminate the listing. Wide enough, and zsh separates
#     listing columns with two-or-more spaces while a service name keeps its
#     single space -- so splitting on runs of 2+ spaces recovers the candidates
#     without tearing "my bank" in half.
#   * Strip \a as well as \r. zsh rings the bell when there are NO matches, and
#     that byte sits after the trailing space where it defeats a whitespace
#     trim -- turning the three "must offer nothing" cases into false failures.
#     (The beep is itself confirmation that nothing was offered.)
#   * bindkey '^I' list-choices, so Tab lists every match instead of inserting
#     the longest common prefix.
emulate -L zsh
setopt no_unset

SCRATCH=${SK2_COMP_SCRATCH:?run via completions/verify/run.sh}
export PATH="$SCRATCH/bin:$PATH" SK2_VAULT="$SCRATCH/vault.db"

mkdir -p "$SCRATCH/zfunc"
sk2 completions zsh > "$SCRATCH/zfunc/_sk2"

zmodload zsh/zpty
integer pass=0 fail=0

drain() { local j; while zpty -r -t ZSH j 2>/dev/null; do :; done }

start_shell() {
    zpty -d ZSH 2>/dev/null
    zpty ZSH "PS1='%%>' COLUMNS=200 LINES=60 zsh -f -i"
    zpty -w ZSH "fpath=($SCRATCH/zfunc \$fpath)"
    zpty -w ZSH "export PATH='$SCRATCH/bin:'\$PATH SK2_VAULT='$SCRATCH/vault.db' COLUMNS=200"
    zpty -w ZSH "autoload -Uz compinit && compinit -u -d $SCRATCH/zcompdump"
    zpty -w ZSH "zstyle ':completion:*' list-packed false"
    zpty -w ZSH "setopt no_always_last_prompt no_list_ambiguous"
    zpty -w ZSH "bindkey '^I' list-choices"
    sleep 1.2
    drain
}

# Candidates are joined with | rather than spaces, so a service name containing
# a space stays unambiguous in the expected/got comparison.
complete_for() {
    local expected=$1 line=$2
    local raw="" chunk
    zpty -w -n ZSH "$line"$'\t'
    sleep 1.0
    while zpty -r -t ZSH chunk 2>/dev/null; do raw+=$chunk; done
    zpty -w ZSH $'\003'      # ^C: abandon the line before the next case
    sleep 0.2
    drain

    # Line-level cleanup first (drop the prompt and the echoed input), only then
    # split listing columns. The echoed line contains single spaces and would
    # otherwise survive the split as a bogus candidate.
    local trimmed; trimmed=$(print -r -- "$line" | sed 's/[[:space:]]*$//')
    local got
    got=$(print -r -- $raw \
        | sed $'s/\033\\[[0-9;?]*[a-zA-Z]//g' \
        | tr -d '\r\a' \
        | sed $'s/.\010//g' \
        | sed 's/[[:space:]]*$//' \
        | grep -v '^%>' \
        | grep -vxF "$trimmed" \
        | sed 's/[[:space:]][[:space:]]*--.*$//' \
        | sed 's/  \+/\n/g' \
        | sed 's/^ *//; s/ *$//' \
        | grep -v '^$' \
        | sort | tr '\n' '|' | sed 's/|$//')

    if [[ $got == $expected ]]; then
        printf '  ok    %-40s -> [%s]\n' "$line" "$got"; (( pass++ ))
    else
        printf '  FAIL  %-40s\n        expected [%s]\n        got      [%s]\n' \
            "$line" "$expected" "$got"
        (( fail++ ))
    fi
}

local SERVICES='github|gitlab|gmail|my bank|zoom'

echo "zsh:"
start_shell

# Positive control -- see the note in bash-check.sh. Three assertions below
# expect nothing, and a broken pty harness also produces nothing. This one
# matters most here: zpty setup is the likeliest thing to go quietly wrong.
complete_for "$SERVICES" "sk2 get "
if (( fail )); then
    echo "  ABORT -- positive control failed; the harness is broken, so the"
    echo "           'must offer nothing' cases cannot be trusted."
    zpty -d ZSH 2>/dev/null
    exit 2
fi

complete_for "generate|get" "sk2 g"
complete_for "github|gitlab" "sk2 get git"
complete_for "$SERVICES" "sk2 delete "
complete_for "$SERVICES" "sk2 edit "
complete_for "$SERVICES" "sk2 rename "
complete_for "" "sk2 add "
complete_for "" "sk2 rename github "
complete_for "" "sk2 list "
complete_for "$SERVICES" "sk2 --vault /tmp/v.db get "
complete_for "bash|fish|powershell|zsh" "sk2 completions "
zpty -d ZSH 2>/dev/null

echo "  ---- zsh: $pass passed, $fail failed"
exit $(( fail > 0 ))
