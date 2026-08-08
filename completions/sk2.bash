# bash completion for sk2
#
# Install:  echo 'command -v sk2 >/dev/null && source <(sk2 completions bash)' >> ~/.bashrc
#
# That form regenerates the script on every shell start, so it always matches the
# installed binary and survives an sk2 upgrade. It also needs no bash-completion
# package, since this script uses only bash builtins.
#
# The guard matters: unguarded, uninstalling sk2 or a PATH that does not yet
# include it when .bashrc runs makes every new shell print a command-not-found
# error at startup. Put the line after whatever sets PATH.
#
# Or install a file -- but a file is a snapshot, so re-run after every upgrade or
# it will keep offering the subcommands of the release you installed it from:
#
#           mkdir -p ~/.local/share/bash-completion/completions
#           sk2 completions bash > ~/.local/share/bash-completion/completions/sk2
#      or:  sk2 completions bash > /etc/bash_completion.d/sk2   (system-wide, needs root)
#
# NOT ~/.bash_completion.d/ -- despite being widely repeated, bash-completion
# reads no such directory. It loads the XDG path above, /etc/bash_completion.d,
# and the single file ~/.bash_completion. A script left in ~/.bash_completion.d/
# is sourced by nothing and Tab silently falls back to filenames.
#
# Service names come from `sk2 --list-services`, which reads only the plaintext
# service column and never prompts for a master password.

_sk2_subcommand() {
    # First non-option word after `sk2`. --vault takes a value, so skip it.
    local i
    for (( i = 1; i < COMP_CWORD; i++ )); do
        case "${COMP_WORDS[i]}" in
            --vault) (( i++ )) ;;
            -*) ;;
            *) printf '%s' "${COMP_WORDS[i]}"; return ;;
        esac
    done
}

_sk2_positional_index() {
    # How many positional words precede the cursor, counting the subcommand as 1.
    local i count=0
    for (( i = 1; i < COMP_CWORD; i++ )); do
        case "${COMP_WORDS[i]}" in
            --vault) (( i++ )) ;;
            -*) ;;
            *) (( count++ )) ;;
        esac
    done
    printf '%s' "$count"
}

_sk2() {
    local cur cmd pos
    cur="${COMP_WORDS[COMP_CWORD]}"
    COMPREPLY=()

    # Complete the value of --vault as a path.
    if [[ "${COMP_WORDS[COMP_CWORD-1]}" == "--vault" ]]; then
        COMPREPLY=( $(compgen -f -- "$cur") )
        return
    fi

    cmd="$(_sk2_subcommand)"

    if [[ -z "$cmd" ]]; then
        COMPREPLY=( $(compgen -W "init add get edit delete rename list generate verify \
                                  change-password export import completions help" -- "$cur") )
        return
    fi

    pos="$(_sk2_positional_index)"

    case "$cmd" in
        get|delete|edit|rename)
            # Only the first positional names a stored service. `rename`'s second
            # argument is a new name the user is coining, and `add`'s is too — so
            # neither gets completed.
            if [[ "$pos" == "1" ]]; then
                local IFS=$'\n'
                COMPREPLY=( $(compgen -W "$(sk2 --list-services 2>/dev/null)" -- "$cur") )
                # Service names may contain spaces; escape so the shell keeps them
                # as one word on insertion.
                COMPREPLY=( "${COMPREPLY[@]// /\\ }" )
            fi
            ;;
        completions)
            [[ "$pos" == "1" ]] && COMPREPLY=( $(compgen -W "bash zsh fish powershell" -- "$cur") )
            ;;
        export)
            [[ "$cur" == -* ]] && COMPREPLY=( $(compgen -W "--output --format --overwrite" -- "$cur") )
            ;;
        add)
            # No service completion: the argument is a new name. Flags only.
            [[ "$cur" == -* ]] && COMPREPLY=( $(compgen -W "--generate --length --charset --notes --url" -- "$cur") )
            ;;
        list)
            # The argument is a substring filter, not a service name. Completing it
            # with exact names would imply it must match one.
            [[ "$cur" == -* ]] && COMPREPLY=( $(compgen -W "--stale --days" -- "$cur") )
            ;;
    esac
}

complete -F _sk2 sk2
