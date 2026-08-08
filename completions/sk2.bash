# bash completion for sk2
#
# Install:  sk2 completions bash > ~/.bash_completion.d/sk2
#      or:  sk2 completions bash > /etc/bash_completion.d/sk2   (system-wide)
#      or:  echo 'source <(sk2 completions bash)' >> ~/.bashrc
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
