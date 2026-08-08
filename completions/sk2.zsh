#compdef sk2
#
# zsh completion for sk2
#
# Install:  sk2 completions zsh > "${fpath[1]}/_sk2"
#      or:  mkdir -p ~/.zsh/completions && sk2 completions zsh > ~/.zsh/completions/_sk2
#           then add to ~/.zshrc, before `compinit`:
#               fpath=(~/.zsh/completions $fpath)
#
# A file is a snapshot: re-run after every sk2 upgrade, or it will keep offering
# the subcommands of the release you installed it from.
#
# Unlike bash and fish, zsh has no `source <(sk2 completions zsh)` equivalent.
# compinit has to autoload this file from fpath, which is what the trailing
# `_sk2 "$@"` below is for -- sourcing it directly runs that call outside the
# completion system, where `_arguments` does not exist, and it fails.
#
# Service names come from `sk2 --list-services`, which reads only the plaintext
# service column and never prompts for a master password.

_sk2_services() {
    local -a services
    # (f) splits on newlines only, so service names containing spaces survive.
    services=( ${(f)"$(sk2 --list-services 2>/dev/null)"} )
    (( ${#services} )) && _describe -t sk2-services 'service' services
}

_sk2_commands() {
    local -a commands
    commands=(
        'init:Initialize a new vault (set master password)'
        'add:Add or update a credential'
        'get:Retrieve a credential by service name'
        'edit:Edit an existing credential'
        'delete:Delete a credential by service name'
        'rename:Rename a stored service'
        'list:List all stored service names'
        'generate:Generate a random password without storing it'
        'verify:Verify the integrity of all stored credentials'
        'change-password:Change the master password'
        'export:Export all credentials as an encrypted backup file'
        'import:Import credentials from an encrypted backup file'
        'completions:Print a shell completion script'
        'help:Print help'
    )
    _describe -t sk2-commands 'sk2 command' commands
}

_sk2() {
    local context state state_descr line
    typeset -A opt_args

    _arguments -C \
        '--vault[path to the vault database file]:vault file:_files' \
        '(-h --help)'{-h,--help}'[print help]' \
        '(-V --version)'{-V,--version}'[print version]' \
        '1: :_sk2_commands' \
        '*:: :->args' && return

    case $state in
        args)
            case $words[1] in
                get)
                    _arguments \
                        '--username[copy the username instead of the password]' \
                        '--print[print the value to stdout instead of copying it]' \
                        '1:service:_sk2_services'
                    ;;
                delete)
                    _arguments '1:service:_sk2_services'
                    ;;
                edit)
                    _arguments \
                        '--username[edit only the username]' \
                        '--password[edit only the password]' \
                        '--notes[edit only the notes]' \
                        '--url[edit only the URL]' \
                        '1:service:_sk2_services'
                    ;;
                rename)
                    # Only the old name is an existing service; the new one is being coined.
                    _arguments '1:service:_sk2_services' '2:new name: '
                    ;;
                add)
                    # The service argument is a new name — deliberately not completed.
                    _arguments \
                        '(-g --generate)'{-g,--generate}'[generate a random password]' \
                        '(-l --length)'{-l,--length}'[length of the generated password]:length: ' \
                        '(-c --charset)'{-c,--charset}'[character set]:charset:(default alphanumeric websafe hex dna)' \
                        '--notes[prompt for notes]' \
                        '--url[URL for the service]:url: ' \
                        '1:new service name: '
                    ;;
                list)
                    # The argument is a substring filter, not a service name.
                    _arguments \
                        '--stale[show only credentials not updated recently]' \
                        '--days[staleness threshold in days]:days: ' \
                        '1:filter: '
                    ;;
                generate)
                    _arguments \
                        '(-l --length)'{-l,--length}'[length]:length: ' \
                        '(-c --charset)'{-c,--charset}'[character set]:charset:(default alphanumeric websafe hex dna)'
                    ;;
                export)
                    _arguments \
                        '(-o --output)'{-o,--output}'[output file path]:output file:_files' \
                        '--format[backup format]:format:(sk2b gpg)' \
                        '--overwrite[overwrite the output file if it exists]'
                    ;;
                import)
                    _arguments '1:backup file:_files'
                    ;;
                completions)
                    _arguments '1:shell:(bash zsh fish powershell)'
                    ;;
            esac
            ;;
    esac
}

_sk2 "$@"
