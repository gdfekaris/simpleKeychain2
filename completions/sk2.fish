# fish completion for sk2
#
# Install:  sk2 completions fish > ~/.config/fish/completions/sk2.fish
#
# Service names come from `sk2 --list-services`, which reads only the plaintext
# service column and never prompts for a master password.

function __sk2_services
    sk2 --list-services 2>/dev/null
end

# How many positional arguments precede the cursor, counting the subcommand as 1.
# --vault takes a value, so its argument is skipped rather than counted.
function __sk2_positional_index
    set -l tokens (commandline -opc)
    set -l count 0
    set -l skip 0
    for token in $tokens[2..-1]
        if test $skip -eq 1
            set skip 0
        else if test "$token" = "--vault"
            set skip 1
        else if string match -qr '^-' -- $token
            # a flag, not a positional
        else
            set count (math $count + 1)
        end
    end
    echo $count
end

function __sk2_at_positional
    test (__sk2_positional_index) -eq $argv[1]
end

# Never fall back to filename completion.
complete -c sk2 -f

# Subcommands
complete -c sk2 -n __fish_use_subcommand -a init            -d 'Initialize a new vault'
complete -c sk2 -n __fish_use_subcommand -a add             -d 'Add or update a credential'
complete -c sk2 -n __fish_use_subcommand -a get             -d 'Retrieve a credential'
complete -c sk2 -n __fish_use_subcommand -a edit            -d 'Edit an existing credential'
complete -c sk2 -n __fish_use_subcommand -a delete          -d 'Delete a credential'
complete -c sk2 -n __fish_use_subcommand -a rename          -d 'Rename a stored service'
complete -c sk2 -n __fish_use_subcommand -a list            -d 'List stored service names'
complete -c sk2 -n __fish_use_subcommand -a generate        -d 'Generate a password without storing it'
complete -c sk2 -n __fish_use_subcommand -a verify          -d 'Verify integrity of all credentials'
complete -c sk2 -n __fish_use_subcommand -a change-password -d 'Change the master password'
complete -c sk2 -n __fish_use_subcommand -a export          -d 'Export an encrypted backup'
complete -c sk2 -n __fish_use_subcommand -a import          -d 'Import an encrypted backup'
complete -c sk2 -n __fish_use_subcommand -a completions     -d 'Print a shell completion script'

# Service names: only the first positional, and only for commands that take an
# existing service. `add` and `rename`'s second argument are new names being
# coined; `list`'s argument is a substring filter, not a service name.
complete -c sk2 -n '__fish_seen_subcommand_from get delete edit rename; and __sk2_at_positional 1' \
    -a '(__sk2_services)' -d Service

complete -c sk2 -n '__fish_seen_subcommand_from completions; and __sk2_at_positional 1' \
    -a 'bash zsh fish powershell'

# Global
complete -c sk2 -l vault -r -F -d 'Path to the vault database file'

# Per-command flags
complete -c sk2 -n '__fish_seen_subcommand_from get' -l username -d 'Copy the username instead'
complete -c sk2 -n '__fish_seen_subcommand_from get' -l print    -d 'Print to stdout instead of copying'

complete -c sk2 -n '__fish_seen_subcommand_from edit' -l username -d 'Edit only the username'
complete -c sk2 -n '__fish_seen_subcommand_from edit' -l password -d 'Edit only the password'
complete -c sk2 -n '__fish_seen_subcommand_from edit' -l notes    -d 'Edit only the notes'
complete -c sk2 -n '__fish_seen_subcommand_from edit' -l url      -d 'Edit only the URL'

complete -c sk2 -n '__fish_seen_subcommand_from add' -s g -l generate -d 'Generate a random password'
complete -c sk2 -n '__fish_seen_subcommand_from add' -s l -l length -r -d 'Generated password length'
complete -c sk2 -n '__fish_seen_subcommand_from add' -s c -l charset -r \
    -a 'default alphanumeric websafe hex dna' -d 'Character set'
complete -c sk2 -n '__fish_seen_subcommand_from add' -l notes -d 'Prompt for notes'
complete -c sk2 -n '__fish_seen_subcommand_from add' -l url -r -d 'URL for the service'

complete -c sk2 -n '__fish_seen_subcommand_from generate' -s l -l length -r -d 'Length'
complete -c sk2 -n '__fish_seen_subcommand_from generate' -s c -l charset -r \
    -a 'default alphanumeric websafe hex dna' -d 'Character set'

complete -c sk2 -n '__fish_seen_subcommand_from list' -l stale -d 'Show only stale credentials'
complete -c sk2 -n '__fish_seen_subcommand_from list' -l days -r -d 'Staleness threshold in days'

complete -c sk2 -n '__fish_seen_subcommand_from export' -s o -l output -r -F -d 'Output file path'
complete -c sk2 -n '__fish_seen_subcommand_from export' -l format -r -a 'sk2b gpg' -d 'Backup format'
complete -c sk2 -n '__fish_seen_subcommand_from export' -l overwrite -d 'Overwrite existing file'

complete -c sk2 -n '__fish_seen_subcommand_from import' -F -d 'Backup file'
