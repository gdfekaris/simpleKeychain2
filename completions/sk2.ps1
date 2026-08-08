# PowerShell completion for sk2
#
# Install:  sk2 completions powershell > ~\sk2-completion.ps1
#           then add to $PROFILE, once:  . ~\sk2-completion.ps1
#
# Refresh after an sk2 upgrade by re-running the first line only. A file is a
# snapshot: left alone it will keep offering the subcommands of the release you
# installed it from.
#
# NOT `sk2 completions powershell >> $PROFILE`. That was the documented install
# until 2026-08-08 and it appends: running it again after an upgrade leaves two
# copies of this script in the profile rather than replacing the first, and the
# profile grows by one copy per upgrade.
#
# Reload with:  . $PROFILE
#
# Service names come from `sk2 --list-services`, which reads only the plaintext
# service column and never prompts for a master password.

Register-ArgumentCompleter -Native -CommandName sk2 -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commands = @(
        @{ Name = 'init';            Tip = 'Initialize a new vault' }
        @{ Name = 'add';             Tip = 'Add or update a credential' }
        @{ Name = 'get';             Tip = 'Retrieve a credential' }
        @{ Name = 'edit';            Tip = 'Edit an existing credential' }
        @{ Name = 'delete';          Tip = 'Delete a credential' }
        @{ Name = 'rename';          Tip = 'Rename a stored service' }
        @{ Name = 'list';            Tip = 'List stored service names' }
        @{ Name = 'generate';        Tip = 'Generate a password without storing it' }
        @{ Name = 'verify';          Tip = 'Verify integrity of all credentials' }
        @{ Name = 'change-password'; Tip = 'Change the master password' }
        @{ Name = 'export';          Tip = 'Export an encrypted backup' }
        @{ Name = 'import';          Tip = 'Import an encrypted backup' }
        @{ Name = 'completions';     Tip = 'Print a shell completion script' }
    )

    # Words typed so far, excluding the executable itself.
    $elements = @($commandAst.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.ToString() })

    # Drop the partially typed word so it is not counted as complete.
    if ($wordToComplete -and $elements.Count -gt 0 -and $elements[-1] -eq $wordToComplete) {
        $elements = @($elements | Select-Object -SkipLast 1)
    }

    # Subcommand and positional count. --vault consumes the word after it.
    $subcommand = $null
    $positionals = 0
    $skipNext = $false
    foreach ($element in $elements) {
        if ($skipNext) { $skipNext = $false; continue }
        if ($element -eq '--vault') { $skipNext = $true; continue }
        if ($element.StartsWith('-')) { continue }
        if (-not $subcommand) { $subcommand = $element }
        $positionals++
    }

    function New-Result($text, $tooltip) {
        # Quote values containing spaces so they insert as a single argument.
        $insert = if ($text -match '\s') { "'" + $text.Replace("'", "''") + "'" } else { $text }
        [System.Management.Automation.CompletionResult]::new(
            $insert, $text, 'ParameterValue', $tooltip)
    }

    if (-not $subcommand) {
        return $commands |
            Where-Object { $_.Name -like "$wordToComplete*" } |
            ForEach-Object { New-Result $_.Name $_.Tip }
    }

    # Only the first positional names a stored service. `add` and `rename`'s second
    # argument are new names being coined; `list`'s argument is a substring filter.
    if ($subcommand -in @('get', 'delete', 'edit', 'rename') -and $positionals -eq 1) {
        $services = @()
        try { $services = @(& sk2 --list-services 2>$null) } catch { }
        return $services |
            Where-Object { $_ -and $_ -like "$wordToComplete*" } |
            ForEach-Object { New-Result $_ 'Stored service' }
    }

    if ($subcommand -eq 'completions' -and $positionals -eq 1) {
        return @('bash', 'zsh', 'fish', 'powershell') |
            Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object { New-Result $_ 'Shell' }
    }

    $flags = switch ($subcommand) {
        'get'      { @('--username', '--print') }
        'edit'     { @('--username', '--password', '--notes', '--url') }
        'add'      { @('--generate', '--length', '--charset', '--notes', '--url') }
        'generate' { @('--length', '--charset') }
        'list'     { @('--stale', '--days') }
        'export'   { @('--output', '--format', '--overwrite') }
        default    { @() }
    }
    $flags += '--vault'

    return $flags |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { New-Result $_ 'Option' }
}
