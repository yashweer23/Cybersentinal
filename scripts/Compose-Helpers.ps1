# Shared by operational scripts; compatible with Windows PowerShell 5.1 and PowerShell 7.
function Invoke-ComposeChecked {
    param([string[]]$Arguments)
    $PreviousPreference = $ErrorActionPreference
    try {
        # Windows PowerShell can wrap native stderr as NativeCommandError even on success.
        # The native process exit code, not the output stream, determines success.
        $ErrorActionPreference = 'Continue'
        & docker compose @script:ComposeArguments @Arguments 2>&1 | ForEach-Object { Write-Host $_.ToString() }
        $Code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $PreviousPreference }
    if ($Code -ne 0) { throw "Docker Compose failed (exit $Code). See output above." }
}

function Set-ComposeArguments {
    param([string[]]$ComposeFile)
    $script:ComposeArguments = @()
    foreach ($File in $ComposeFile) {
        $script:ComposeArguments += @('-f', $File)
    }
}
