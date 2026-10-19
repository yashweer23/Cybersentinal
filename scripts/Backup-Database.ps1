param(
    [string]$OutputDirectory = '',
    [string[]]$ComposeFile = @('docker-compose.yml')
)
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Compose-Helpers.ps1')
Set-ComposeArguments $ComposeFile
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $ProjectRoot 'backups' }
$Name = 'cybersentinel_' + [DateTime]::UtcNow.ToString('yyyyMMdd_HHmmss') + '_' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$RemoteArchive = "/tmp/$Name.dump"
$RemoteScript = "/tmp/$Name.sh"
$Archive = $null
$Temporary = $null
$ExitCode = 0
Push-Location $ProjectRoot
try {
    Get-Command docker -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $Archive = Join-Path (Resolve-Path $OutputDirectory).Path "$Name.dump"
    $Temporary = "$Archive.partial"
    Invoke-ComposeChecked @('cp', (Join-Path $PSScriptRoot 'database-maintenance.sh'), "db:$RemoteScript")
    Invoke-ComposeChecked @('exec', '-T', 'db', 'sh', $RemoteScript, 'backup', $RemoteArchive)
    # Binary archives must never pass through PowerShell text redirection or Tee-Object.
    Invoke-ComposeChecked @('cp', "db:$RemoteArchive", $Temporary)
    if ((Get-Item $Temporary).Length -le 0) { throw 'Backup is empty.' }
    $Hash = (Get-FileHash $Temporary -Algorithm SHA256).Hash.ToLowerInvariant()
    Move-Item -LiteralPath $Temporary -Destination $Archive
    [IO.File]::WriteAllText("$Archive.sha256", $Hash + "`n", [Text.Encoding]::ASCII)
    Write-Host "[PASS] PostgreSQL custom-format backup: $Archive"
    Write-Host '[INFO] Keep the .dump and .dump.sha256 together. This contains database contents, including authentication records.'
} catch {
    Write-Host "[FAIL] $($_.Exception.Message)"
    $ExitCode = 1
} finally {
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        try { Invoke-ComposeChecked @('exec', '-T', 'db', 'rm', '-f', $RemoteArchive, $RemoteScript) }
        catch { Write-Host '[WARN] Temporary container files could not be removed.' }
    }
    if ($Temporary -and (Test-Path -LiteralPath $Temporary)) { Remove-Item -LiteralPath $Temporary }
    Pop-Location
}
exit $ExitCode
