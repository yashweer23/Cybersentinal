param(
    [Parameter(Mandatory = $true)][string]$BackupFile,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z][a-z0-9_]{0,62}$')][string]$TargetDatabase,
    [string[]]$ComposeFile = @('docker-compose.yml')
)
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Compose-Helpers.ps1')
Set-ComposeArguments $ComposeFile
$Name = 'cybersentinel_restore_' + [Guid]::NewGuid().ToString('N')
$RemoteArchive = "/tmp/$Name.dump"
$RemoteScript = "/tmp/$Name.sh"
$ExitCode = 0
# Resolve the caller's path before changing directory.
try { $Archive = (Resolve-Path -LiteralPath $BackupFile).Path }
catch { Write-Host '[FAIL] Backup file does not exist.'; exit 1 }
Push-Location $ProjectRoot
try {
    Get-Command docker -ErrorAction Stop | Out-Null
    if ($TargetDatabase -in @('postgres', 'template0', 'template1')) { throw 'Choose a new application database name.' }
    if (-not (Test-Path -LiteralPath "$Archive.sha256")) { throw 'Matching .dump.sha256 file is required.' }
    $Expected = ([IO.File]::ReadAllText("$Archive.sha256")).Trim()
    $Actual = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash
    if ($Expected -notmatch '^[a-fA-F0-9]{64}$' -or $Expected -ne $Actual) { throw 'Backup checksum verification failed.' }
    Write-Host "[INFO] Restore target: $TargetDatabase. Existing databases are never overwritten. Restore only your own trusted backups."
    Invoke-ComposeChecked @('cp', (Join-Path $PSScriptRoot 'database-maintenance.sh'), "db:$RemoteScript")
    Invoke-ComposeChecked @('cp', $Archive, "db:$RemoteArchive")
    Invoke-ComposeChecked @('exec', '-T', 'db', 'sh', $RemoteScript, 'restore', $RemoteArchive, $TargetDatabase)
    Write-Host "[PASS] Restored into $TargetDatabase. The application's current database and .env are unchanged."
    Write-Host '[INFO] Inspect this database before deliberately switching POSTGRES_DB and recreating the backend.'
} catch {
    Write-Host "[FAIL] $($_.Exception.Message)"
    Write-Host '[INFO] If restore failed after database creation, the new empty database is retained for inspection. Use another new name when retrying.'
    $ExitCode = 1
} finally {
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        try { Invoke-ComposeChecked @('exec', '-T', 'db', 'rm', '-f', $RemoteArchive, $RemoteScript) }
        catch { Write-Host '[WARN] Temporary container files could not be removed.' }
    }
    Pop-Location
}
exit $ExitCode
