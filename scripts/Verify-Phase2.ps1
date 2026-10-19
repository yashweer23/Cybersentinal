param(
    [string]$FrontendUrl = '',
    [string]$BackendUrl = '',
    [string]$AccessToken = ''
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$environmentFile = Join-Path $projectRoot '.env'

function Get-ConfiguredPort([string]$Name, [int]$Default) {
    if (Test-Path $environmentFile) {
        $escapedName = [regex]::Escape($Name)
        $match = Select-String -Path $environmentFile -Pattern "^${escapedName}=(\d+)\s*$" | Select-Object -First 1
        if ($match) { return [int]$match.Matches[0].Groups[1].Value }
    }
    return $Default
}

if (-not $FrontendUrl) { $FrontendUrl = 'http://localhost:' + (Get-ConfiguredPort 'FRONTEND_PORT' 5173) }
if (-not $BackendUrl) { $BackendUrl = 'http://localhost:' + (Get-ConfiguredPort 'BACKEND_PORT' 8000) }
$BackendUrl = $BackendUrl.TrimEnd('/')
$FrontendUrl = $FrontendUrl.TrimEnd('/')

try {
    $phase1Script = Join-Path $PSScriptRoot 'Verify-Phase1.ps1'
    powershell -NoProfile -ExecutionPolicy Bypass -File $phase1Script -FrontendUrl $FrontendUrl -BackendUrl $BackendUrl
    if ($LASTEXITCODE -ne 0) { throw 'Phase 1 connectivity checks failed' }

    $database = Invoke-RestMethod -Uri "$BackendUrl/api/database/status" -TimeoutSec 20
    if ($database.status -ne 'healthy' -or -not $database.connected -or -not $database.schema_ready) {
        throw 'Database schema is not ready. Run alembic upgrade head.'
    }
    if ($database.migration_revision -ne $database.expected_revision) { throw 'Database is behind migration head' }
    Write-Host "[PASS] PostgreSQL schema is ready at revision $($database.migration_revision)"

    if ($AccessToken) {
    $rules = Invoke-RestMethod -Uri "$BackendUrl/api/detection-rules" -Headers @{ Authorization = "Bearer $AccessToken" } -TimeoutSec 20
    $actualIds = @($rules | ForEach-Object { $_.rule_id } | Sort-Object)
    $expectedIds = @(1..10 | ForEach-Object { 'CS-{0:D3}' -f $_ })
    if ($rules.Count -ne 10 -or ($actualIds -join ',') -ne ($expectedIds -join ',')) {
        throw 'Expected the ten seeded rules CS-001 through CS-010'
    }
    Write-Host '[PASS] Detection-rules endpoint returned all ten definitions'
    } else {
        Write-Host '[SKIP] Rule listing now requires authentication. Run Verify-Phase3.ps1 for the authenticated check.'
    }

    $proxied = Invoke-RestMethod -Uri "$FrontendUrl/api/database/status" -TimeoutSec 20
    if (-not $proxied.schema_ready) { throw 'Database endpoint failed through the frontend proxy' }
    Write-Host '[PASS] Phase 2 endpoint works through the frontend proxy'
    $database | ConvertTo-Json -Depth 4
    Write-Host 'All Phase 2 HTTP checks passed. Use run_database_tests for database constraint tests.'
} catch {
    Write-Host "[FAIL] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Inspect: docker compose ps; docker compose logs --tail=80 backend db frontend'
    exit 1
}
