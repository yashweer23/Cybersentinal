param(
    [string]$FrontendUrl = '',
    [string]$BackendUrl = ''
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
$FrontendUrl = $FrontendUrl.TrimEnd('/')
$BackendUrl = $BackendUrl.TrimEnd('/')

try {
    $frontend = Invoke-WebRequest -UseBasicParsing -Uri $FrontendUrl -TimeoutSec 20
    if ($frontend.StatusCode -ne 200 -or $frontend.Content -notmatch 'CyberSentinel') { throw 'Unexpected frontend response' }
    Write-Host '[PASS] Frontend HTML is served'

    $health = Invoke-RestMethod -Uri "$BackendUrl/api/system/health" -TimeoutSec 20
    if ($health.status -ne 'healthy' -or $health.services.api.status -ne 'running') { throw 'Backend is not healthy' }
    if ($health.services.database.status -ne 'connected') { throw 'PostgreSQL is not connected' }
    Write-Host '[PASS] Backend is running and PostgreSQL query succeeded'

    $proxy = Invoke-RestMethod -Uri "$FrontendUrl/api/system/health" -TimeoutSec 20
    if ($proxy.status -ne 'healthy') { throw 'Frontend-to-backend proxy is not healthy' }
    Write-Host '[PASS] Frontend API proxy is working'

    $docs = Invoke-WebRequest -UseBasicParsing -Uri "$BackendUrl/docs" -TimeoutSec 20
    if ($docs.StatusCode -ne 200 -or $docs.Content -notmatch 'swagger') { throw 'API docs are unavailable' }
    $schema = Invoke-RestMethod -Uri "$BackendUrl/openapi.json" -TimeoutSec 20
    if (-not $schema.paths.'/api/system/health') { throw 'OpenAPI health endpoint is missing' }
    Write-Host '[PASS] /docs and OpenAPI schema are accessible'
    Write-Host 'All Phase 1 connectivity checks passed. Open the frontend to confirm the React page renders.'
    $health | ConvertTo-Json -Depth 6
} catch {
    Write-Host "[FAIL] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Inspect: docker compose ps; docker compose logs --tail=80 backend db frontend'
    exit 1
}
