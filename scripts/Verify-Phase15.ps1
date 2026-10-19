param(
    [int]$FrontendPort = 0,
    [int]$BackendPort = 0,
    [switch]$RestartServices,
    [switch]$SkipLogin,
    [switch]$SkipDocs,
    [string[]]$ComposeFile = @('docker-compose.yml')
)
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Compose-Helpers.ps1')
Set-ComposeArguments $ComposeFile
$ConfiguredPorts = @{}
if (Test-Path (Join-Path $ProjectRoot '.env')) {
    Get-Content (Join-Path $ProjectRoot '.env') | ForEach-Object {
        if ($_ -match '^\s*(FRONTEND_PORT|BACKEND_PORT)\s*=\s*(\d+)\s*$') { $ConfiguredPorts[$Matches[1]] = [int]$Matches[2] }
    }
}
if (-not $FrontendPort) { $FrontendPort = if ($ConfiguredPorts.ContainsKey('FRONTEND_PORT')) { $ConfiguredPorts['FRONTEND_PORT'] } else { 5173 } }
if (-not $BackendPort) { $BackendPort = if ($ConfiguredPorts.ContainsKey('BACKEND_PORT')) { $ConfiguredPorts['BACKEND_PORT'] } else { 8000 } }
$Frontend = "http://localhost:$FrontendPort"
$Backend = "http://localhost:$BackendPort"
$Session = $null
$Auth = $null
$ExitCode = 0

function Wait-Ready {
    $Deadline = [DateTime]::UtcNow.AddSeconds(120)
    do {
        try {
            $Ready = Invoke-RestMethod "$Frontend/api/system/ready" -TimeoutSec 5
            if ($Ready.status -eq 'ready') { return }
        } catch { }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $Deadline)
    throw 'Readiness did not recover within 120 seconds. Inspect logs and run Alembic migrations.'
}
function Get-BusinessCounts {
    $Raw = & docker compose @script:ComposeArguments exec -T backend python -m scripts.inspect_operations
    if ($LASTEXITCODE -ne 0) { throw 'Could not read database counts.' }
    $Object = ($Raw -join "`n") | ConvertFrom-Json
    return ($Object | ConvertTo-Json -Compress)
}
function Check-HTTP {
    foreach ($Path in @('/', '/incidents/INC-operational-smoke', '/analytics', '/api/system/live', '/api/system/ready', '/api/system/health')) {
        $Result = Invoke-WebRequest "$Frontend$Path" -UseBasicParsing -TimeoutSec 15
        if ($Result.StatusCode -ne 200) { throw "Unexpected HTTP status: $Path" }
        if ($Path.StartsWith('/api/') -and $Result.Headers['X-Request-ID'] -notmatch '^[a-f0-9]{32}$') { throw 'Missing request correlation ID.' }
        if ($Result.Headers['X-Content-Type-Options'] -ne 'nosniff') { throw 'Missing security header.' }
    }
    if ((Invoke-RestMethod "$Backend/api/system/live").status -ne 'alive') { throw 'Direct backend liveness failed.' }
    if ((Invoke-RestMethod "$Frontend/api/system/health").status -ne 'healthy') { throw 'Database connectivity check failed.' }
    if (-not $SkipDocs) {
        Invoke-WebRequest "$Frontend/docs" -UseBasicParsing | Out-Null
        $Spec = Invoke-RestMethod "$Frontend/openapi.json"
        foreach ($Path in @('/api/system/ready', '/api/auth/login', '/api/detection/run', '/api/analytics/overview', '/api/reports/{report_type}')) {
            if ($null -eq $Spec.paths.PSObject.Properties[$Path]) { throw "Missing API route: $Path" }
        }
    }
    Write-Host '[PASS] Frontend deep links, backend proxy, health, request IDs, security headers and configured docs'
}

Push-Location $ProjectRoot
try {
    Invoke-ComposeChecked @('ps')
    Wait-Ready
    Check-HTTP
    $Before = Get-BusinessCounts
    if ($RestartServices) {
        Write-Host '[INFO] Restart tests temporarily interrupt the local application. Do not run workflows concurrently.'
        Invoke-ComposeChecked @('restart')
        Wait-Ready
        Check-HTTP
        Invoke-ComposeChecked @('stop', 'db')
        try {
            if ((Invoke-RestMethod "$Backend/api/system/live").status -ne 'alive') { throw 'API process stopped with the database.' }
            $OutageStatus = 200
            try { Invoke-WebRequest "$Backend/api/system/ready" -UseBasicParsing -TimeoutSec 15 | Out-Null }
            catch {
                if ($null -eq $_.Exception.Response) { throw }
                $OutageStatus = [int]$_.Exception.Response.StatusCode
            }
            if ($OutageStatus -ne 503) { throw 'Expected readiness HTTP 503 during database outage.' }
        } finally { Invoke-ComposeChecked @('start', 'db') }
        Wait-Ready
        Invoke-ComposeChecked @('restart', 'backend')
        Wait-Ready
        Check-HTTP
        if ((Get-BusinessCounts) -ne $Before) { throw 'Business-table counts changed during restart. Check for concurrent workflows.' }
        Write-Host '[PASS] Full restart, database outage/recovery, backend restart, business-row persistence'
    }
    if (-not $SkipLogin) {
        $Credential = Get-Credential -Message 'Use your existing CyberSentinel username/password to verify login through Nginx.'
        if ($null -eq $Credential) { throw 'Login check cancelled.' }
        $Body = @{ username = $Credential.UserName; password = $Credential.GetNetworkCredential().Password } | ConvertTo-Json
        $Auth = Invoke-RestMethod "$Frontend/api/auth/login" -Method Post -ContentType 'application/json' -Headers @{ 'X-CSRF-Guard' = '1' } -Body $Body -SessionVariable Session
        $Body = $null
        $Credential = $null
        $Headers = @{ Authorization = "Bearer $($Auth.access_token)" }
        Invoke-RestMethod "$Frontend/api/auth/me" -Headers $Headers -WebSession $Session | Out-Null
        Invoke-RestMethod "$Frontend/api/dashboard/overview" -Headers $Headers -WebSession $Session | Out-Null
        Write-Host '[PASS] Login and authenticated dashboard through the frontend proxy'
    }
    Write-Host '[PASS] Phase 15 requested smoke checks complete. Backup/restore verification is documented separately in docs/PHASE15.md.'
} catch {
    Write-Host "[FAIL] $($_.Exception.Message)"
    Write-Host 'Inspect: docker compose ps; docker compose logs --tail=80 frontend backend db'
    $ExitCode = 1
} finally {
    if ($Auth -and $Session) {
        try { Invoke-RestMethod "$Frontend/api/auth/logout" -Method Post -ContentType 'application/json' -Body '{}' -WebSession $Session -Headers @{ 'X-CSRF-Guard' = '1'; Authorization = "Bearer $($Auth.access_token)" } | Out-Null }
        catch { Write-Host '[WARN] Verification session could not be closed; it expires normally.' }
    }
    $Credential = $null
    $Body = $null
    $Headers = $null
    $Auth = $null
    $Session = $null
    Pop-Location
}
exit $ExitCode
