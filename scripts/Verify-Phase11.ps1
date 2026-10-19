param(
    [int]$FrontendPort = 0,
    [int]$BackendPort = 0
)
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$EnvironmentFile = Join-Path $ProjectRoot '.env'
# Read only non-secret port settings. Never print the environment file.
$ConfiguredPorts = @{}
if (Test-Path $EnvironmentFile) {
    Get-Content $EnvironmentFile | ForEach-Object {
        if ($_ -match '^\s*(FRONTEND_PORT|BACKEND_PORT)\s*=\s*(\d+)\s*$') {
            $ConfiguredPorts[$Matches[1]] = [int]$Matches[2]
        }
    }
}
if ($FrontendPort -eq 0) {
    $FrontendPort = if ($ConfiguredPorts.ContainsKey('FRONTEND_PORT')) { $ConfiguredPorts['FRONTEND_PORT'] } else { 5173 }
}
if ($BackendPort -eq 0) {
    $BackendPort = if ($ConfiguredPorts.ContainsKey('BACKEND_PORT')) { $ConfiguredPorts['BACKEND_PORT'] } else { 8000 }
}
$ApiBase = "http://localhost:$BackendPort"
$Credential = $null
$LoginBody = $null
$Session = $null
$Auth = $null
$Headers = $null
try {
    $Frontend = Invoke-WebRequest "http://localhost:$FrontendPort" -UseBasicParsing
    if ($Frontend.StatusCode -ne 200) { throw 'Frontend did not return HTTP 200.' }
    Write-Host '[PASS] Frontend reachable'
    $Health = Invoke-RestMethod "$ApiBase/api/system/health"
    if ($Health.status -ne 'healthy') { throw 'Backend readiness is not healthy.' }
    Write-Host '[PASS] Backend readiness healthy'
    $Docs = Invoke-WebRequest "$ApiBase/docs" -UseBasicParsing
    if ($Docs.StatusCode -ne 200) { throw 'Swagger did not return HTTP 200.' }
    Write-Host '[PASS] Swagger accessible'
    $Credential = Get-Credential -Message 'Use an existing CyberSentinel username and password (any role).'
    $LoginBody = @{ username = $Credential.UserName; password = $Credential.GetNetworkCredential().Password } | ConvertTo-Json
    $Auth = Invoke-RestMethod "$ApiBase/api/auth/login" -Method Post -ContentType 'application/json' -Headers @{ 'X-CSRF-Guard' = '1' } -Body $LoginBody -SessionVariable Session
    $Headers = @{ Authorization = "Bearer $($Auth.access_token)" }
    foreach ($Path in @('overview?range=24h', 'events/timeline?range=24h', 'incidents/severity?range=24h', 'risk/distribution?range=24h', 'events/recent?range=24h', 'detection/rules?range=24h', 'threats/summary?range=24h', 'system/health')) {
        $Result = Invoke-RestMethod "$ApiBase/api/dashboard/$Path" -Headers $Headers -WebSession $Session
        if ($null -eq $Result) { throw "Empty response for $Path" }
        Write-Host "[PASS] /api/dashboard/$Path"
    }
    $Recent = Invoke-RestMethod "$ApiBase/api/dashboard/events/recent?range=24h&limit=5" -Headers $Headers -WebSession $Session
    $Updates = Invoke-RestMethod "$ApiBase/api/dashboard/events/updates?after_id=$($Recent.polling_cursor)&limit=5" -Headers $Headers -WebSession $Session
    if ($null -eq $Updates.next_cursor) { throw 'Polling cursor missing.' }
    Write-Host '[PASS] Decimal polling cursor accepted'
    Write-Host 'API verification complete. Follow docs/PHASE11.md for browser acceptance checks.'
} catch {
    Write-Host "[FAIL] $($_.Exception.Message)"
    Write-Host 'Inspect: docker compose ps; docker compose logs --tail=80 frontend backend db'
    exit 1
} finally {
    if ($Auth -and $Session) {
        try {
            Invoke-RestMethod "$ApiBase/api/auth/logout" -Method Post -ContentType 'application/json' -Body '{}' -WebSession $Session -Headers @{ 'X-CSRF-Guard' = '1'; Authorization = "Bearer $($Auth.access_token)" } | Out-Null
        } catch { Write-Host 'Could not close the verification session; it will expire normally.' }
    }
    $LoginBody = $null
    $Credential = $null
    $Auth = $null
    $Headers = $null
    $Session = $null
}
