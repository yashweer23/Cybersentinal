param(
    [int]$FrontendPort = 0,
    [int]$BackendPort = 0
)
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$EnvironmentFile = Join-Path $ProjectRoot '.env'
$ConfiguredPorts = @{}
# Read only ports; never print secrets or bearer tokens.
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
$ExitCode = 0
function Assert-Forbidden([string]$Path) {
    try {
        Invoke-RestMethod "$ApiBase$Path" -Headers $Headers -WebSession $Session | Out-Null
    } catch {
        if ($null -ne $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 403) {
            Write-Host "[PASS] Role restriction: $Path"
            return
        }
        throw
    }
    throw "Expected HTTP 403 for $Path"
}
try {
    $Frontend = Invoke-WebRequest "http://localhost:$FrontendPort" -UseBasicParsing
    if ($Frontend.StatusCode -ne 200) { throw 'Frontend did not return HTTP 200.' }
    Write-Host '[PASS] Frontend reachable'
    $Health = Invoke-RestMethod "$ApiBase/api/system/health"
    if ($Health.status -ne 'healthy') { throw 'Backend readiness is not healthy.' }
    Write-Host '[PASS] Backend and database readiness healthy'
    $Docs = Invoke-WebRequest "$ApiBase/docs" -UseBasicParsing
    if ($Docs.StatusCode -ne 200) { throw 'Swagger did not return HTTP 200.' }
    $Spec = Invoke-RestMethod "$ApiBase/openapi.json"
    $Endpoints = @('overview', 'events/trend', 'incidents/trend', 'incidents/status-history', 'detections/rules', 'risk/trend', 'risk/histogram', 'entities/high-risk', 'incidents/backlog', 'analysts/workload', 'threat-intelligence', 'categories', 'geography', 'ai/usage', 'detections/evaluation')
    foreach ($Path in $Endpoints) {
        if ($null -eq $Spec.paths.PSObject.Properties["/api/analytics/$Path"]) {
            throw "Missing Phase 14 OpenAPI route: $Path. Rebuild the backend."
        }
    }
    if ($null -eq $Spec.paths.PSObject.Properties['/api/reports/{report_type}']) { throw 'Report route is missing.' }
    Write-Host '[PASS] Swagger contains all 15 analytics routes and reports'
    $Credential = Get-Credential -Message 'Use an existing CyberSentinel username and password (any role).'
    if ($null -eq $Credential) { throw 'Credential entry was cancelled.' }
    $LoginBody = @{ username = $Credential.UserName; password = $Credential.GetNetworkCredential().Password } | ConvertTo-Json
    $Auth = Invoke-RestMethod "$ApiBase/api/auth/login" -Method Post -ContentType 'application/json' -Headers @{ 'X-CSRF-Guard' = '1' } -Body $LoginBody -SessionVariable Session
    $LoginBody = $null
    $Credential = $null
    $Headers = @{ Authorization = "Bearer $($Auth.access_token)" }
    $Profile = Invoke-RestMethod "$ApiBase/api/auth/me" -Headers $Headers -WebSession $Session
    Write-Host "[PASS] Authenticated as $($Profile.role)"
    $End = [DateTimeOffset]::UtcNow
    $Start = $End.AddDays(-30)
    $Period = 'start=' + [uri]::EscapeDataString($Start.ToString('o')) + '&end=' + [uri]::EscapeDataString($End.ToString('o'))
    foreach ($Path in $Endpoints) {
        if ($Path -eq 'analysts/workload' -and $Profile.role -ne 'ADMIN') {
            Assert-Forbidden "/api/analytics/$Path"
            continue
        }
        $Result = Invoke-RestMethod "$ApiBase/api/analytics/${Path}?$Period" -Headers $Headers -WebSession $Session
        if ($null -eq $Result.scope -or -not $Result.definition) { throw "Missing analytics scope or definition: $Path" }
        if ($Path -eq 'overview') { $Overview = $Result }
        Write-Host "[PASS] /api/analytics/$Path"
    }
    if ($Profile.role -eq 'VIEWER') {
        Assert-Forbidden '/api/reports/security-summary'
    } else {
        $Report = Invoke-RestMethod "$ApiBase/api/reports/security-summary?${Period}&format=json&limit=5000" -Headers $Headers -WebSession $Session
        if ($Report.report_type -ne 'security-summary' -or $null -eq $Report.sections.overview) { throw 'Missing structured security summary.' }
        $Csv = Invoke-WebRequest "$ApiBase/api/reports/incidents?${Period}&format=csv&limit=100" -Headers $Headers -WebSession $Session -UseBasicParsing
        if ($Csv.Headers['Content-Type'] -notmatch 'text/csv' -or $null -eq $Csv.Headers['X-Export-Rows']) { throw 'Missing CSV response metadata.' }
        Write-Host "[PASS] JSON summary and CSV report ($($Csv.Headers['X-Export-Rows']) incident rows)"
        if ($Profile.role -ne 'ADMIN') { Assert-Forbidden '/api/reports/analyst-workload' }
    }
    Write-Host "[PASS] Selected UTC period: events=$($Overview.total_events), findings=$($Overview.detection_findings), incidents=$($Overview.incidents_created)"
    Write-Host '[INFO] Empty datasets and unavailable response metrics are valid (0/null). No processing or AI generation was triggered.'
    Write-Host '[PASS] Phase 14 read-only verification complete. See docs/PHASE14.md for browser checks and database tests.'
} catch {
    Write-Host "[FAIL] $($_.Exception.Message)"
    Write-Host 'Inspect: docker compose ps; docker compose logs --tail=80 frontend backend db'
    $ExitCode = 1
} finally {
    if ($Auth -and $Session) {
        try {
            Invoke-RestMethod "$ApiBase/api/auth/logout" -Method Post -ContentType 'application/json' -Body '{}' -WebSession $Session -Headers @{ 'X-CSRF-Guard' = '1'; Authorization = "Bearer $($Auth.access_token)" } | Out-Null
        } catch { Write-Host 'Could not close the verification session; it will expire normally.' }
    }
    $Credential = $null
    $LoginBody = $null
    $Headers = $null
    $Auth = $null
    $Session = $null
}
exit $ExitCode
