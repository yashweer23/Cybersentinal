param(
    [int]$FrontendPort = 0,
    [int]$BackendPort = 0
)
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$EnvironmentFile = Join-Path $ProjectRoot '.env'
# Read only non-secret ports. Never print the environment file or access token.
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
$ExitCode = 0
try {
    $Frontend = Invoke-WebRequest "http://localhost:$FrontendPort" -UseBasicParsing
    if ($Frontend.StatusCode -ne 200) { throw 'Frontend did not return HTTP 200.' }
    Write-Host '[PASS] Frontend reachable'
    $Health = Invoke-RestMethod "$ApiBase/api/system/health"
    if ($Health.status -ne 'healthy') { throw 'Backend readiness is not healthy.' }
    Write-Host '[PASS] Backend readiness healthy'
    $Docs = Invoke-WebRequest "$ApiBase/docs" -UseBasicParsing
    if ($Docs.StatusCode -ne 200) { throw 'Swagger did not return HTTP 200.' }
    $Spec = Invoke-RestMethod "$ApiBase/openapi.json"
    if ($null -eq $Spec.paths.PSObject.Properties['/api/incidents/eligible-analysts']) {
        throw 'Phase 12 analyst directory is missing from OpenAPI. Rebuild the backend image.'
    }
    Write-Host '[PASS] Swagger includes the Phase 12 projection API'
    $Credential = Get-Credential -Message 'Use an existing CyberSentinel username and password (any role).'
    if ($null -eq $Credential) { throw 'Credential entry was cancelled.' }
    $LoginBody = @{ username = $Credential.UserName; password = $Credential.GetNetworkCredential().Password } | ConvertTo-Json
    $Auth = Invoke-RestMethod "$ApiBase/api/auth/login" -Method Post -ContentType 'application/json' -Headers @{ 'X-CSRF-Guard' = '1' } -Body $LoginBody -SessionVariable Session
    $LoginBody = $null
    $Credential = $null
    $Headers = @{ Authorization = "Bearer $($Auth.access_token)" }
    $Profile = Invoke-RestMethod "$ApiBase/api/auth/me" -Headers $Headers -WebSession $Session
    Write-Host "[PASS] Signed in with role $($Profile.role)"
    if ($Profile.role -in @('ADMIN', 'ANALYST')) {
        $Directory = Invoke-RestMethod "$ApiBase/api/incidents/eligible-analysts?limit=5" -Headers $Headers -WebSession $Session
        if ($null -eq $Directory.total) { throw 'Analyst directory pagination is missing.' }
        foreach ($Operator in $Directory.items) {
            if (-not $Operator.is_active -or $Operator.role -notin @('ADMIN', 'ANALYST')) {
                throw 'Analyst directory returned an ineligible operator.'
            }
        }
        Write-Host '[PASS] Eligible analyst directory'
    }
    $Queue = Invoke-RestMethod "$ApiBase/api/incidents?limit=1" -Headers $Headers -WebSession $Session
    if ($Queue.items.Count -eq 0) {
        Write-Warning 'No incidents exist. Startup checks passed, but investigation checks cannot run. Use the existing Phase 4-9 workflow, then rerun this script.'
        $ExitCode = 2
    } else {
        $IncidentId = $Queue.items[0].incident_id
        $CasePath = "/api/incidents/$([uri]::EscapeDataString($IncidentId))"
        $Case = Invoke-RestMethod "$ApiBase$CasePath" -Headers $Headers -WebSession $Session
        foreach ($Field in @('allowed_transitions', 'risk_assessment', 'findings', 'evidence_total', 'first_seen', 'last_seen')) {
            if ($null -eq $Case.PSObject.Properties[$Field]) { throw "Incident detail is missing $Field" }
        }
        if ($Profile.role -eq 'VIEWER' -and $Case.allowed_transitions.Count -gt 0) {
            throw 'VIEWER unexpectedly received workflow transitions.'
        }
        Write-Host "[PASS] Investigation detail: $IncidentId"
        foreach ($Section in @('findings?limit=5', 'events?limit=5', 'timeline?order=desc&limit=5', 'comments?limit=5', 'threat-intelligence?limit=5')) {
            $Result = Invoke-RestMethod "$ApiBase$CasePath/$Section" -Headers $Headers -WebSession $Session
            if ($null -eq $Result) { throw "Empty response for $Section" }
            Write-Host "[PASS] Investigation $Section"
        }
        if ($null -ne $Case.risk_assessment) {
            if ($null -eq $Case.risk_assessment.breakdown) { throw 'Stored risk component breakdown is missing.' }
            Write-Host '[PASS] Stored risk assessment available'
        } else {
            Write-Host '[INFO] This incident has no stored assessment; the UI shows unavailable.'
        }
        $DeepLink = Invoke-WebRequest "http://localhost:$FrontendPort/incidents/$([uri]::EscapeDataString($IncidentId))?tab=events" -UseBasicParsing
        if ($DeepLink.StatusCode -ne 200) { throw 'Frontend deep link is not reachable.' }
        Write-Host '[PASS] Frontend investigation deep link returns HTTP 200'
        Write-Host 'Read-only API verification complete. Follow docs/PHASE12.md for browser and mutation acceptance checks.'
    }
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
    $LoginBody = $null
    $Credential = $null
    $Auth = $null
    $Headers = $null
    $Session = $null
}
exit $ExitCode
