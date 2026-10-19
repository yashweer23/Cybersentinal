param(
    [int]$FrontendPort = 0,
    [int]$BackendPort = 0,
    [switch]$Generate
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
    if ($null -eq $Spec.paths.PSObject.Properties['/api/ai/incidents/{incident_id}/analyze']) {
        throw 'Phase 13 AI analyst is missing from OpenAPI. Rebuild the backend image.'
    }
    Write-Host '[PASS] Swagger includes the Phase 13 AI endpoints'
    $Credential = Get-Credential -Message 'Use an existing CyberSentinel username and password (any role).'
    if ($null -eq $Credential) { throw 'Credential entry was cancelled.' }
    $LoginBody = @{ username = $Credential.UserName; password = $Credential.GetNetworkCredential().Password } | ConvertTo-Json
    $Auth = Invoke-RestMethod "$ApiBase/api/auth/login" -Method Post -ContentType 'application/json' -Headers @{ 'X-CSRF-Guard' = '1' } -Body $LoginBody -SessionVariable Session
    $LoginBody = $null
    $Credential = $null
    $Headers = @{ Authorization = "Bearer $($Auth.access_token)" }
    $Profile = Invoke-RestMethod "$ApiBase/api/auth/me" -Headers $Headers -WebSession $Session
    Write-Host "[PASS] Signed in with role $($Profile.role)"
    $Status = Invoke-RestMethod "$ApiBase/api/ai/status" -Headers $Headers -WebSession $Session
    if ($Status.status -notin @('READY', 'CONFIGURED', 'FALLBACK', 'DISABLED')) { throw 'Invalid AI status.' }
    Write-Host "[PASS] AI analyst: $($Status.status)"
    $Queue = Invoke-RestMethod "$ApiBase/api/incidents?limit=1" -Headers $Headers -WebSession $Session
    if ($Queue.items.Count -eq 0) {
        Write-Warning 'No incidents available. Startup passed; create cases through the existing pipeline and rerun.'
        $ExitCode = 2
    } else {
        $IncidentId = $Queue.items[0].incident_id
        $Path = "/api/ai/incidents/$([uri]::EscapeDataString($IncidentId))"
        $Saved = Invoke-RestMethod "$ApiBase$Path/analysis" -Headers $Headers -WebSession $Session
        $History = Invoke-RestMethod "$ApiBase$Path/history?limit=5" -Headers $Headers -WebSession $Session
        Write-Host "[PASS] Analysis read and history ($($History.total) versions)"
        if ($Generate) {
            if ($Profile.role -notin @('ADMIN', 'ANALYST')) { throw '-Generate requires ADMIN or ANALYST.' }
            if (-not $Status.enabled) { throw 'AI analyst generation is disabled in the environment.' }
            $Before = Invoke-RestMethod "$ApiBase/api/incidents/$IncidentId" -Headers $Headers -WebSession $Session
            $Report = Invoke-RestMethod "$ApiBase$Path/analyze" -Method Post -Body '{"force_refresh":false}' -ContentType 'application/json' -Headers $Headers -WebSession $Session -TimeoutSec 100
            if ($Report.analysis_mode -notin @('AI', 'FALLBACK')) { throw 'Invalid analysis mode.' }
            if (-not $Report.summary -or $Report.key_evidence.Count -eq 0) { throw 'Missing structured evidence report.' }
            foreach ($Evidence in $Report.key_evidence) {
                foreach ($ReferenceId in $Evidence.reference_ids) {
                    if ($ReferenceId -notin $Report.references.reference_id) { throw 'Report contains an unrecognized evidence reference.' }
                }
            }
            $Answer = Invoke-RestMethod "$ApiBase$Path/ask" -Method Post -Body '{"question":"Was there a successful login after failures?"}' -ContentType 'application/json' -Headers $Headers -WebSession $Session
            if (-not $Answer.answer) { throw 'Incident Q&A did not return an answer.' }
            $After = Invoke-RestMethod "$ApiBase/api/incidents/$IncidentId" -Headers $Headers -WebSession $Session
            foreach ($Field in @('risk_score', 'severity', 'status', 'evidence_total')) {
                if ($Before.$Field -ne $After.$Field) { throw "Case $Field changed; check for concurrent analyst activity." }
            }
            Write-Host "[PASS] Generated/read report: $($Report.analysis_mode), cached=$($Report.cached), stale=$($Report.stale)"
            Write-Host '[PASS] Scoped Q&A and unchanged authoritative case fields'
        } else {
            Write-Host '[INFO] Read-only verification. Add -Generate to explicitly generate one report (may call the configured provider).'
        }
        Write-Host 'Follow docs/PHASE13.md for browser acceptance checks, tests and SQL inspection.'
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
