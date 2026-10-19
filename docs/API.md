# API reference

[Architecture](ARCHITECTURE.md) · [Security](SECURITY.md) · [Database](DATABASE.md)

The generated OpenAPI document is the authoritative field-level contract. With the default local stack, use `http://localhost:5173/docs` or `http://localhost:8000/docs`; JSON is at `/openapi.json`. `API_DOCS_ENABLED=false` hides interactive documentation. This inventory was checked against the restored application on 2026-10-17: 87 paths and 88 unique operations in development/test, including four development diagnostics. Production omits those diagnostics.

## Authentication from PowerShell

Login accepts JSON `username` and `password`, not an OAuth form or email lookup. Use your actual account; no example below contains a reusable password. This keeps credentials/tokens in process memory without printing them.

```powershell
$Api = 'http://localhost:5173'
$Credential = Get-Credential -Message 'CyberSentinel username and password'
if ($null -eq $Credential) { throw 'Credentials not supplied.' }
$Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$Guard = @{ 'X-CSRF-Guard' = '1'; Origin = $Api }
$LoginBody = @{
    username = $Credential.UserName
    password = $Credential.GetNetworkCredential().Password
} | ConvertTo-Json
try {
    $Login = Invoke-RestMethod "$Api/api/auth/login" -Method Post -ContentType 'application/json' -Headers $Guard -WebSession $Session -Body $LoginBody
    $Headers = @{ Authorization = "Bearer $($Login.access_token)" }
    Invoke-RestMethod "$Api/api/auth/me" -Headers $Headers
} finally {
    $Credential = $null
    $LoginBody = $null
}
```

Expected login response: `access_token`, `token_type: "bearer"`, `expires_in` and a safe user projection. The refresh credential is an HttpOnly cookie. Refresh uses `POST /api/auth/refresh` with the cookie, guard and trusted origin; logout revokes the session. Swagger's Authorize control accepts an existing bearer token but does not bypass the browser guard for cookie-auth requests. Avoid saving tokens in screenshots or shared request collections.

## Representative requests

After the login block, an ADMIN or ANALYST can ingest one synthetic event. The ID is intentionally fixed: rerunning this example returns `duplicate` instead of another row.

```powershell
$Event = @{
    event_id = 'DOC-DEMO-LOGIN-001'
    timestamp = [DateTime]::UtcNow.ToString('o')
    source_ip = '198.51.100.44'
    destination_ip = '10.0.0.12'
    username = 'employee014'
    event_type = 'LOGIN_FAILED'
    service = 'authentication'
    destination_port = 443
    status = 'failed'
    raw_data = @{}
} | ConvertTo-Json -Depth 5
Invoke-RestMethod "$Api/api/events/ingest" -Method Post -Headers $Headers -ContentType 'application/json' -Body $Event
Invoke-RestMethod "$Api/api/events?event_type=LOGIN_FAILED&limit=20&offset=0" -Headers $Headers
```

Single ingestion returns `status`, `event_id`, `database_id` and `duplicate`. Batch ingestion takes `{"events": [...]}` and returns inserted/duplicate/invalid/failed counts and bounded per-record errors. A successful HTTP response is not evidence that every batch item was accepted: check the counters and `complete`.

```powershell
Invoke-RestMethod "$Api/api/detection/run" -Method Post -Headers $Headers -ContentType 'application/json' -Body '{"batch_size":500,"until_empty":true}'
Invoke-RestMethod "$Api/api/risk/run" -Method Post -Headers $Headers -ContentType 'application/json' -Body '{"until_empty":true}'
Invoke-RestMethod "$Api/api/incidents/process" -Method Post -Headers $Headers -ContentType 'application/json' -Body '{"until_empty":true}'
Invoke-RestMethod "$Api/api/detections?rule_id=CS-001&limit=20" -Headers $Headers
Invoke-RestMethod "$Api/api/incidents?status=OPEN&minimum_risk=50&limit=20" -Headers $Headers
```

Runs return actual counts/timing and a completion state; bounded work may require another run when `complete=false`. A single failed-login event alone does not meet the brute-force threshold. Detection dry-run/replay and risk rescore are separate options; use the [demo pipeline](DEMO.md) for a complete seeded example.

Use an actual incident ID from the queue before executing the following. These are operator actions; the comment and status update are persisted/audited.

```powershell
$IncidentId = Read-Host 'Existing synthetic incident ID'
$CasePath = "$Api/api/incidents/$([Uri]::EscapeDataString($IncidentId))"
Invoke-RestMethod $CasePath -Headers $Headers
Invoke-RestMethod "$CasePath/comments" -Method Post -Headers $Headers -ContentType 'application/json' -Body '{"comment":"Synthetic demo: reviewed the linked event evidence."}'
Invoke-RestMethod "$Api/api/ai/incidents/$([Uri]::EscapeDataString($IncidentId))/analyze" -Method Post -Headers $Headers -ContentType 'application/json' -Body '{}'
Invoke-RestMethod "$Api/api/threats/lookup" -Method Post -Headers $Headers -ContentType 'application/json' -Body '{"ip":"198.51.100.73","force_refresh":false}'
Invoke-RestMethod "$Api/api/reports/security-summary?range=7d&format=json" -Headers $Headers
```

AI response modes and intelligence `simulation` / `mode` / `lookup_status` must be inspected, not interpreted as evidence of a paid provider call. The lookup uses server-configured mode; the demo requires mock mode. Incident status updates use `PATCH .../status`, e.g. `{"status":"INVESTIGATING"}`; valid transition constraints still apply. Resolution requires its summary, and false-positive decisions require a reason. Notes cannot substitute for a workflow transition.

End the session when finished:

```powershell
Invoke-RestMethod "$Api/api/auth/logout" -Method Post -Headers $Guard -WebSession $Session
$Headers = $null
$Login = $null
$Session = $null
```

## Pagination, filters and errors

List endpoints expose bounded `limit` and `offset`. Event lists default to 50 and allow at most 500; case lists at most 200; reports at most 5,000 rows per page. Responses expose the corresponding total or continuation information. Reporting CSV headers include `X-Export-Has-More` and `X-Export-Next-Offset`; do not assume one response is a complete large export.

Event filters include event type, source/destination IP, username, service, status, processed, `start_time` and `end_time`. Findings add rule and severity. Incidents add status, severity, minimum/maximum risk, analyst, rule, username and IP. Dashboard and analytics have their own validated UTC period/range contracts: consult OpenAPI rather than reusing event-list parameter names. Live updates use the ingestion cursor so late occurrence timestamps do not disappear from the stream.

Typical responses: 401 unauthenticated/invalid session; 403 role denied; 404 missing resource; 409 incompatible state/concurrent operation where applicable; 413 oversized body; 422 validation failure; 429 rate limited; 503 unavailable dependency/readiness. Error details are sanitized. Never treat a provider timeout or unknown score as a clean reputation verdict.

## Complete route inventory

`Authenticated` means ADMIN, ANALYST or VIEWER with an active session. `Operator` means ADMIN or ANALYST. Public auth routes have credential/cookie/CSRF/rate-limit requirements; “public” does not imply an unrestricted action. Report workload restrictions are enforced inside the handler as well as by its route dependency.

| Method | Path | Access |
| --- | --- | --- |
| GET | `/api/system/live` | Public |
| GET | `/api/system/ready` | Public |
| GET | `/api/system/health` | Public |
| POST | `/api/auth/register` | Public; guard; creates VIEWER |
| POST | `/api/auth/login` | Public; guard + credentials |
| GET | `/api/auth/me` | Authenticated |
| POST | `/api/auth/refresh` | Refresh cookie + guard |
| POST | `/api/auth/logout` | Refresh cookie + guard |
| GET | `/api/users` | ADMIN |
| GET | `/api/users/{user_id}` | ADMIN |
| PATCH | `/api/users/{user_id}/role` | ADMIN |
| PATCH | `/api/users/{user_id}/status` | ADMIN |
| POST | `/api/events/ingest` | Operator |
| POST | `/api/events/ingest/batch` | Operator |
| GET | `/api/events` | Authenticated |
| GET | `/api/events/stats` | Authenticated |
| GET | `/api/events/{event_id}` | Authenticated |
| POST | `/api/detection/run` | Operator |
| GET | `/api/detections` | Authenticated |
| GET | `/api/detections/{finding_id}` | Authenticated |
| GET | `/api/detection/stats` | Authenticated |
| GET | `/api/detection-rules` | Authenticated |
| PATCH | `/api/detection-rules/{rule_id}` | ADMIN |
| POST | `/api/risk/run` | Operator |
| GET | `/api/risk` | Authenticated |
| GET | `/api/risk/stats` | Authenticated |
| GET | `/api/risk/{assessment_id}` | Authenticated |
| GET | `/api/incidents` | Authenticated |
| GET | `/api/incidents/eligible-analysts` | Operator |
| GET | `/api/incidents/stats` | Authenticated |
| POST | `/api/incidents/process` | Operator |
| GET | `/api/incidents/{incident_id}` | Authenticated |
| PATCH | `/api/incidents/{incident_id}/assign` | Operator |
| PATCH | `/api/incidents/{incident_id}/status` | Operator |
| POST | `/api/incidents/{incident_id}/comments` | Operator |
| GET | `/api/incidents/{incident_id}/comments` | Authenticated |
| GET | `/api/incidents/{incident_id}/findings` | Authenticated |
| GET | `/api/incidents/{incident_id}/events` | Authenticated |
| GET | `/api/incidents/{incident_id}/timeline` | Authenticated |
| POST | `/api/threats/lookup` | Operator |
| GET | `/api/threats` | Authenticated |
| GET | `/api/threats/providers/status` | Authenticated |
| POST | `/api/threats/enrich/incidents` | Operator |
| GET | `/api/threats/ip/{ip}` | Authenticated |
| GET | `/api/incidents/{incident_id}/threat-intelligence` | Authenticated |
| GET | `/api/detections/{finding_id}/threat-intelligence` | Authenticated |
| GET | `/api/dashboard/overview` | Authenticated |
| GET | `/api/dashboard/events/timeline` | Authenticated |
| GET | `/api/dashboard/events/types` | Authenticated |
| GET | `/api/dashboard/events/recent` | Authenticated |
| GET | `/api/dashboard/events/updates` | Authenticated |
| GET | `/api/dashboard/incidents/severity` | Authenticated |
| GET | `/api/dashboard/incidents/status` | Authenticated |
| GET | `/api/dashboard/incidents/recent` | Authenticated |
| GET | `/api/dashboard/threats/top-ips` | Authenticated |
| GET | `/api/dashboard/threats/summary` | Authenticated |
| GET | `/api/dashboard/users/targeted` | Authenticated |
| GET | `/api/dashboard/detection/rules` | Authenticated |
| GET | `/api/dashboard/risk/distribution` | Authenticated |
| GET | `/api/dashboard/activity/summary` | Authenticated |
| GET | `/api/dashboard/system/health` | Authenticated |
| GET | `/api/ai/status` | Authenticated |
| POST | `/api/ai/incidents/{incident_id}/analyze` | Operator |
| GET | `/api/ai/incidents/{incident_id}/analysis` | Authenticated |
| GET | `/api/ai/incidents/{incident_id}/history` | Authenticated |
| POST | `/api/ai/incidents/{incident_id}/ask` | Operator |
| POST | `/api/ai/overview/ask` | Operator |
| GET | `/api/analytics/overview` | Authenticated |
| GET | `/api/analytics/events/trend` | Authenticated |
| GET | `/api/analytics/incidents/trend` | Authenticated |
| GET | `/api/analytics/detections/rules` | Authenticated |
| GET | `/api/analytics/risk/trend` | Authenticated |
| GET | `/api/analytics/risk/histogram` | Authenticated |
| GET | `/api/analytics/entities/high-risk` | Authenticated |
| GET | `/api/analytics/incidents/backlog` | Authenticated |
| GET | `/api/analytics/analysts/workload` | ADMIN |
| GET | `/api/analytics/threat-intelligence` | Authenticated |
| GET | `/api/analytics/categories` | Authenticated |
| GET | `/api/analytics/geography` | Authenticated |
| GET | `/api/analytics/ai/usage` | Authenticated |
| GET | `/api/analytics/detections/evaluation` | Authenticated |
| GET | `/api/analytics/incidents/status-history` | Authenticated |
| GET | `/api/reports/{report_type}` | Operator; analyst-workload requires ADMIN |
| GET | `/api/database/status` | Public; development/test only |
| GET | `/api/test/authenticated` | Authenticated; development/test only |
| GET | `/api/test/analyst` | Operator; development/test only |
| GET | `/api/test/admin` | ADMIN; development/test only |
| GET | `/` | Public |

Report types: `security-summary`, `incidents`, `detection-findings`, `risk-assessments`, `threat-indicators`, `analyst-workload`, `detection-rules`. Both JSON and CSV use the same underlying definitions and authorization.

Implementation: [routes](../backend/app/routes), [schemas](../backend/app/schemas), [authorization dependencies](../backend/app/security/dependencies.py). The development-only database route verifies connectivity; use `/api/system/ready` for schema-aware operational readiness.
