# Testing and verification

This is the current test guide. The recorded [Phase 16 validation](PHASE16_VALIDATION.md) and [measurements](phase16_results.json) remain dated evidence; [Phase 17 validation](PHASE17_VALIDATION.md) records checks rerun for documentation/screenshots. A skipped native gate is not counted as a pass.

The application migration head is `0008_ai_analyses`. Phase 17 updates documentation and removes a stale phase label in the UI; domain behavior and production/dev build separation are unchanged. Use development targets for pytest, Ruff and pipeline validation. See [Setup](SETUP.md), [Demo](DEMO.md) and [Architecture](ARCHITECTURE.md) for current commands and policy.

## Verification matrix

Existing tests remain part of the suite. Phase 16 adds targeted missing boundaries, cross-module authorization checks and bounded-query regressions.

| Area | What is verified | Main evidence |
| --- | --- | --- |
| Configuration and health | Invalid secrets/configuration rejected; readiness checks migrations; outages return 503; liveness independent | `test_config.py`, `test_health.py`, `test_operations.py` |
| Database and migrations | PostgreSQL enums/JSONB/constraints/FKs; clean migrations; populated upgrade preserves rows; no metadata drift | `test_database.py`, `test_auth_migration.py`, isolated pipeline |
| Authentication | bcrypt, JWT expiry/signature/algorithm, refresh rotation/replay, logout, CSRF, rate limits | `test_auth_api.py`, `test_auth_security.py` |
| RBAC | Anonymous 401, VIEWER 403 on 13 write routes; no mutating SQL; existing JWT respects role change/deactivation | `test_security_matrix.py`, existing module API tests |
| Synthetic generation | Determinism, scenario parameters, valid normalized events, streaming export | `test_simulation.py`, `test_simulation_export.py` |
| Ingestion | Single/batch/file input, malformed records, size limits, duplicate IDs, rollback and pagination | `test_event_ingestion*.py`, full pipeline |
| Detection | All ten rules; below/equal/above thresholds; time windows, DST, labels ignored, historical context, replay, dry run | `test_detection_rules.py`, `test_detection_boundaries.py`, `test_detection_engine.py` |
| Risk | Score boundaries, explanations, versioned assessments, repeat/rescore behavior | `test_risk_calculator.py`, `test_risk_engine.py` |
| Incidents | Promotion boundaries including 75; correlation, evidence, assignment, transitions, notes and audits | `test_incident_*.py`, `test_investigation_api.py` |
| Intelligence | Mock/cache behavior; private/documentation IP handling; provider timeout, rate limit and error contracts | `test_threat_*.py`; outbound providers mocked |
| AI analyst | Grounded references, deterministic fallback, stale/cache behavior, rejected unsupported claims and bounded query intents | `test_ai_analyst.py`; no paid LLM calls |
| Dashboard and polling | UTC ranges, cohort counts, stable cursor, deduplication and bounded pages | `test_dashboard*.py`; native concurrency test requires real PostgreSQL |
| Analytics and reports | One case with 3 findings, 2 assessments each and 4 comments counts once; audited MTTA/MTTR; CSV formula neutralization | `test_advanced_analytics.py` |
| Frontend | Loading/error/empty states, filters/polling, investigations, AI, reports, auth retry, role routing, escaped text | Seven Vitest files; real Chromium/Nginx acceptance |
| Operations and performance | Bounded investigation queries, 1k/10k pipeline, authenticated API timings, JMeter 10/25 users; restart/recovery gates | `test_query_bounds.py`, `validate_system.py`, Phase 15 operational scripts |

The SQL-like filter test sends literal text to existing parameterized queries. Browser text is rendered through React. These checks and dependency scans are evidence of specific protections, not a penetration-test certification or proof that no vulnerability exists.

## Windows PowerShell: primary native verification

Prerequisites: Docker Desktop with Linux containers, the working Phase 15 project and its existing `.env`. From VS Code PowerShell:

```powershell
Set-Location 'C:\Users\saiya\OneDrive\Documents\Projects\cybersentinel'
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Verify-Phase16.ps1
if ($LASTEXITCODE -ne 0) { throw 'Phase 16 verification failed; inspect the first failure.' }
```

The script explicitly builds the **development** targets, applies existing migrations, idempotently seeds rules, runs Ruff, creates a fresh test database for pytest, runs both isolated pipelines, tests/builds React, and copies reports to `reports/phase16/`. The existing database role needs `CREATEDB` for the test runner and `CREATE` schema permission for pipeline validation. Test cleanup only drops the generated test database/schema; it never resets public tables. Do not use `docker compose down -v`.

Equivalent individual commands, useful when diagnosing one step:

```powershell
docker compose -f docker-compose.yml -f compose.dev.yml up --build -d --wait --wait-timeout 180
docker compose -f docker-compose.yml -f compose.dev.yml exec backend alembic upgrade head
docker compose -f docker-compose.yml -f compose.dev.yml exec backend python -m scripts.seed_detection_rules
docker compose -f docker-compose.yml -f compose.dev.yml exec backend python -m ruff check .
docker compose -f docker-compose.yml -f compose.dev.yml exec backend python -m scripts.run_database_tests -ra
docker compose -f docker-compose.yml -f compose.dev.yml exec backend python -m scripts.validate_system --count 1000 --output data/phase16-1000.json
docker compose -f docker-compose.yml -f compose.dev.yml exec backend python -m scripts.validate_system --count 10000 --output data/phase16-10000.json
docker compose -f docker-compose.yml -f compose.dev.yml exec frontend npm test
docker compose -f docker-compose.yml -f compose.dev.yml exec frontend npm run build
```

Expected: no failed tests; native PostgreSQL should execute the concurrency case skipped in the embedded run. Both pipeline JSON files must have `status: "passed"`, the requested event count, zero `unprocessed_events`, all integrity counters zero and `idempotency.passed: true`. Exact finding counts depend on existing defaults, seed, start date and timezone rules; the supplied measurements record their date/configuration. Do not accept an unexpectedly skipped database suite as a pass.

The validation pipeline always creates a fresh random schema, runs real Alembic migrations and generates temporary JSONL. It uses seed 42, mixed scenarios, the existing 95% normal ratio and a seven-day window. It forces local mock intelligence and deterministic AI fallback with fresh temporary user credentials. It verifies ingestion → detection → scoring → incidents → enrichment → investigation → AI → analytics/reports. It then reimports/replays/rescores/reprocesses and checks unchanged row counts and original-event hashes (excluding only `processed`). It also checks orphan references, uniqueness, valid scores, clean/populated migrations and OpenAPI uniqueness. It does not populate your visible demo workspace; use the [demo workflow](DEMO.md) for that.

## Host Python and JMeter measurements

Use Python 3.12+, Node 22.12+ and Java 17. Install the standalone Apache JMeter 5.6.3 release from the [Apache archive](https://archive.apache.org/dist/jmeter/binaries/); verify its SHA-512 checksum. JMeter and Playwright remain optional validation tools, outside application dependencies.

Keep the development Compose stack running so PostgreSQL is published on your existing host port (15432 in this project). The root `.env` should retain `POSTGRES_HOST=127.0.0.1` and that host port; Compose independently supplies `db:5432` inside containers. Do not change the internal PostgreSQL port to fix a host-port conflict.

```powershell
py -3.12 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r .\backend\requirements-dev.txt
Push-Location .\backend
try {
    & ..\.venv\Scripts\python.exe -m scripts.validate_system --count 10000 `
        --jmeter 'C:\Tools\apache-jmeter-5.6.3\bin\jmeter.bat' `
        --load-users 10 --load-seconds 30 --output ..\reports\phase16\load10.json
    if ($LASTEXITCODE -ne 0) { throw '10-user validation failed.' }
    & ..\.venv\Scripts\python.exe -m scripts.validate_system --count 10000 `
        --jmeter 'C:\Tools\apache-jmeter-5.6.3\bin\jmeter.bat' `
        --load-users 25 --load-seconds 60 --output ..\reports\phase16\load25.json
    if ($LASTEXITCODE -ne 0) { throw '25-user validation failed.' }
} finally { Pop-Location }
```

Run these sequentially. `--port` defaults to unused loopback port 18000; choose another if occupied. `--samples` defaults to 20 serial observations after one warm-up; `--db-pool-size` defaults to 5 for native PostgreSQL. The recorded embedded run used pool size 1 because its adapter has a single database backend. `TEST_DATABASE_URL`, when explicitly set, takes precedence over the application's configured connection for isolated validation; keep credentials out of command history and reports.

JMeter uses real loopback HTTP against a temporary FastAPI server and one temporary bearer identity shared by 10 or 25 virtual readers. Nine read endpoints cover overview, recent events, polling, incidents, findings, analytics overview/trend/rules and CSV reports. Each request has 100 ms think time, a 5-second ramp and an HTTP-200 assertion. The token is passed only in the child environment. CSV samples and a JMeter HTML report are written beside the result JSON; response bodies and authorization headers are not saved. This is a read-load smoke test, not a mixed-workload capacity or endurance test.

Serial API timings include application dispatch, database work and JSON/CSV serialization through TestClient. JMeter elapsed values include TCP HTTP. p95 uses nearest rank, `sorted_values[ceil(.95*n)-1]`; mean and median are separate statistics. Compare repeated runs on the same environment; do not compare these embedded measurements to a cloud SLA.

## Production build, Swagger and browser acceptance

Return to the production build after development verification:

```powershell
docker compose up --build -d --wait --wait-timeout 180
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Verify-Phase15.ps1
docker compose ps
Invoke-RestMethod http://localhost:8000/api/system/health
Invoke-RestMethod http://localhost:5173/api/system/ready
Start-Process http://localhost:5173
Start-Process http://localhost:5173/docs
```

Expected health `healthy`, readiness `ready`, three healthy containers, working login and authenticated pages. `/docs` is available when `API_DOCS_ENABLED=true`. Test the current detection, risk, incident, intelligence, AI, analytics and report routes using **your own login**. The validation runner also checks 88 unique OpenAPI operation IDs and anonymous denial on its read endpoints.

Browser acceptance needs one existing ADMIN, ANALYST and VIEWER account and at least one incident. It logs in/out, follows nine navigation pages, opens an incident deep link, and verifies `/admin` access/denial for each role. API authorization remains tested separately; hiding a route is not a security boundary.

```powershell
npm install --prefix .validation-tools playwright@1.63.0
& .\.validation-tools\node_modules\.bin\playwright.cmd install chromium
$env:PLAYWRIGHT_MODULE = (Resolve-Path .\.validation-tools\node_modules\playwright\index.mjs).Path
$env:CS_SMOKE_BASE_URL = 'http://localhost:5173'
try {
    foreach ($Role in @('ADMIN', 'ANALYST', 'VIEWER')) {
        $Credential = Get-Credential -Message "Existing CyberSentinel $Role account"
        if ($null -eq $Credential) { throw 'Credentials were not supplied.' }
        [Environment]::SetEnvironmentVariable("CS_SMOKE_${Role}_USERNAME", $Credential.UserName, 'Process')
        [Environment]::SetEnvironmentVariable("CS_SMOKE_${Role}_PASSWORD", $Credential.GetNetworkCredential().Password, 'Process')
    }
    node .\scripts\verify-browser.mjs
    if ($LASTEXITCODE -ne 0) { throw 'Browser acceptance failed.' }
} finally {
    $Credential = $null
    Get-ChildItem Env: | Where-Object { $_.Name -like 'CS_SMOKE_*' -or $_.Name -eq 'PLAYWRIGHT_MODULE' } | Remove-Item
}
```

Expected `Browser acceptance passed for ADMIN, ANALYST and VIEWER.` and empty error arrays in `browser-results.json`. Normal SPA navigation avoids spending a refresh request on every page. Explicit reloads still test Nginx fallback and cookie refresh. Leave authentication rate limits enabled. The sandbox-only `CS_SMOKE_NO_SANDBOX` override is not needed on a normal workstation.

## Native restart and restore gates

These commands require your local Docker environment. Stop concurrent ingestion/workflows while comparing counts. The restart test temporarily interrupts the local application, verifies database-down readiness 503, recovery and preserved business-table counts.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Verify-Phase15.ps1 -RestartServices
if ($LASTEXITCODE -ne 0) { throw 'Restart verification failed.' }
$Before = (docker compose exec -T backend python -m scripts.inspect_operations) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'Could not record source counts.' }
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Backup-Database.ps1 -OutputDirectory .\backups\phase16
if ($LASTEXITCODE -ne 0) { throw 'Backup failed.' }
$Backup = Get-ChildItem .\backups\phase16\*.dump | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$RestoreDb = 'cybersentinel_restore_' + (Get-Date -Format 'yyyyMMddHHmmss')
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Restore-Database.ps1 -BackupFile $Backup.FullName -TargetDatabase $RestoreDb
if ($LASTEXITCODE -ne 0) { throw 'Restore failed.' }
$After = (docker compose exec -T -e "POSTGRES_DB=$RestoreDb" backend python -m scripts.inspect_operations) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect restored database.' }
if (($Before | ConvertFrom-Json | ConvertTo-Json -Compress) -ne ($After | ConvertFrom-Json | ConvertTo-Json -Compress)) { throw 'Restored business-table counts differ.' }
docker compose exec -T -e "POSTGRES_DB=$RestoreDb" backend alembic current
```

The archive SHA-256 is checked by the restore script. It creates a **new** database and never overwrites the working database or changes `.env`. Equal counts are an initial recovery check, not proof of every value: inspect a representative populated case, linked findings, evidence, notes and audit records in the restored database before treating recovery as verified. Keep the restored database until that review is complete. Full native backup/restore execution remains an outstanding gate in the supplied results.

For this project's database username, inspect the existing database with:

```powershell
docker compose exec db psql -U cybersentinel -d cybersentinel
```

Use your actual `POSTGRES_USER`/`POSTGRES_DB` if changed. In psql:

```sql
\dt
SELECT version_num FROM alembic_version;
SELECT processed, count(*) FROM security_events GROUP BY processed;
SELECT r.rule_id, count(f.id) FROM detection_rules r
LEFT JOIN detection_findings f ON f.detection_rule_id=r.id
GROUP BY r.rule_id ORDER BY r.rule_id;
SELECT count(*) AS findings FROM detection_findings;
SELECT count(*) AS incidents FROM incidents;
\q
```

## Dependency and secret scans

Scanners are optional tools installed outside runtime requirements. From project root:

```powershell
py -3.12 -m venv .validation-tools\audit
& .\.validation-tools\audit\Scripts\python.exe -m pip install pip-audit==2.10.1 detect-secrets==1.5.0
& .\.validation-tools\audit\Scripts\python.exe -m pip_audit -r .\backend\requirements-dev.txt --no-deps --disable-pip
Push-Location .\frontend
try { npm audit; npm audit --omit=dev } finally { Pop-Location }
& .\.validation-tools\audit\Scripts\detect-secrets.exe scan --all-files --exclude-files '(^|/)(node_modules|\.venv|venv|\.validation-tools|dist|data|reports|backups|__pycache__|\.git)/|(^|/)\.env$|\.log$' > .\reports\phase16\secret-scan.json
```

Review every candidate in its source context; fixture passwords, canaries and the `password_spray` enum may be reported. Do not auto-suppress new findings or include actual `.env`, database backups or tokens in a shared report. The supplied scan inspected source files, not Git history (the provided project had no Git metadata). Dependency advisory results are dated snapshots and should be refreshed before deployment.

## Acceptance boundary

Pass only when test failures are zero, no relevant database tests were unexpectedly skipped, both isolated pipelines pass, browser errors are empty, load requests pass, and native operational/recovery checks have been recorded. The supplied report distinguishes completed embedded/runtime checks from those still requiring Docker Desktop and native PostgreSQL. No claim of complete native deployment verification is made.
