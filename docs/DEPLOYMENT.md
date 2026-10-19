# Phase 18 — Render deployment

> **Scope update — 2026-10-19:** The project owner selected GitHub repository publication with local Docker execution. Render deployment is no longer part of the current task. Use [GITHUB.md](GITHUB.md). This guide preserves optional deployment preparation; it is not a required setup step or a live deployment record.

**Status: deployment preparation, not a completed live deployment.** The application changes and local checks are recorded in [PHASE18_VALIDATION.md](PHASE18_VALIDATION.md). No Render services, cloud database, public URL, production credentials, backup or live screenshot have been created. The connected account still requires explicit workspace confirmation, a Git repository containing this update, and approval of recurring hosting costs.

## Architecture and costs

The proposed `render.yaml` keeps the existing application containers. It defines one project, `cybersentinel`, with a `production` environment in Singapore. Confirm region and resource names before applying; do not attach an unrelated existing database.

| Resource | Configuration | Purpose |
| --- | --- | --- |
| `cybersentinel-web` | Docker web service, `0.5c-512mb`, one instance | Built React assets, Nginx, public HTTPS and same-origin `/api` proxy |
| `cybersentinel-api` | Docker private service, `0.5c-512mb`, one instance | FastAPI on port 8000; no public backend hostname |
| `cybersentinel-postgres` | Managed PostgreSQL 17, `0.1c-256mb`, 1 GB disk | Persistent relational data; private connections only |

Estimated base compute cost is **US$20/month**: two $7 services and a $6 database. Storage, bandwidth, workspace plans, temporary restore databases and taxes may add charges. Confirm the actual Dashboard estimate before creation. No custom domain, external AI, paid threat lookup, autoscaling, preview stack or background worker is enabled. Monitor disk usage; storage autoscaling is deliberately off. The small database is a starting point for a portfolio demo, not a verified capacity claim.

The browser connects over Render-managed HTTPS to Nginx. Nginx serves the production build and forwards `/api`, `/docs`, `/redoc` and `/openapi.json` to the private API over Render's private network. The API connects to managed PostgreSQL over TLS. The internal Nginx → API hop uses HTTP on that private network; it is not a claim of end-to-end TLS between every container. All browser-facing API traffic stays on the HTTPS frontend origin.

Same-region private networking is workspace-scoped. Project grouping alone does not provide tenant isolation from other services in that workspace. Use a dedicated trusted workspace, or the provider's environment isolation when available, if other operators run untrusted workloads.

## Configuration ownership

`render.yaml` owns service definitions and the declared environment keys. `PUBLIC_ORIGIN` is intentionally omitted until Render allocates the web hostname. Add it to the API through Dashboard **Environment → Save and deploy**. Blueprint sync preserves omitted keys. After a hostname change, update that one value and redeploy; do not maintain contradictory CORS settings elsewhere.

| Key | Where / value | Behavior |
| --- | --- | --- |
| `APP_ENV` | API: `production` | Secure refresh cookies; no reload/debug |
| `DATABASE_URL` | API: `fromDatabase.connectionString` | Internal URL; stored as a secret, normalized to `postgresql+psycopg` |
| `DATABASE_SSLMODE` | API: `require` | Render internal TLS; see connection note below |
| `EXPECTED_DATABASE_NAME` | API: `fromDatabase.database` | Release script refuses a different database |
| `JWT_SECRET_KEY` | API: `generateValue: true` | Render generates the production secret; no source value |
| `PUBLIC_ORIGIN` | API: exact allocated HTTPS origin, no final slash | Exact CORS/auth origin, allowed public Host, canonical HTTPS handling |
| `ALLOWED_HOSTS` | API: `localhost`, `127.0.0.1`, plus derived public host | Restricts Host; add an actual internal hostname only if a verified probe needs it |
| `PROXY_HEADERS_ENABLED` | API: `false` | Does not accept arbitrary forwarded client identities |
| `SERVER_PORT`, `SERVER_WORKERS` | API: `8000`, `1` | Existing production server command |
| `DB_POOL_SIZE`, `DB_MAX_OVERFLOW` | API: `3`, `2` | Up to five connections per API process; pre-ping remains enabled |
| `THREAT_INTELLIGENCE_MOCK_MODE` | API: `true` | Explicit synthetic reputation, no external lookup |
| `ABUSEIPDB_ENABLED`, `VIRUSTOTAL_ENABLED`, `OTX_ENABLED` | API: `false` | Provider integrations disabled |
| `AI_PROVIDER` | API: `fallback` | Existing deterministic analyst; no paid model |
| `API_DOCS_ENABLED` | API: `true` | Public schema/docs; operations still enforce authentication/RBAC |
| `BACKEND_UPSTREAM` | Web: `fromService.hostport` | Private API DNS and port; refreshed on Blueprint sync |
| `PORT`, `PUBLIC_SCHEME`, `NGINX_RESOLVER` | Web: `10000`, `https`, `auto` | Cloud listener, trusted deployment protocol, platform DNS |

Do not copy the local `.env` into Render. Never set a `VITE_` secret. The browser continues using relative `/api`; no frontend rebuild is required just to change the API's private hostname.

For provider URLs, `postgres://`, `postgresql://` and `postgresql+psycopg://` are accepted. Password encoding is preserved. Plaintext/ambiguous URLs and unsafe query overrides are rejected. Render documents a self-signed certificate on its internal database endpoint, so this manifest uses `sslmode=require` there. It encrypts traffic but does not authenticate the certificate hostname. For an external endpoint or a different provider with a trusted certificate, use `verify-full` with its required CA; the application will not silently weaken an explicitly stronger URL setting. Local Compose keeps the existing separate `POSTGRES_*` configuration.

`PUBLIC_ORIGIN` declares the protocol of this deployment. The API must remain private behind the HTTPS gateway. The middleware never derives its scheme from caller-supplied forwarding headers. Nginx replaces those headers, and Uvicorn proxy-header trust remains off. Consequently authentication IP limits see the gateway address and can be shared by multiple visitors. This conservative portfolio configuration does **not** provide verified end-user IP attribution or distributed rate limiting. Keep one API instance/worker; review a trusted proxy chain and shared limiting before scaling. AI/TI role checks and existing per-user controls remain enabled; external providers are off.

## Apply the update locally first — Windows PowerShell

Extract the update alongside your project and copy only the listed files from [PHASE18_FILES.md](PHASE18_FILES.md). Retain your `.env`, database volume and existing source. From the project root:

```powershell
docker compose up --build -d --wait --wait-timeout 180
if ($LASTEXITCODE -ne 0) { throw 'Container startup failed.' }
docker compose exec backend alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw 'Migration failed.' }
Invoke-RestMethod http://localhost:5173/api/system/ready
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Verify-Phase16.ps1
if ($LASTEXITCODE -ne 0) { throw 'Native local verification failed.' }
```

No new migration is introduced by this update. The latest revision remains `0008_ai_analyses`. Do not run `cloud_release` on the development environment: it deliberately requires production settings.

## Publish source and create the stack

1. Confirm the Render workspace and estimated recurring cost. Check whether any matching CyberSentinel services already exist; reuse only after inspecting them. This update is not permission to replace an existing deployment.
2. Put the complete, tested project in an accessible GitHub, GitLab or Bitbucket repository. This update ZIP contains changed files only, not a replacement for Phases 1–17. Do not publish `.env`, backup archives, account credentials or generated runtime data. Use the existing Git repository if you have one.
3. Review the repository status and commit only this update's source/configuration/documentation. If no remote is configured, create/select the repository first; do not paste a placeholder URL into a deployment command.

```powershell
git status --short
git diff --check
git remote -v
```

4. In Render, choose **New → Blueprint**, connect the actual repository/branch and select `render.yaml`. Review the resource preview, region, paid plan IDs and private database access. All three resources must use the same region. Apply only after reviewing the preview. The file passed the public JSON Schema; account-side Blueprint acceptance is still required. With an installed/authenticated Render CLI, also run `render blueprints validate render.yaml` before applying.
5. Wait for the database and builds. The backend's **pre-deploy command** is `python -m scripts.cloud_release --migrate`. It verifies the expected database, acquires a transaction-scoped PostgreSQL advisory lock, runs existing Alembic migrations and checks tables, columns, indexes, foreign keys and enum values. A failure stops that deployment. It does not seed accounts or demo data.
6. Copy the web service's **actual** HTTPS origin. On the API service add `PUBLIC_ORIGIN` with exactly that origin (no trailing slash), and choose **Save and deploy**. Until then, browser authentication is intentionally unavailable. Do not infer the URL from the resource name; Render may assign a different hostname.
7. Review the API release/startup logs and Render service status. The web check `/healthz` tests Nginx; a private service's platform check is not a database readiness guarantee. Verify the public `/api/system/ready` separately before sign-in or seeding.

Autodeploy is off. Manually deploy reviewed revisions of both containers. Database migrations are a release operation, not per-request or every-API-start work. For future schema changes, take a backup first, review compatibility with the currently running application and use an expand/contract change where needed. An advisory lock does not make an incompatible migration safe.

## Verify schema and initialize privately

Open the API service's interactive Shell in Render. The working directory is `/app/backend`:

```bash
python -m scripts.cloud_release
alembic current
python -m scripts.seed_detection_rules
python -m scripts.create_admin
```

Expected: release JSON `status: verified`, 17 domain tables, current Alembic head `0008_ai_analyses`; ten rules after idempotent seeding; administrator creation uses masked password prompts. Record the username privately. Do not publish an administrator password. Never use `seed_demo_users` against production or weaken its development-only guard.

Register private VIEWER accounts through the existing app as needed. An administrator can promote one to ANALYST through existing user administration. Keep all privileged credentials private. Public sharing of a viewer account is optional and separate from deployment; no default account is created by this Blueprint.

## Remote verification and synthetic population — PowerShell

These commands use the updated local backend container as an HTTPS client. They do not connect your local database to the cloud. Leave your local `.env` unchanged. Password prompts are masked; do not put a password in the command line.

```powershell
$cloudOrigin = Read-Host 'Paste the actual Render HTTPS origin without a trailing slash'
docker compose exec backend python -m scripts.verify_cloud --url "$cloudOrigin" --output data/cloud-public.json
if ($LASTEXITCODE -ne 0) { throw 'Public checks failed; inspect cloud configuration.' }

# Record this date and reuse it for any reviewed resume. Do not choose a future date.
$demoStart = (Get-Date).ToUniversalTime().Date.AddDays(-6).ToString('yyyy-MM-dd')
docker compose exec backend python -m scripts.populate_cloud_demo --url "$cloudOrigin" --start-date "$demoStart" --count 10000 --confirm-synthetic-demo --output data/cloud-demo.json
if ($LASTEXITCODE -ne 0) { throw 'Demo population incomplete; review logs before resuming.' }

# Each run prompts for the private account matching the requested role.
foreach ($role in @('ADMIN', 'ANALYST', 'VIEWER')) {
    docker compose exec backend python -m scripts.verify_cloud --url "$cloudOrigin" --role $role --output "data/cloud-$role.json"
    if ($LASTEXITCODE -ne 0) { throw "$role verification failed." }
}
New-Item -ItemType Directory -Force .\data\cloud-verification | Out-Null
docker compose cp backend:/app/backend/data/cloud-demo.json .\data\cloud-verification\cloud-demo.json
foreach ($name in @('public', 'ADMIN', 'ANALYST', 'VIEWER')) {
    docker compose cp "backend:/app/backend/data/cloud-$name.json" ".\data\cloud-verification\cloud-$name.json"
}
Start-Process "$cloudOrigin"
Start-Process "$cloudOrigin/docs"
```

The population script uses the existing seed-42 mixed generator and authenticated APIs: 500-event ingestion batches → detection → risk → incident processing → mock enrichment. It refuses a non-ADMIN account, live intelligence mode, missing/disabled rules, or a nonempty event database unless `--resume` is explicitly supplied. Resume only after reviewing an interrupted run, with the same date/count. There are no automatic network retries, restart-time seeding, provider calls or changes to development-only CLI guards. On a small plan, a server timeout may leave earlier committed batches; inspect results and unprocessed counts before retrying. Use `--count 1000` for a separately approved smaller demo if measured cloud limits require it.

`verify_cloud` measures its requests and checks HTTP→HTTPS, SPA shell routes, readiness, request IDs, Swagger/OpenAPI, protected routes, CORS, secure refresh-cookie flags, login/rotation/logout/revocation, and selected role permissions/report export. It is a bounded smoke check, not a load test or a complete browser acceptance test. Output files contain status/timings, not passwords, bearer tokens or response bodies. No `--insecure` TLS option exists.

## Complete live acceptance before calling Phase 18 finished

Record actual URLs, deploy IDs/Git revisions, timestamps, results and limitations in a private release record. Existing application/OpenAPI version `0.15.0` is retained; it identifies the application, not this particular Git deployment. Record the deployed commit separately. Do not invent a `v1.0.0` release.

| Check | Evidence to collect |
| --- | --- |
| Infrastructure | Three actual resource IDs, healthy status, private PG access, TLS connection, current schema |
| Auth/RBAC | All three role reports; expired access token rejected after its real lifetime; refresh/logout behavior |
| Dashboard | Chromium login, populated seven-day charts/events/incidents, date filters, polling, no console errors |
| Investigation | Open a real synthetic case; refresh its deep link; inspect risk, evidence, timeline, intelligence; analyst comment/assignment/status changes and audit history |
| AI | Run one fallback analysis and one supported question; verify references against case evidence and FALLBACK label |
| Intelligence | MOCK label, cached response and incident enrichment; do not label synthetic data live |
| Analytics/reports | Executive/risk/detection/backlog/intelligence views; download a CSV for the chosen period, inspect content and formula protection |
| Browser/security | No mixed content or exposed secrets; authenticated controls; smaller-screen navigation; frontend assets and HTTP redirect |
| Logs/monitoring | Request IDs correlate; startup/errors sanitized; review CPU, memory, DB usage, restarts and plan retention |
| Recovery | Cloud backup created and a separate restore test recorded; no live overwrite |
| Portfolio | Only after these pass: actual live link, cloud screenshots, 3–5 minute demo and deployment resume wording |

The existing test suite covers simulated provider failures and denied actions. Do not break a live provider or stop the production database to create a screenshot. With providers disabled, live-provider behavior has not been verified. Browser rendering, real network TLS, managed backup recovery and instance sizing require actual cloud evidence, not local TestClient results.

## Database inspection

Use the provider's private database console/CLI from an authorized environment. Do not make PostgreSQL public solely for inspection. These read-only queries are suitable for the connected database:

```sql
SELECT current_database(), version();
SELECT version_num FROM alembic_version;
SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;
SELECT rule_id, name, enabled FROM detection_rules ORDER BY rule_id;
SELECT processed, count(*) FROM security_events GROUP BY processed;
SELECT 'events' AS kind, count(*) FROM security_events
UNION ALL SELECT 'findings', count(*) FROM detection_findings
UNION ALL SELECT 'risk assessments', count(*) FROM risk_assessments
UNION ALL SELECT 'incidents', count(*) FROM incidents;
SELECT r.rule_id, count(*) FROM detection_findings f
JOIN detection_rules r ON r.id = f.detection_rule_id
GROUP BY r.rule_id ORDER BY r.rule_id;
```

## Backups, separate restore and rollback

Paid Render PostgreSQL provides continuous backup/PITR. Current documented recovery windows depend on workspace plan: Hobby three days, Pro or higher seven days. Verify the actual database's Recovery page and earliest recovery time. After successful demo population, create a **logical export** there and record completion, size and date privately. Provider exports are retained for seven days; download an export to private storage if longer retention is needed. Backups contain password hashes and other sensitive records and must not go into Git or the public frontend.

For manual logical backups, retain the Phase 15 principle: use PostgreSQL 17 `pg_dump`, custom format, then `pg_restore --list` to check archive readability. Existing `Backup-Database.ps1` / `Restore-Database.ps1` target the **local Compose database**, not the managed deployment. Do not claim that running them backed up Render.

A manual cloud dump requires an authorized host with PostgreSQL client tools and connectivity. Prefer an approved one-off private-network environment. If external access is unavoidable, temporarily allow only the operator's exact IP, use the provider's external hostname and certificate-validated TLS, then restore the original allowlist. Never allow `0.0.0.0/0`. With the reviewed connection fields supplied privately through `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGSSLMODE=verify-full` and the required CA setting:

```powershell
# pg_dump prompts for the database password; do not put a URL/password in arguments.
$backupFile = Join-Path (Get-Location) ('cybersentinel-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.dump')
pg_dump --password --format=custom --no-owner --no-acl --file "$backupFile"
if ($LASTEXITCODE -ne 0) { throw 'Backup failed.' }
pg_restore --list "$backupFile" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Archive cannot be read.' }
Get-FileHash "$backupFile" -Algorithm SHA256
```

Inspecting the archive is **not** a restore test. Restore only to a newly created, empty, explicitly confirmed temporary database. Reconfigure the connection variables for that target and confirm its identity first with `psql --password -c 'SELECT current_database();'`. Then use `pg_restore --password --no-owner --no-acl --exit-on-error --dbname "$env:PGDATABASE" "$backupFile"`. Do not use `--clean` against the live database. Compare schema revision, table counts and evidence relationships on the restored target; preferably run read-only application smoke checks against it. Record actual results before asserting recovery works. Additional managed restore resources incur cost and need review; remove only the temporary resources you created after verification.

For application rollback, redeploy the recorded previous successful Git revision/container in Render and verify readiness/authentication again. Do not automatically run `alembic downgrade`. Check that the prior code supports the current schema; otherwise use a forward fix or a separately reviewed restoration plan. A rollback does not undo database writes. Preserve the current database and a fresh backup while investigating.

## Monitoring and common failures

Use Render CPU/memory/restart/deploy graphs, database storage/connections and structured INFO logs. Keep platform default log retention unless a specific plan requirement is approved; no retention change has been made here. A lightweight external readiness monitor is optional and not provisioned. Do not run JMeter against the public service by default.

| Symptom | Check |
| --- | --- |
| Web healthy but API 502 | API deployment/startup, private hostname/port, same workspace/region and Nginx DNS resolution |
| API 400 | Exact `PUBLIC_ORIGIN`/Host; never fix by allowing `*` |
| Login/refresh 403 | Origin without trailing slash, API redeployed after environment update, `X-CSRF-Guard`, HTTPS |
| Login 429 | Existing rate limit; gateway IP is shared. Wait for its real window; do not disable limits to hide it |
| Readiness 503 | PostgreSQL connectivity, migrations, release logs, target database, pool limits |
| Provider unavailable | Expected mock/fallback status; do not add keys just to make a green indicator |
| Failed migration | Correct database identity, TLS requirements, current migration head and release lock; do not reset the DB |
| Seed interrupted | Inspect committed counts and logs, then deliberate resume with the identical date/count |
| Memory/time limit | Measure first; reduce demo workload or review a plan change. Do not claim local timing is cloud capacity |

Official references reviewed on 2026-10-18: [Blueprints](https://render.com/docs/blueprint-spec), [compute plans](https://render.com/docs/compute-plans), [pricing](https://render.com/pricing), [private networking](https://render.com/docs/private-network), [environment variables](https://render.com/docs/configure-environment-variables), [PostgreSQL connections](https://render.com/docs/postgresql-creating-connecting), [backup/recovery](https://render.com/docs/postgresql-backups). Recheck provider acceptance and pricing at creation.
