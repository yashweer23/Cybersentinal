# Phase 15 — Executed validation and remaining local checks

Validation date: **2026-10-16**. This is operational smoke verification, not the Phase 16 security/regression matrix. No cloud deployment or live threat/AI provider request was performed.

## Executed successfully

| Check | Actual result |
| --- | --- |
| Backend focused tests | **68 passed**, 16.86 seconds: `test_operations.py`, `test_health.py`, `test_config.py`, `test_auth_api.py`. One existing Starlette/httpx deprecation warning; no dependency upgrade made. |
| Frontend focused tests | **5 passed** across operational recovery and existing API-client tests. |
| Production frontend build | `npm run build` succeeded; 2,620 modules transformed. Exact package-lock dependency versions preserved. |
| Python lint | Ruff passed for changed operational Python files; existing protected business logic was not edited. |
| Compose parsing/merge | Real Docker Compose **2.39.4** parsed both default and development configurations with isolated fixture environment values. Production database has no host port; development maps loopback 15432 → 5432. Project/volume identity retained. This is config validation, not container execution. |
| Nginx syntax and serving | Native **Nginx 1.30.0** compiled and tested the supplied template; it served the actual production bundle and proxied the actual FastAPI application. Only validation paths, loopback ports/upstream, and process identity were adapted to this sandbox. |
| Browser | Headless Chromium: login, overview, analytics, System Health and incident-list navigation passed; direct SPA deep-link refresh worked; **zero browser errors, zero CSP violations, zero unexpected API failures**. |
| Proxy behavior | API unknown route returned JSON 404; missing asset returned 404; `/docs` loaded without the SPA CSP; `X-Request-ID` returned correctly. |
| OpenAPI | **88 unique operation IDs** with prior routers preserved and migration-readiness route added. No duplicate IDs. |
| Clean schema | All **eight existing Alembic revisions** upgraded a clean embedded PostgreSQL database; readiness moved from 503/pending to 200/current. `alembic check` found no drift. |
| Existing populated schema | Reapplying `upgrade head` and checking metadata preserved row counts and row-content digests across all 18 tables. No Phase 15 migration is required. |
| PostgreSQL outage/recovery | Closed/reopened the embedded database and its socket listener with actual disk storage; liveness stayed 200, readiness became 503, and the existing SQLAlchemy connection pool recovered without rebuilding the app. |
| Backend stop/start | Actual Uvicorn lifespan stopped and disposed its pool, restarted, and accepted login and authenticated dashboard reads through the still-running Nginx proxy. |
| Persistence | Business-table counts/content digests survived the embedded database and backend restarts. Auth-session/audit additions and user last-login changes were expected login side effects; user count was preserved. |
| PostgreSQL backup | Native **pg_dump 17.11**, custom archive, `--no-owner --no-acl`: exit 0. `pg_restore --list` accepted the archive. No backup is included in the deliverable. |
| PowerShell | PowerShell **7.5.4** parsed the new scripts. A clearly isolated Docker-command stub checked binary file copying with spaces in paths, SHA-256 verification, existing-target failure, checksum rejection before restore, and native-stderr/exit-code handling. These are wrapper contract checks, not actual Docker backups/restores. |
| Shell scripts | `sh -n` passed for database-maintenance and frontend entrypoint scripts. |
| Compatibility | SHA-256 comparison against the saved Phase 14 baseline confirmed **105 business-logic/model/auth/migration files unchanged**. No baseline file was deleted. Python requirement locks are byte-identical; frontend manifest/lock dependencies remain synchronized. |

The embedded backend was **PGlite PostgreSQL 17.5** with a serialized local socket adapter. Validation disabled Psycopg prepared/pipeline behavior only in that adapter harness, and used a one-connection pool for the adapter's single-connection constraint. Application source keeps the native PostgreSQL driver and normal configurable pool. Native Nginx ran under the available sandbox identity with a single-process validation configuration; this does not verify Docker user 101, Linux capabilities or container mounts.

## Preserved workflow fixture

A fresh, isolated **1,000-event** dataset (`seed=42`, `mixed`) passed through the existing generator, ingestion, detection, risk, incident and mock-intelligence CLIs. One analyst note and one deterministic AI analysis were added to exercise persistence of later-phase objects. This is a compatibility fixture, not a new accuracy or performance benchmark.

| Stored object | Count before browser/login checks |
| --- | ---: |
| Security events | 1,000 |
| Detection rules | 10 |
| Detection findings | 6 |
| Risk assessments | 6 |
| Incidents | 5 |
| Incident evidence | 17 |
| Incident-finding links | 5 |
| Incident processing records | 6 |
| Analyst comments | 1 |
| Legacy intelligence cache | 8 |
| Provider-result cache | 8 |
| AI analyses | 1 |
| Users | 1 |
| Audit records | 14 |
| System metrics | 20 |

The browser's selected 24-hour range may show fewer events than the whole 1,000-event database. It filters timestamps; this is not missing data. Counts are actual output of this small smoke fixture, not targets or expected production rates.

## Restore limitation — not passed

Native `pg_restore --single-transaction --exit-on-error` was attempted against a separate empty PGlite instance. It reached data import and failed when the adapter handled PostgreSQL `COPY ... FROM stdin`; the embedded WebAssembly process reported `RuntimeError: unreachable`. Therefore **a complete restored database was not verified here**. The archive was successfully created/listed, and the restore script uses standard native PostgreSQL commands, but the Docker PostgreSQL restore must still be run locally.

No application code was changed to hide this adapter limitation, no restore success was fabricated, and the working application database was never targeted. The Windows guide provides a restore into a new database and inspection queries. A successful local restore is still a release gate.

## Checks not executable in this workspace

There is no Docker daemon or native PostgreSQL service here. Consequently the following remain **unverified**, not implied by the component checks above:

- Docker image build / clean `build --no-cache` and image startup.
- Actual non-root container users, read-only mount permissions and volume copy-up ownership.
- Docker DNS refresh when an upstream container gets a new address.
- Clean and existing **Docker-volume** startup, whole-stack restart and Docker-volume persistence.
- Full native PostgreSQL backup/restore through Docker.
- Windows PowerShell **5.1** execution and Windows Docker Desktop behavior.
- Docker Scout/image vulnerability scans, cloud TLS/forwarded-header deployment and production scaling.

Use `scripts/Verify-Phase15.ps1 -RestartServices`, the clean-project instructions, and the backup/restore commands in [PHASE15.md](PHASE15.md) on Docker Desktop. Do not replace these required checks with the embedded results. Existing phase validation reports remain historical evidence; their full suites were not rerun as part of Phase 15.

## Issues encountered and resolutions

1. Windows PowerShell may interpret native stderr progress as `NativeCommandError`. The shared Compose helper uses the native exit code as the success criterion and preserves stderr text without treating successful output as failure.
2. PowerShell text redirection can damage custom-format dumps. The backup script writes inside PostgreSQL and uses `docker compose cp`; the binary hash remained unchanged in wrapper checks.
3. A fresh database is connectable before tables exist. A separate migration-aware `/api/system/ready` now reports that distinction; Docker uses process liveness so operators can run explicit migrations.
4. A proposed dashboard smoke URL was outdated. The script now calls the existing `/api/dashboard/overview`; the application route was preserved.
5. Exact user-row equality across login was an invalid test assertion because `last_login` changes intentionally. Persistence checks compare business content and user counts, excluding expected authentication side effects.
6. The sandbox cannot change process ownership or run a native PostgreSQL daemon. Nginx validation used local paths/current identity; PostgreSQL checks used the existing isolated embedded adapter. These adaptations were confined to validation tooling.
7. Native restore exposed the embedded COPY limitation described above. It remains explicitly unverified on Docker rather than being marked as passed.

## User-facing checks after applying the update

```powershell
docker compose up --build -d --wait --wait-timeout 180
docker compose exec backend alembic upgrade head
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Verify-Phase15.ps1 -RestartServices
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Backup-Database.ps1
```

Then restore the new archive into a fresh database as documented, inspect the tables/counts and verify the application still uses its original database. Preserve `.env` and named volumes. Phase 15 implementation is supplied; native Docker completion depends on those local results.
