# Phase 2 validation

Validated during the 25 September 2026 delivery. Phase 1 source files were inspected before extending the project, and a SHA-256 baseline was retained for change review.

| Check | Result | What it establishes |
| --- | --- | --- |
| Full pytest suite | **66 passed** | 34 unit checks and 32 database integration checks, including original Phase 1 regression tests |
| PostgreSQL schema | **Passed** | Nine application tables plus Alembic version table; UUID, INET, JSONB, TIMESTAMPTZ, four native enums, constraints and indexes |
| Alembic | **Passed** | Upgrade, repeated upgrade, no model drift, downgrade to base, clean re-upgrade; explicit enum lifecycle |
| Event/rule/incident creation | **Passed** | Real PostgreSQL inserts and relationship reads through SQLAlchemy/Psycopg |
| Constraints | **Passed** | Score/port ranges, JSON shape, enum validation, unique business identifiers, missing foreign keys |
| Deletion rules | **Passed** | Incident deletion retains events; referenced events/rules cannot be removed; user deletion retains comments, incidents and audit rows |
| Timestamps and metric metadata | **Passed** | Timezone-aware round trip, update triggers, reserved-name schema mapping |
| Rule seed | **Passed** | First run inserts ten; second inserts zero; existing edits preserved |
| Demo user seed | **Passed** | First inserts three; second inserts zero; bcrypt verification, hash redaction, conflict rejection and production refusal |
| Cache repository | **Passed** | Canonical IP/domain identity, atomic upsert, first-seen preservation, stale-response protection and expiry |
| Unit tests without DB URL | **Passed: 34; skipped: 32** | Skips are explicit; a unit-only run is not reported as database validation |
| Test runner safety | **Passed with controlled engine/process substitutes** | Does not drop a database if creation fails; cleans only its generated name after a failing test run; refuses production before connecting |
| Live Uvicorn HTTP | **Passed** | Actual requests to `/api/system/health`, `/api/database/status`, `/api/detection-rules`, `/docs`, and `/openapi.json` returned 200 against the migrated/seeded database |
| Live Vite proxy | **Passed** | Frontend HTML and proxied health, database status, ten rules, and documentation returned 200 |
| Ruff | **Passed** | Python static checks across backend source, migration, scripts, and tests |
| Phase 1 compatibility | **Preserved** | Compose, both Dockerfiles, frontend sources/lockfile, `.env.example`, original settings/engine/session code, and original PowerShell scripts remain byte-for-byte unchanged |
| Docker image build / Compose boot | **Not executed here** | Docker is not installed in the build workspace |
| Windows PowerShell scripts | **Not executed here** | Windows/PowerShell runtime is unavailable; scripts were reviewed and exact local acceptance commands are supplied |
| Native test database create/drop | **Not executed here end to end** | Requires a normal multi-database PostgreSQL server; safety control flow is unit-tested |

## PostgreSQL test environment and limits

The database checks used **PostgreSQL 17.5 compiled to WebAssembly**, provided by `@electric-sql/pglite@0.3.15` and `@electric-sql/pglite-socket@0.0.20`, over TCP through the project's SQLAlchemy 2 / Psycopg 3 stack. This exercised PostgreSQL SQL behavior; it was not SQLite or a database mock. Database fixtures created isolated schemas and ran the actual Alembic revision.

The embedded socket implementation shares one PostgreSQL backend between connections. The validation harness disabled Psycopg's automatic prepared-statement cache to avoid name collisions across those connections; server-side parameter binding remained in use. **That harness setting is not applied to application code, shipped fixtures, requirements, or Docker.** Normal PostgreSQL gives connections separate backend sessions. The full suite and live checks passed with the embedded fixture. This does not establish Docker Desktop startup, native PostgreSQL authentication/network behavior, concurrency performance, or the test runner's real database-creation permissions.

A native PostgreSQL helper was attempted but could not create its required non-root OS user in this workspace. No permission restrictions were bypassed. The embedded fixture is only a build-workspace test tool; the delivered application continues to use the original PostgreSQL 17 Docker service.

One non-failing upstream Starlette warning remains about the Phase 1 `httpx` TestClient dependency. Existing dependency pins were preserved; no unrelated framework upgrade was introduced. Alembic's path-separator warning was resolved by adding `path_separator = os` to its configuration.

## Required Windows acceptance

After merging the update into the existing project, run from its root:

```powershell
docker compose up --build -d --wait --wait-timeout 180
docker compose exec backend alembic upgrade head
docker compose exec backend python -m scripts.seed_detection_rules
docker compose exec backend python -m scripts.seed_demo_users
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Verify-Phase2.ps1
docker compose exec backend python -m scripts.run_database_tests
docker compose exec backend alembic check
docker compose ps
```

Expected: all three services healthy, schema `0001_core`, ten rule definitions, three development users, all HTTP checks passing, all 66 tests passing on the native PostgreSQL container, and no pending migration changes. Inspect the frontend and Swagger page in your browser as well. These are expected local outcomes, not a claim that Windows/Docker was executed in this workspace.

See [PHASE2.md](PHASE2.md) for installation, exact file placement, expected responses, direct SQL inspection, native Python alternatives, and troubleshooting.
