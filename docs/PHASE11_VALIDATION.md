# Phase 11 validation

## Environment and limits

Validation ran on 10 October 2026 using Python 3.12, Node 24, FastAPI/SQLAlchemy from the existing requirements, Chromium 153, and the real PostgreSQL 17.5 engine embedded by PGlite. A socket adapter connected the unmodified application models, migrations and SQL services. Adapter-only patches disabled psycopg pipeline/prepared-statement optimizations. Validation used an isolated schema and synthetic accounts; no development data was changed.

**Docker and PowerShell are unavailable in this execution environment.** Their commands and the new PowerShell verifier are supplied, but Phase 11 container startup and the PowerShell script must be verified on the Windows machine. Existing Dockerfiles, Compose, environment handling and host ports were preserved. A clean `npm ci` plus production build validated the frontend lockfile/install path. This is not a claim that the Docker daemon was tested here.

One native PostgreSQL concurrency test is skipped by the embedded adapter; run the existing isolated database test runner inside your PostgreSQL Compose environment to exercise that check. A pre-existing Starlette/httpx deprecation warning remains; no test fails because of it.

## Automated results

| Check | Actual result |
| --- | --- |
| Frontend Vitest / React Testing Library | **26 passed**, 2 files |
| Complete backend pytest regression | **646 passed**, 1 native-only concurrency skip, 0 failures |
| Added backend coverage | Recent/update previews preserve IPv6 destination and nullable destinations |
| Alembic from isolated empty schema | Upgrade to `0007_dashboard_polling` succeeds; `alembic check` reports no new operations |
| Production Vite build | Pass; page/chart code splitting; no large-chunk warning |
| Clean install from package-lock | `npm ci --no-audit --no-fund` and build pass |
| Python lint on changed files | Ruff passes |
| Windows Docker / PowerShell | Not executable in this runtime; local commands supplied |

Frontend coverage includes server-driven metrics, loading/partial errors/retry, malformed payloads, empty queue, range forwarding/navigation, filters/pagination, badges, per-user cache replacement, role controls, stale reputation, loss of health readiness on fetch failure, 401 refresh/expiry, 403 without logout, large cursors, deduplication, cursor drainage, the 500-row bound, clear/pause/resume/visibility/unmount behavior.

## End-to-end fixture

The existing generator produced 10,000 events with seed 42, mixed scenario, 95% normal traffic and a seven-day UTC interval starting 2026-10-04. The unchanged Phase 5 importer, Phase 6 detector, Phase 7 scorer, Phase 8 case processor and Phase 9 mock enrichment runner processed the file.

| Pipeline stage | Measured wall time |
| --- | ---: |
| Ingest | 7.251 s |
| Detect | 23.077 s |
| Risk | 0.126 s |
| Incidents | 0.954 s |
| Intelligence | 0.647 s |

Final base population: **10,000 events**, **36 findings**, **36 risk assessments**, **29 incidents**, **34 cached intelligence results**. All 10,000 events are processed; there are **0 invalid incident-evidence references**.

| Rule | Findings |
| --- | ---: |
| CS-001 | 5 |
| CS-002 | 2 |
| CS-003 | 4 |
| CS-004 | 3 |
| CS-005 | 3 |
| CS-006 | 3 |
| CS-007 | 7 |
| CS-008 | 5 |
| CS-009 | 4 |
| CS-010 | 0 |

These are synthetic development observations, not production accuracy or capacity estimates. The default mixed budget does not include abnormal API activity; CS-010 remains covered by existing rule tests and was not given invented findings.

## Browser and network checks

- Real UTC range queries update aggregates.
- 40 responsive page captures; no document overflow; mobile drawer Escape and focus return.
- Server-side HIGH/minimum-risk filter, page 2 offset, incident summary route.
- Single 5-second polling loop; pause/resume; 600 late logs drained; 500-row cap; clear preserves DB; unmount stops polling; admin toggle round trip.
- Explicit mocked-provider lookup; health failure removes old healthy cards.
- Viewer/Analyst controls, server 403 without logout, cookie refresh after reload, user-isolated cache, preferences-only Web Storage.

All **40** route/viewport combinations passed: 10 pages at **1366×768**, **1440×900**, **1920×1080**, and **390×844**. No document overflow, page errors, console warnings or unexpected API failures were recorded. Screenshots were inspected for layout, chart sizing, header placement and table overflow.

Measured development-server login + dashboard time: **3344 ms**. Median navigation/settle time across the 40 captures: **1327 ms** (maximum **2853 ms**). These include full navigation, auth refresh and a deliberate 180 ms settle wait, and are not production latency benchmarks.

The live feed issued **2** updates in **10.8 seconds**. The browser test then ingested **600** additional logs with old occurrence timestamps, drained cursor pages, retained exactly **500** rows, and cleared the view. PostgreSQL still contained **10,600** events; the added 600 were correctly pending detection. Automatic updates stopped after leaving the page.

Exact machine-readable results are included in [phase11_results.json](phase11_results.json). Build output has an approximately **311 KB** entry chunk (**99 KB gzip**) and a separately loaded **397 KB** chart chunk (**113 KB gzip**); these are measured bundle sizes, not invented performance claims.

Anonymous session bootstrap correctly returns HTTP 401 before a login cookie exists. Deliberate 403 permission probes and a mocked 503 health outage are expected test responses. They are separated from unexpected API failures; no unauthorized response is mislabeled as a healthy system. No auth token, password, cookie or provider secret is included in the shipped results.

Visual review found and fixed an inherited mobile `position: static` sidebar rule that reserved blank space above the header. Explicit accessible names were added to select filters. Shared charts/pages now use lazy bundles, avoiding the original single 824 KB application chunk. The existing origin guard correctly rejected the harness's non-default browser port until that exact local origin was configured in the harness; application CSRF/CORS protection was preserved.

## Reproduce

```powershell
# Existing project root, after merging files:
docker compose up --build -d --wait --wait-timeout 180
docker compose exec backend alembic upgrade head
docker compose exec frontend npm test
docker compose exec frontend npm run build
docker compose exec backend python -m scripts.run_database_tests
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Verify-Phase11.ps1
```

Follow [PHASE11.md](PHASE11.md) for the fresh synthetic pipeline, role checks and responsive acceptance steps. Native PostgreSQL results can differ in timing; Docker status is established by your local `docker compose ps`, not by these embedded measurements.
