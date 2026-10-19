# Phase 16 — Executed validation results

**Measured 17 October 2026. The checks available in this environment passed. Native Docker/Desktop, independent PostgreSQL writer concurrency and full native archive recovery remain pending; Phase 16 is not claimed as fully verified on those targets.**

Phases 1–15 are preserved. No database model, migration, API contract, detection rule, risk policy, incident workflow or production service was changed. New test/validation tooling exercises the existing application. The frontend lockfile contains one dependency patch. See [TESTING.md](TESTING.md) for reproducible Windows and Docker commands.

## Test results

| Check | Actual result |
| --- | --- |
| Backend pytest | 799 passed, 1 skipped, 0 failed; 58.59 seconds |
| Skipped case | Native independent-writer polling concurrency; embedded PostgreSQL has one backend |
| Frontend Vitest | 86 passed across 7 files; 4.07 seconds |
| Vite production build | Passed |
| Ruff | All checks passed |
| PostgreSQL migrations | Fresh schema → head, populated `upgrade head`, and Alembic metadata check passed |
| Swagger/OpenAPI | `/docs` and readiness returned 200; 88 unique operation IDs |
| Compose | Default and development configurations parsed; no Docker daemon available |
| PowerShell | New verifier parsed with PowerShell 7.5.4; Windows 5.1 execution pending |
| Browser | Chromium 153 + Nginx 1.30 + real FastAPI; ADMIN, ANALYST and VIEWER passed |

Backend tests use PostgreSQL JSONB/enums/constraints through PGlite PostgreSQL 17.5 and its TCP adapter, not SQLite. The adapter requires disabled psycopg pipeline/prepared execution and a single pooled connection for HTTP/load checks. Those overrides are local validation-harness details, not production connection changes. Native PostgreSQL 17/Docker must run the supplied verifier before closing the remaining gate.

The one warning is Starlette’s deprecation of its current httpx TestClient adapter. It does not fail the suite; changing that dependency stack is outside this targeted validation update. No coverage-percentage claim is made.

## End-to-end pipelines

Seed 42, mixed scenarios, 95% normal traffic, seven days starting 2026-10-10 UTC. Each run used its own temporary schema, real migrations, temporary users and JSONL ingestion. Intelligence was local mock; AI was deterministic fallback; no external providers were called.

| Measure | 1,000 events | 10,000 events |
| --- | ---: | ---: |
| Generation (ms) | 104.416 | 1,054.241 |
| Ingestion (ms) | 496.522 | 5,500.269 |
| Detection (ms) | 364.888 | 13,663.183 |
| Risk assessment (ms) | 143.448 | 93.118 |
| Incident promotion (ms) | 134.589 | 519.477 |
| Mock enrichment (ms) | 71.904 | 281.401 |
| One incident AI fallback (ms) | 228.767 | 131.826 |
| Ingestion events/sec | 2,014.01 | 1,818.09 |
| Detection events/sec | 2,740.57 | 731.89 |
| Stored events | 1,000 | 10,000 |
| Findings | 6 | 36 |
| Risk assessments | 6 | 36 |
| Incidents | 5 | 29 |
| Incident evidence links | 17 | 160 |
| Unprocessed events | 0 | 0 |
| Enabled rules executed | 10 | 10 |
| Replay-created findings / assessments / incidents | 0 / 0 / 0 | 0 / 0 / 0 |

Reimporting produced 1,000 and 10,000 duplicates respectively, with zero inserts. Detection replay skipped 6 and 36 existing findings. All business-row counts stayed unchanged on repeat processing. Raw security-event hashes were unchanged, excluding only `processed`. Finding/evidence/assessment reference checks, duplicate checks and score-bound checks all returned zero violations. Detection itself created zero incidents; the later promotion service created them.

The pipeline also assigned a case to an analyst, transitioned it to INVESTIGATING, added a note, generated grounded fallback analysis and resolved the case. Analytics exactly matched the seeded event/case counts. These synthetic response durations are validation timings, not analyst effectiveness measures.

## Rule distribution and synthetic evaluation

| Rule | Findings in 10,000-event run |
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

The 10,000-event run covered 36 of 37 expected labelled (rule, scenario) pairs: scenario recall 97.30%, zero unexpected findings and finding-label agreement 100%. The 1,000-event run covered 6 of 6. Precision is deliberately null: labels and retained evidence cannot establish true false positives. None of these synthetic metrics measures real-world accuracy.

The mixed generator’s 500-event suspicious budget omitted an abnormal-API episode, so CS-010 executed but produced no finding. Its positive behavior and below/equal/above threshold are covered by dedicated rule tests. The generator also included an eight-event ACCESS_DENIED episode below the existing seeded CS-009 threshold of ten; the other four denial episodes yielded four findings. Thresholds were preserved rather than adjusted to make synthetic label coverage 100%.

## Serial API measurements

Twenty observations per endpoint after one warm-up, on the 10,000-event schema. TestClient includes serialization. All responses were HTTP 200; anonymous requests to the measured collection/report endpoints returned 401. The seven-day filters ensure event-based views query populated data.

| Endpoint | Mean ms | Median ms | p95 ms | Response bytes |
| --- | ---: | ---: | ---: | ---: |
| `/api/dashboard/overview?range=7d` | 21.329 | 21.081 | 24.744 | 436 |
| `/api/dashboard/events/recent?range=7d` | 9.484 | 6.961 | 16.216 | 6,748 |
| `/api/dashboard/events/updates?after_id=0&limit=20` | 6.550 | 6.287 | 8.022 | 6,725 |
| `/api/incidents?limit=20` | 8.078 | 7.970 | 9.087 | 18,078 |
| `/api/detections?limit=20` | 9.323 | 9.029 | 11.214 | 50,104 |
| `/api/analytics/overview?range=7d` | 36.636 | 36.583 | 40.302 | 961 |
| `/api/analytics/events/trend?range=7d` | 18.284 | 17.741 | 21.530 | 1,504 |
| `/api/analytics/detections/rules?range=7d` | 9.215 | 8.883 | 11.050 | 3,016 |
| `/api/reports/incidents?format=csv&range=7d&limit=100` | 5.567 | 5.540 | 6.015 | 6,825 |
| `/api/reports/security-summary?range=7d` | 70.577 | 69.620 | 75.301 | 30,949 |
| `/api/incidents/{incident_id}` | 24.218 | 23.252 | 30.029 | 9,182 |

## JMeter read-load measurements

JMeter 5.6.3/Java 17, loopback Uvicorn HTTP, 10,000 events, nine read endpoints, one temporary authenticated identity, 100 ms think time/request and 5-second ramp. Each sample asserts HTTP 200. Runs were sequential. The single-backend database adapter and pool size 1 mean these results do not validate native database writer concurrency, multiple API workers or a production capacity target.

| Virtual readers | Scheduled duration | Samples | Errors | Measured request interval | Requests/sec | Mean ms | Median ms | p95 ms |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | 30 s | 2,027 | 0 | 29.363 s | 69.032 | 36.035 | 32.0 | 77.0 |
| 25 | 60 s | 4,956 | 0 | 59.615 s | 83.133 | 190.219 | 179.0 | 337.0 |

Measured interval runs from the first request start to the last request completion; it excludes pre-request JMeter startup. Throughput uses that interval. Latency p95 is calculated from samples, not from averaging endpoint percentiles.

| Endpoint | 10 users mean / median / p95 ms | 25 users mean / median / p95 ms |
| --- | ---: | ---: |
| Analytics overview | 55.240 / 46.0 / 104.0 | 209.073 / 196.0 / 359.0 |
| CSV report | 28.638 / 24.0 / 60.0 | 190.297 / 176.0 / 349.0 |
| Event polling | 39.925 / 37.0 / 79.0 | 187.005 / 176.0 / 329.0 |
| Event trend | 28.955 / 21.0 / 61.0 | 186.159 / 176.0 / 330.0 |
| Findings | 36.951 / 32.0 / 75.0 | 188.397 / 180.5 / 327.0 |
| Incidents | 32.947 / 27.0 / 74.0 | 186.117 / 175.0 / 326.0 |
| Overview | 48.341 / 46.0 / 82.0 | 193.499 / 181.0 / 343.0 |
| Recent events | 21.316 / 14.0 / 58.0 | 181.766 / 172.0 / 328.0 |
| Rule analytics | 31.685 / 29.0 / 62.0 | 189.871 / 179.0 / 341.0 |

Raw timing samples are supplied in [phase16-load10.csv](performance/phase16-load10.csv) and [phase16-load25.csv](performance/phase16-load25.csv). They contain status/timing metadata and loopback URLs, without request authorization headers or response bodies. The reusable runner also generates a local JMeter HTML report.

## Query behavior and browser acceptance

`test_query_bounds.py` grows one incident from 1 to 56 findings and adds 60 comments, clearing the ORM identity map before each read. It asserts query count grows by at most two and stays below 30; response collections remain capped at 20 findings/20 comments/50 evidence records. Two paginated event requests return 56 unique events. The analytics fixture separately verifies that 3 findings × 2 assessments × 4 notes do not multiply a single case count.

`EXPLAIN (ANALYZE, BUFFERS)` for the event-type aggregate used the existing timestamp index plus bitmap heap scan and hash aggregate. It returned 15 event types; execution was 15.314 ms with no temporary disk blocks. This is one recorded plan, not a claim that every query is optimal. No speculative indexes were added.

Browser acceptance passed nine navigation pages, incident investigation and the administrator route for each of three roles. ADMIN could access user administration; ANALYST and VIEWER saw the access-denied state. Login, refresh across explicit deep links and logout worked. Page exceptions, CSP violations and unexpected API-error arrays were all empty. Mutation paths and detailed error/empty/polling behavior are covered by the component and API suites.

## Security verification and fixes

- Cross-module RBAC tests prove unauthenticated and VIEWER requests are rejected before INSERT/UPDATE/DELETE on 13 write endpoints. Existing JWTs immediately lose permissions after a database role downgrade; inactive accounts are rejected. SQL-like username filters remain literal and return no matching rows.
- New browser-component tests cover protected deep links, loading/error retry, administrator-only routing and escaped user text. Axios tests cover 404/422/429/500/503 and network failures without inappropriate authentication retries.
- `pip-audit` 2.10.1 inspected 38 resolved Python packages from the development requirements on this platform: zero known vulnerabilities returned. Windows-only conditional packages must be checked on Windows.
- The first npm scan found the high-severity development dependency advisory [GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q), an indexed-source-map denial of service. The lockfile now resolves `source-map-js` 1.2.2; the final full npm audit returned zero vulnerabilities. Frontend tests and production build passed after that patch.
- `detect-secrets` 1.5.0 reported 16 candidates. Source review identified scenario/event names, test-only credentials, invalid-hash fixtures and explicit logging/schema canaries. No live credential was identified. The provided source had no Git history, so historical secret scanning was not performed.

## Issues encountered

| Issue | Resolution / status |
| --- | --- |
| Production-route test returned 400 instead of expected 404 | Its TestClient used `testserver`, disallowed by existing TrustedHost protection. Changed only the fixture base URL to trusted `https://localhost`; protection retained. |
| Browser smoke exhausted refresh rate limit | Replaced repeated full-page navigation with SPA links, retaining explicit deep-link reloads. Rate limits remain enabled. |
| Initial load-plan header was not applied | Corrected the JMeter HeaderManager GUI class to `HeaderPanel`; successful runs then authenticated every sample. Failed setup runs are excluded from successful benchmark statistics. |
| Browser runtime failed to launch | Local cached Chromium executable was truncated. Re-extracted the complete runtime and reran successfully; no application change. |
| Backend TestClient deprecation | Warning recorded; no unrelated dependency-stack migration. |
| Native backup/restore unavailable | Earlier native-client restore against the embedded adapter failed during COPY handling. No restore pass is claimed; use native PostgreSQL and the supplied recovery commands. |

## Remaining completion gates

1. Execute `Verify-Phase16.ps1` on Docker Desktop/native PostgreSQL and confirm the independent-writer test runs instead of skipping.
2. Execute the production-image smoke and restart/database-outage recovery checks; confirm health and business-row persistence.
3. Create and checksum a real PostgreSQL archive, restore it to a new database, compare counts and inspect representative case/evidence/audit data.
4. Run browser acceptance and JMeter on that native setup if native performance is required. The supplied Linux/embedded timings cannot stand in for those measurements.
5. Record Windows PowerShell 5.1 execution. Parsing in PowerShell 7 is not equivalent to running the commands on Windows.

Live external intelligence/LLM calls, public deployment, cloud scaling and endurance testing were intentionally not performed. Their mocked contracts and deterministic fallback paths were tested. Phase 17 and Phase 18 have not started.
