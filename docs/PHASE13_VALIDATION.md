# Phase 13 validation report

Phase 13 implementation is complete. The application, migration, tests and browser workflow were exercised in the available runtime. Native Windows/Docker execution and a live LLM request remain environment-specific verification gates; this report does not claim they passed.

## Environment and scope

- Real FastAPI, SQLAlchemy, psycopg, React/Vite and Chromium were used.
- PostgreSQL behavior was exercised through PGlite PostgreSQL 17.5 with a local socket adapter in an isolated schema. The adapter was a validation aid, not an application dependency or Docker replacement.
- No developer database was reset. Temporary validation schemas and credentials were removed by the harness.
- External threat intelligence used the existing explicitly labelled mock mode. AI used deterministic fallback and mocked HTTP provider responses; no real API credentials were used.
- Docker, PowerShell, native PostgreSQL concurrency and live provider latency were unavailable for execution here. Use the exact native commands in `PHASE13.md`.

Machine-readable observations are in `phase13_results.json`. These are measured local development results, not production capacity or real-world detection-accuracy claims.

## Automated results

| Check | Observed result |
| --- | --- |
| Full backend regression | **683 passed, 1 skipped, 1 warning in 44.52 s** |
| Final Phase 13 backend tests | **29 passed, 1 warning in 6.65 s** |
| Frontend suite | **58 passed across 4 files in 3.50 s**, including 10 Phase 13 tests |
| Production frontend build | Passed; 2,613 modules, Vite-reported build time 324 ms |
| Ruff lint / formatting | Passed for all 27 changed Python files |
| Fresh Alembic upgrade | Passed through `0008_ai_analyses` |
| Alembic schema drift | No new upgrade operations detected |
| Migration downgrade/upgrade regression | Passed |
| Browser application errors | 0 JavaScript exceptions, 0 console issues, 0 unexpected API errors |
| Swagger | HTTP 200 and all six Phase 13 AI endpoint paths present |

The full regression ran before the last expansion of the context digest to all original event fields and additional intelligence fields. All 29 Phase 13 tests and the full pipeline/browser workflow were rerun after that change. The skipped existing test requires independent native PostgreSQL writer concurrency, which the adapter does not represent. The warning is an existing Starlette TestClient/httpx deprecation; application dependencies were deliberately not upgraded in this phase. An npm environment warning about `http-proxy` did not prevent the build.

Backend tests cover evidence minimization, unrelated-record exclusion, log/comment injection resistance, stored rule thresholds, risk explanation, cached intelligence and expiry, changes outside the displayed sample, fresh/cache/forced/history behavior, evidence changes during provider latency, malformed and invalid provider output, timeouts/authentication/rate limits, provider cooldown, identity/score/reference validation, no invented successful-login sequence, controlled overview queries, RBAC, missing cases, invalid input, rate limiting, disabled mode, Swagger, audits and metrics. HTTP-provider success is simulated through `httpx.MockTransport`.

Frontend tests cover empty state and no generation on mount, deterministic and AI mode labels, explicit generation, duplicate-click prevention, evidence drawers, stale/regenerated/history states, scoped Q&A, errors that retain the previous report, viewer restrictions, overview selection and rejection of invalid references.

## End-to-end synthetic pipeline

The existing generator produced **10,000 events** with seed 42, `mixed`, start date `2026-10-06`, over seven days. The existing ingestion, detection, risk, incident and mock-intelligence CLIs processed them without replacing their implementations.

| Step | Measured wall time |
| --- | ---: |
| Ingestion | 4,675.44 ms |
| Detection | 12,259.96 ms |
| Risk scoring | 76.88 ms |
| Incident processing | 439.25 ms |
| Mock threat enrichment | 281.17 ms |

The detection CLI reported 10,000 evaluated and processed events, 36 created findings, zero duplicates, all ten rules executed, zero events remaining, and **12.254 s / 816.1 events per second**. Wall time includes command overhead and differs slightly from internal engine time. This was a single measured run, not a multi-run capacity benchmark.

A separate synthetic fixture added 50 failed admin-console logins over 49 seconds from a documentation-address reputation indicator, then one successful login. It passed through the normal engines and produced the critical case needed for the investigation workflow. Scores were not manually changed to force that case.

Final isolated database totals:

| Record | Count |
| --- | ---: |
| Security events | 10,051 |
| Processed events | 10,051 |
| Detection findings | 89 |
| Risk assessments | 89 |
| Incidents | 30 |
| Threat-intelligence result bundles | 35 |
| Invalid retained evidence references | 0 |

Final finding distribution, including the 51 supplemental events:

| Rule | Findings |
| --- | ---: |
| CS-001 | 6 |
| CS-002 | 2 |
| CS-003 | 4 |
| CS-004 | 4 |
| CS-005 | 3 |
| CS-006 | 3 |
| CS-007 | 7 |
| CS-008 | 56 |
| CS-009 | 4 |
| CS-010 | 0 |

The mixed generator explicitly reported that `abnormal_api` was not included in its suspicious-event budget. CS-010 executed and correctly produced no finding in this fixture; this run must not be presented as exercising every attack scenario. Rule-specific regression tests remain responsible for that rule's positive/negative cases.

## AI performance

Ten samples used one incident with **one linked finding, one linked event and two cached indicators**, inside the populated 30-incident database. The table measures local service calls, not network round trips.

| Operation | Median | Minimum | Maximum |
| --- | ---: | ---: | ---: |
| Context construction | 44.492 ms | 40.781 ms | 61.019 ms |
| Deterministic fallback generation | 92.877 ms | 88.448 ms | 99.536 ms |
| Compatible cached analysis | 47.349 ms | 45.185 ms | 48.990 ms |

One valid mocked Responses call took 1.372 ms inside the adapter and 95.52 ms for the service request. Those values measure mock response parsing/validation and local application overhead, **not real LLM speed**.

The larger browser case contained 53 findings and 51 events; configured context limits included 20 findings and 50 events, plus both indicators. First report generation/display took **249 ms** in the browser measurement; a subsequent authenticated cached HTTP request took **73.5 ms**. These are single observations on local synthetic data.

## Browser investigation results

The automated Chromium workflow used the running app and real authenticated HTTP endpoints:

1. Logged in as ANALYST, opened the critical case and verified that viewing the AI tab did not trigger generation.
2. Explicitly generated a fallback report and inspected the summary, actual finding metrics, six stored risk contributions, conditional guidance, uncertainties and coverage limits.
3. Opened a finding source and a related event drawer. Q&A identified a same-account success one second after a failure and cited the two actual case events. The answer explicitly did not assert compromise.
4. Added an analyst note through the existing supported UI. The earlier report became stale; explicit regeneration produced a new current version while retaining the older history entry.
5. Used the general AI Analyst incident picker and controlled overview question, checked honest FALLBACK health, and verified all six OpenAPI paths and `/docs`.
6. Confirmed incident risk, severity, status and assignment were not changed by analysis.
7. Logged in as VIEWER, read the saved report and verified that generation/question controls were absent. Direct POST requests to all three AI write/query endpoints returned 403.
8. Checked the investigation layout at 1,440×1,000, 1,366×768 and 390×844; no horizontal overflow remained after layout settled. Also checked the mobile analyst overview.

There were 56 observed API requests, zero unexpected API failures and two retained generated versions for the exercised case. Browser screenshots were used for internal visual inspection; this handoff records the outcomes in text.

## Issues encountered and resolved

- Existing Phase 2 schema tests expected the previous migration head/table count. Updated those assertions to include the one new analysis-history table; fresh migration and drift checks now pass.
- Test interactions initially clicked generation before asynchronous health/status loading completed. The tests now wait for the actual enabled control, preserving the UI's no-duplicate-request behavior.
- A first narrow-viewport measurement captured an intermediate responsive layout transition. The browser check now waits for settled layout; the final 390 px view has no overflow.
- A formatting pass temporarily produced adjacent parenthesized strings interpreted as a call in an uncertainty message. Corrected the expression and reran the backend regression.
- Context review identified fields outside the displayed sample that could change without invalidating an earlier report. Expanded deterministic digests to all original event columns (excluding the operational `processed` flag) and intelligence timestamps/reputation/score; final focused and full-pipeline checks pass.
- Baseline health placeholders claimed AI was not implemented. Replaced them with truthful disabled/fallback/configured/recent-success states; configured credentials alone never establish provider readiness.

## Remaining environment checks

Run `docker compose up --build -d --wait --wait-timeout 180`, `docker compose exec backend alembic upgrade head`, and `scripts/Verify-Phase13.ps1` on Windows as documented. Run the isolated database test runner against native PostgreSQL to cover its concurrency test. If you choose an external provider, supply your own key/model and explicitly generate one report to validate account access and latency. Until those actions succeed, Docker Desktop, native concurrency, PowerShell and live-provider behavior remain unverified.

Phase 14, infrastructure finalization and cloud deployment were not started.
