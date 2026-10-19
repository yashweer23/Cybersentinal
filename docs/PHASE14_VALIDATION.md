# Phase 14 validation — 2026-10-15

These are executed results, not expected outputs. The test runtime used PGlite PostgreSQL 17.5 through a local socket adapter, the existing Python 3.12 dependencies, real FastAPI/Vite servers and headless Chromium. The adapter disables unsupported prepared/pipeline transport for validation only. Application database code remains unchanged. No user development database was used.

## Automated checks

- Backend: **717 passed, 1 skipped**, 718 collected. This includes 33 new advanced-analytics/report tests and all existing phases. The single skipped test requires native PostgreSQL independent concurrent writers; it remains runnable through the Docker test runner.
- Frontend: **72 passed** across five files, including 14 new analytics tests. Production Vite build passed.
- Ruff: all backend application/test files passed.
- Fresh Alembic upgrade to `0008_ai_analyses` and metadata drift check passed; Phase 14 has no schema migration.
- Existing Starlette TestClient emitted its httpx deprecation warning; this update does not change dependencies to suppress it.

Controlled fixtures verify known MTTA/MTTR/P90 and denominators, null samples, UTC boundaries, outside-range exclusion, all three roles, unauthenticated/forbidden/invalid requests, export limits/paging, formula-safe CSV, repeated closures/reopening, missing creation audits, automatic/invalid acknowledgement exclusion, stale intelligence, recorded AI metrics, and read-only SQL behavior. The mandatory one-case/three-findings/two-assessment-versions fixture remains one incident; entity and rule joins do not multiply it. Empty populations and current-version score selection are covered. Previous-period comparison is not implemented or advertised.

## Executed 10,000-event workflow

Generated seed 42, mixed scenarios, seven completed UTC days beginning 2026-10-08. Used the existing generator, ingestion, detection, scoring, incident processing and mock enrichment CLIs. The existing workflow service then assigned three cases, recorded investigation/notes, resolved one case, marked one false positive, and generated one deterministic fallback explanation. Those deliberate synthetic analyst actions exercise response metrics; their approximately one-second durations do not represent real SOC performance.

| Stored data | Count |
| --- | ---: |
| `security_events` | 10,000 |
| `detection_findings` | 36 |
| `risk_assessments` | 36 |
| `incidents` | 29 |
| `threat_intelligence_results` | 34 |
| `ai_analyses` | 1 |

All 10,000 original events were processed. Invalid incident-evidence event references: 0. Executive/report counts were asserted against direct SQL. Case critical count was zero for this fixture; no scores were changed to force a critical KPI.

| Stage | Wall time (ms) |
| --- | ---: |
| ingest | 5,436.107 |
| detect | 14,407.628 |
| risk | 88.578 |
| incidents | 559.207 |
| intelligence | 379.734 |

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

The seed 42 mixed budget omitted the abnormal-API scenario, so CS-010 had zero findings in this dataset. Its positive/negative rule tests remain in the passing regression suite. A mixed generator budget does not guarantee all scenarios.

Synthetic evaluation: **37 expected scenario-rule units, 36 detected, 1 missed, 0 unexpected findings**; scenario recall 97.30%, retained finding-label agreement 100%. Precision is null. Overlap, sampled evidence and boundaries limit interpretation; this is not real-world detection accuracy.

The creation cohort contained 29 cases, with one RESOLVED and one FALSE_POSITIVE. Resolution rate was 3.45%, false-positive rate 50.0%, current average risk 57.72. MTTA used 2 audited acknowledgements (1.0 seconds mean); MTTR used 1 valid resolution (1.01 seconds). Those are fixture observations with documented sample counts.

## Measured aggregation performance

Each operation ran five sequential samples in one local process; the table shows median service/query time including SQL execution and response assembly. These are not p95 API latency or production throughput claims. The first population was the complete 10,000-event workflow above. Then 90,000 additional **normal events were ingested only** for analytics scale, and PostgreSQL statistics were refreshed. Findings/cases remained 36/29; the second population is **not 100,000 fully processed detections or incidents**. The period covered all stored events and created cases.

| Operation | 10,000 events median ms | 100,000 events median ms |
| --- | ---: | ---: |
| overview | 33.705 | 65.778 |
| events | 11.742 | 93.537 |
| incidents | 2.677 | 2.754 |
| rules | 4.031 | 5.856 |
| risk_trend | 1.399 | 1.646 |
| entities | 52.563 | 170.208 |
| service_entities | 32.355 | 92.264 |
| status_history | 9.050 | 6.167 |
| intelligence | 12.026 | 11.465 |
| evaluation | 41.746 | 160.186 |

Full individual samples, minimum/maximum and EXPLAIN JSON are retained in `phase14_results.json`. Existing `ix_security_events_timestamp` and `ix_incidents_created_at` were used in the inspected query plans. No additional index, result cache or materialized view was justified by these observations. The existing 3-second per-statement timeout still applies in the application. Native hardware, more findings/cases, wider scope and concurrent load can change performance.

## Browser acceptance

Real Uvicorn + Vite + Chromium exercised all eight analytics tabs against 100,000 stored events. Successful checks include event filters, rule sorting, risk-population and source/service selectors, recurring IPs, separated mock/live intelligence, audited response values, ADMIN workload, custom empty periods, tab/date preservation and 90D selection.

The browser downloaded a security-summary CSV and a 29-row incident JSON report. Both reflected stored data; passwords/hashes were absent. ADMIN, ANALYST and VIEWER behavior was checked both in the UI and against server responses, including 403 for restricted workload/exports. All 15 analytics routes and the report route appeared in OpenAPI; `/docs` returned 200.

Widths 1440, 1366 and 390 passed document-overflow checks. Executive and report layouts were visually inspected. Page errors: 0; unexpected API errors: 0; console warnings/errors: 0. The initial signed-out refresh 401 is expected. A separate real-chart check confirmed a single risk observation remains visible without drawing across missing buckets.

One observed initial analytics navigation took 1205ms, and one overview HTTP request took 80ms. These are single local observations, not latency guarantees.

## Issues found and resolved

- A nested evidence query reused a CTE name, causing PostgreSQL compilation failure. Anonymous CTE names now compose safely; deduplication tests pass.
- Exact accessible report-selector labels were obscured by nested option text. Explicit labelled spans fixed keyboard/accessibility/browser selection; CSV and JSON flows now pass.
- A chart with only one populated risk bucket hid its point. Risk-series dots now display isolated observations while preserving gaps.
- Threat-indicator exports now use current policy/expiry semantics, suppressing stale scores and exposing cache status; tests cover expired and incompatible records.
- The first validation harness requested 100 enrichment cases against the existing maximum 50. The harness was corrected to 50; application limits were preserved.
- The earlier navigation test expected the placeholder Analytics heading/global dropdown. It now verifies the expanded page and inherited 7D scope.
- Long Python literals were wrapped with an AST-equivalence guard; unsafe formatting attempts were rejected before writes. Final lint passes.

## Remaining native verification

**Docker Desktop and PowerShell were unavailable here. Native Docker/Windows execution has not been claimed as passed.** Run `scripts/Verify-Phase14.ps1`, the Docker build/health/migration checks and the isolated test runner from `PHASE14.md` on your existing installation. The unchanged Compose/Dockerfiles and dependency pins were compared with the Phase 13 baseline.

Live-provider calls were not needed or made by analytics; enrichment used mock mode and explanations used deterministic fallback. Native multi-writer concurrency and production load remain unverified. Phase 15 infrastructure and later deployment are outside this delivery.
