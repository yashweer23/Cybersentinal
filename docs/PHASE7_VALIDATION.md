# Phase 7 validation results

## Environment and execution limits

Actual validation used Python 3.12.14, the project's existing dependency locks and an isolated embedded **PostgreSQL 17.5** database (PGlite through a local PostgreSQL protocol adapter). SQLAlchemy/psycopg exercised PostgreSQL JSONB, INET, native enums, constraints, transactions and migrations. These are database-backed results, not SQLite substitutions or mocked persistence.

Docker, native PostgreSQL and Windows PowerShell were unavailable here. Container startup, Windows execution and native multi-process concurrency are therefore **not claimed as verified**. Use [PHASE7.md](PHASE7.md) for exact local commands. Compose, Dockerfiles, frontend, dependency locks and your actual `.env` are unchanged.

The existing scratch validation environment had lost its Python interpreter link; restoring the link to the installed Python 3.12 runtime recovered the existing packages without changing project dependencies. The validation adapter disables prepared statements, as in earlier phases. Neither that adapter nor the local environment repair is application code or part of the update package.

Each benchmark ran in a fresh isolated schema on a disposable database. Tests reused the established isolated test-database fixtures. No development data was deleted or modified for validation.

## Pytest and migration results

```text
459 passed, 1 warning in 29.30s
```

This comprises **361 existing tests and 98 new tests**: 64 scoring/configuration/helper cases and 34 risk engine/database/API cases. Ruff passed across the backend. There were no skipped tests in the full database-backed run.

The warning is the pre-existing Starlette/httpx test-client deprecation. It did not fail tests; dependencies were not changed to hide it.

Verified coverage:

- Exact category boundaries: 0/24, 25/49, 50/74, 75/100; invalid totals rejected.
- All six components, independent rounding, maximum score 100, invalid component bounds, deterministic input hashing and stable scores.
- Representative scores for all ten rule types; stronger count/speed anomalies score higher while frequency does not reuse those counts.
- Successful authentication requires matching IP/account and the configured follow-up interval; unrelated, failed and out-of-window events do not add that context.
- Structured admin/manager role distinctions, approval context, sensitive accounts, administrative ports, resource breadth, endpoint path boundaries and HTTP response composition.
- Local reputation bands, expired context, provider failure, malformed evidence and missing event references.
- Persistence, finding relationship, JSONB explanations, total/component/category integrity and nonempty matching explanations enforced by PostgreSQL.
- Idempotent normal runs, unchanged rescore, explicit policy/context rescore, preserved assessment identity and separate algorithm-version rows.
- Dry-run read-only behavior, bounded batches, lock-busy response, current-batch rollback and preservation of earlier committed batches.
- Batched event retrieval: the ten-event fixture uses one retained-evidence query and one successful-login context query, not one query per event.
- SQL field projection excludes large unrelated raw payloads; a 100,000-character payload test confirms only bounded scoring metadata is loaded and source data is preserved.
- ADMIN/ANALYST run access, VIEWER read access and prohibited runs; filters, pagination, highest-score ordering, date ranges, detail lookup, empty/populated stats, summary audits and OpenAPI BearerAuth declarations.
- All previously existing generation, ingestion, detection, authentication, schema and API regression tests.

The migration suite upgraded a clean database through `0004_risk_assessments`, ran Alembic's metadata drift check, downgraded to base and upgraded again. No new native enum was introduced. Each integration dataset also ran `alembic check` successfully with no missing operations.

## Actual generate → ingest → detect → score runs

The real Phase 4 generator, Phase 5 importer, Phase 6 detection CLI and new Phase 7 CLI entry points were invoked with seed **42**, mixed scenario and existing rule thresholds. The harness routed them to isolated schemas; it did not fabricate events, findings, scores or counts outside those application entry points.

| Dataset | Events imported | Ingestion time | Detection time | Findings | Risk scoring time | Assessments | Unscored/invalid |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1,000 events, 95% normal | 1,000 | 0.606 s | 0.445 s | 6 | 68.680 ms | 6 | 0 / 0 |
| 10,000 events, default 95% normal | 10,000 | 5.713 s | 13.239 s | 36 | 88.006 ms | 36 | 0 / 0 |
| 10,000 events, 92% normal | 10,000 | 5.703 s | 13.999 s | 24 | 61.052 ms | 24 | 0 / 0 |

The durations are actual measurements from this validation run. Risk timing measures the scoring engine, not the entire pipeline or Python startup. Scoring operates on **36 or 24 findings**, not directly on 10,000 raw events. These are single embedded-environment measurements, not native PostgreSQL production performance claims.

Every import reported zero invalid/failed events. Every initial detector run executed all ten enabled rules and ended with zero unprocessed events. Every eligible finding received a bounded, explained risk assessment.

The default 95%-normal dataset cannot fit the generator's minimum API-burst episode after other scenarios use its attack budget. The additional 92%-normal dataset includes all ten finding types; no generation or detection threshold was altered to force a result.

## Risk distributions

| Dataset | LOW | MEDIUM | HIGH | CRITICAL | Average | Highest |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 / 95% normal | 0 | 1 | 5 | 0 | 54.00 | 64 |
| 10,000 / 95% normal | 0 | 7 | 29 | 0 | 54.86 | 73 |
| 10,000 / 92% normal | 0 | 8 | 16 | 0 | 52.42 | 73 |

The default policy did not produce CRITICAL scores for these datasets. No score was inflated to populate a category. Unit tests independently verify CRITICAL boundaries and a valid 100-point combination. Many Phase 6 volume findings capture the first threshold crossing, so their intensity contribution is zero; high detection confidence or CRITICAL detection severity alone does not automatically produce CRITICAL risk.

| Rule | Default 10,000 findings | Default average / range | All-rule 10,000 findings | All-rule average / range |
| --- | ---: | --- | ---: | --- |
| CS-001 | 5 | 55.20 / 53–59 | 4 | 54.75 / 53–57 |
| CS-002 | 2 | 54.00 / 53–55 | 1 | 53.00 / 53 |
| CS-003 | 4 | 64.00 / 64 | 1 | 64.00 / 64 |
| CS-004 | 3 | 51.00 / 50–52 | 3 | 50.33 / 49–52 |
| CS-005 | 3 | 73.00 / 73 | 2 | 73.00 / 73 |
| CS-006 | 3 | 51.67 / 50–53 | 1 | 50.00 / 50 |
| CS-007 | 7 | 43.00 / 43 | 7 | 43.00 / 43 |
| CS-008 | 5 | 59.00 / 59 | 2 | 59.00 / 59 |
| CS-009 | 4 | 53.00 / 53 | 2 | 53.00 / 53 |
| CS-010 | 0 | — | 1 | 50.00 / 50 |

## Idempotency, rescoring and source preservation

For each dataset:

1. A dry run calculated previews without assessments or risk metrics.
2. The first normal run created exactly one v1 assessment per finding.
3. A normal repeat evaluated zero new findings and created zero rows, reporting 6/36/24 already scored.
4. An unchanged rescore evaluated all findings but created/updated zero rows, reporting 6/36/24 unchanged assessments.
5. A controlled policy change raised authentication/records service sensitivity to 15. Rescoring updated the existing 6/36/24 rows without adding assessments. A row is updated when its full input/configuration hash changes, even if the final integer score is unchanged.
6. Restoring the original policy and rescoring restored every original input hash and score while preserving assessment identifiers. Original score averages returned to 54.00/54.86/52.42.

The controlled policy-change average for the default 10,000 dataset was 58.08; restored average was 54.86. These deliberate changes were confined to the validation settings and were not written to your `.env` or defaults.

Full-row digests of `security_events` and `detection_findings` matched before and after all risk operations, including processed flags, raw JSON, timestamps, severity, confidence, evidence and fingerprints. Every finding was linked to an assessment. `incidents`, `incident_evidence` and `incident_comments` remained empty. Tests separately verify rollback and preservation of raw sources under failures.

## API and Swagger verification

FastAPI's test client with real application JWT/session authentication returned 200 for:

- `/api/risk?limit=2`, `/api/risk/stats` and a real `/api/risk/{assessment_id}`.
- Normal, rescore and dry-rescore requests to `POST /api/risk/run` after the pipeline.
- Existing `/api/detections`, `/api/system/health` and schema-aware `/api/database/status`.
- `/docs` and `/openapi.json`.

The full test suite also exercises API runs that create assessments, forbidden VIEWER runs, all requested filters, stable pagination, missing records, invalid inputs and one audit row per invocation. OpenAPI declares BearerAuth on all four risk operations. HTTP asset/browser rendering and native Docker networking remain local verification steps.

## Compatibility issues handled

| Issue | Resolution |
| --- | --- |
| Findings are immutable and distinct from incidents | Added a separate `risk_assessments` table; risk never edits finding/event rows. |
| Existing enum already supplies all four categories | Reused `SeverityLevel` with a separate risk field; no duplicate enum. |
| Existing evidence reflects threshold crossings, not whole-episode peaks | Scored the actual snapshot and documented its limit; never inferred larger counts from simulation labels. |
| Reusing counts could inflate both intensity and frequency | Kept threshold exceedance in intensity; used duration, resource breadth or response composition for the independent component. |
| More logs or policy changes may affect risk after initial scoring | Explicit `--rescore`, input/configuration hashes and one assessment per finding/version. Same-version history is deliberately not retained. |
| JSON explanations could disagree with numeric columns | PostgreSQL checks require matching points, correct maximums and nonempty reasons for every component. |
| Full raw payloads unnecessarily increased evidence-lookup memory | Changed SQL queries to select only scoring fields and bounded metadata; reran regression and integration validation. |
| The added projection test initially lacked its SQLAlchemy `update` import | Corrected the test import; the final complete suite passes all 459 cases. |
| Test schema/head expectations were from Phase 6 | Updated only expected table/head assertions; all existing tests pass. |
| Local validation Python path no longer resolved | Repaired the scratch interpreter link; retained the existing locked packages. |

Remaining limits: bounded/capped evidence can understate sensitivity or breadth; absent logs cannot prove absent behavior; local reputation is synthetic; development weights are not empirically calibrated; native Docker/Windows and concurrent-worker stress testing were unavailable. Phase 8 was not started.
