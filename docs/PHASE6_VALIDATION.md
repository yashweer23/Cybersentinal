# Phase 6 validation

## What was actually run

Validation used Python 3.12.14, the existing locked dependencies, and an isolated embedded PostgreSQL 17.5 database (PGlite exposed through a local PostgreSQL protocol adapter). The application used SQLAlchemy and psycopg against PostgreSQL types and SQL; these results do not come from SQLite or mocked database persistence. The validation-only adapter disables prepared statements. It is not part of the application or update package.

Docker, Windows PowerShell and a native PostgreSQL server were unavailable in this execution environment. Consequently, Docker startup, the Windows verification scripts, native PostgreSQL concurrency and production throughput are **not claimed as verified here**. Run the existing Compose environment and the commands in [PHASE6.md](PHASE6.md) on Windows to confirm those integration points. Dockerfiles, Compose, database credentials, dependency locks and frontend code are unchanged.

Each benchmark used a fresh isolated schema. Tests used the existing isolated test-database fixtures. No development events or databases were deleted. The integration sequence executed the actual Phase 4 generator, Phase 5 importer and Phase 6 detection CLI, then exercised the APIs through FastAPI's test client with real application JWT authentication.

## Tests and migration

```text
361 passed, 1 warning in 25.03s
```

This includes the existing 278 tests and 83 added tests: 64 rule/configuration/helper/CLI cases and 19 database/engine/API cases. Ruff passed for the backend.

Coverage includes:

- All ten rules, positive and negative cases, inclusive time boundaries, grouping, malformed metadata, missing coordinates, timezone behavior and historical baselines.
- Dry runs, single-rule processing, enabled rules, bounded batches, capped evidence, fingerprint replay, processed historical context, late arrivals and batch-size-independent fingerprints.
- Whole-batch rollback on failure, preservation of earlier committed batches, invalid configuration, context-limit errors, lock contention responses and missing evidence rejection.
- Findings persistence, confidence constraints, evidence references, primary-event deletion protection and unchanged original event content.
- Existing JWT/RBAC, read permissions, administrator-only configuration changes, run audit records and OpenAPI route registration.
- Clean Alembic upgrade through `0003_detection_findings`, downgrade/upgrade round trip and schema-versus-metadata checks. No `create_all()` migration shortcut is used.

The warning is an existing Starlette test-client deprecation concerning its use of httpx. It did not fail tests; dependencies were not changed solely to suppress it. The revised PowerShell verifier was inspected but could not be executed here.

## Measured processing results

All datasets used `--seed 42 --scenario mixed`, the retained seeded rule configuration, batch size 500 and the completed implementation including historical volume baselines. Duration and throughput are the engine's actual measurements, including rule evaluation, context queries and persistence. They exclude generation, ingestion and Python process startup. These are single local runs, not a native PostgreSQL production benchmark.

| Dataset | Normal ratio | Events processed | Duration | Events/second | Findings created |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1,000 events | 0.95 | 1,000 | 0.348 s | 2,874.9 | 6 |
| 10,000 events, default mix | 0.95 | 10,000 | 12.808 s | 780.8 | 36 |
| 10,000 events, all-rule scenario coverage | 0.92 | 10,000 | 13.232 s | 755.7 | 24 |

All three imports accepted their full event count. All ten enabled rules executed in each initial detection run. All three runs ended with zero unprocessed events. Follow-up checks confirmed that raw-event digests were unchanged, every retained evidence identifier resolved to an event, and both `incidents` and `incident_evidence` remained empty.

| Rule | 1,000 / 0.95 | 10,000 / 0.95 | 10,000 / 0.92 |
| --- | ---: | ---: | ---: |
| CS-001 Brute force | 1 | 5 | 4 |
| CS-002 Password spraying | 1 | 2 | 1 |
| CS-003 Impossible travel | 1 | 4 | 1 |
| CS-004 Unusual login time | 1 | 3 | 3 |
| CS-005 Privilege escalation | 0 | 3 | 2 |
| CS-006 Suspicious ports | 0 | 3 | 1 |
| CS-007 Excessive sensitive access | 1 | 7 | 7 |
| CS-008 Synthetic suspicious IP | 1 | 5 | 2 |
| CS-009 Repeated access denied | 0 | 4 | 2 |
| CS-010 Abnormal API activity | 0 | 0 | 1 |
| **Total** | **6** | **36** | **24** |

The default 95% normal 10,000-event mix has only a 500-event attack budget. The generator cannot fit its minimum API-burst episode after reserving other scenarios. The additional 92% normal dataset exercises all ten rule types without changing the generator or detection thresholds. An executed rule need not produce a finding when its behavior is absent.

## Idempotency and API verification

| Dataset | Normal rerun: events evaluated / new findings | Forced replay: events evaluated / duplicates / new findings |
| --- | --- | --- |
| 1,000 | 0 / 0 | 1,000 / 6 / 0 |
| 10,000 / 0.95 | 0 / 0 | 10,000 / 36 / 0 |
| 10,000 / 0.92 | 0 / 0 | 10,000 / 24 / 0 |

The normal rerun checks processing flags. `--replay` deliberately re-evaluates stored events and checks the database fingerprint uniqueness constraint. It does not reset flags. No additional findings were created in either mode.

Authenticated API checks returned 200 for finding lists, a single finding, statistics, rule listing and a completed detection run. `/docs` and `/openapi.json` returned 200, and the OpenAPI document contained all six Phase 6 route operations. Role tests verify that VIEWER cannot run detection, and only ADMIN can update rules. The separate API engine tests also cover runs that create findings; benchmark API runs occurred after the CLI had emptied the queue.

## Synthetic ground-truth evaluation

Only the optional evaluator reads simulation labels. Runtime detection uses observed event fields, timestamps, metadata and the independent local reputation provider. Tests remove or contradict labels without changing behavior-based outcomes.

| Dataset | Expected scenarios | Detected | Missed | Unexpected findings | Scenario recall | Finding-label agreement |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 6 | 6 | 0 | 0 | 100% | 100% |
| 10,000 / 0.95 | 37 | 36 | 1 | 0 | 97.30% | 100% |
| 10,000 / 0.92 | 25 | 24 | 1 | 0 | 96% | 100% |

An expected scenario is a distinct `(rule_id, simulation.scenario_id)` pair for a supported scenario. It counts as detected when a finding of that rule retains evidence from the scenario. Scenario recall is detected/expected. Finding-label agreement is the fraction of findings with at least one retained evidence event carrying the corresponding expected label. It is deliberately not presented as calibrated precision. An unexpected finding means no matching label was found in retained evidence; it does not establish a real false positive. Truncated evidence and overlapping behavior limit these comparisons. Normal activity and malware alerts have no corresponding expected Phase 6 scenario match.

The missed scenario in each 10,000-event dataset contains eight access denials. The existing CS-009 configuration requires ten. Keeping that threshold preserves Phase 2 configuration; the engine correctly declines to classify an insufficient pattern just because its simulation label names an attack.

These results measure synthetic coverage and consistency, not real-world detection accuracy.

## Issues resolved and remaining limits

| Issue | Resolution or explicit limit |
| --- | --- |
| Existing seeded thresholds differ from Phase 6 examples | Retained existing values and documented them; configuration remains editable through ADMIN-only validation. |
| Sensitive access is represented by both event types and per-event record counts | Supports `SENSITIVE_RECORD_ACCESS` and sensitive `FILE_ACCESS`; measures supplied record counts without generating patient data. |
| Events arrive across batches or out of timestamp order | Queries processed history and relevant future anchors; tests cover threshold crossings, late arrivals and stable replay fingerprints. |
| Very large historical context could exhaust memory | Context is SQL-filtered and bounded; over-limit batches fail visibly and leave flags unchanged. Baseline context increases processing cost, as reflected in the final timings above. |
| Historical Phase 3 verifier required revision `0002_auth_sessions` | It now compares the installed revision with the API's expected Alembic head. No authentication flow was replaced. |
| One embedded test fixture stalled while issuing repeated ORM label updates around savepoints | Replaced the fixture setup with one SQL update; the same behavioral assertion passes. This was validation setup, not a change to production detection behavior. |
| Concurrent native workers | PostgreSQL advisory locking, row locks and unique fingerprints are implemented; busy-lock behavior is tested. A native multi-process stress test remains unperformed. |
| Historical baselines | Explainable heuristics can reflect contaminated history. Volume baselines use completed active UTC days; login windows use earlier local days. They are not learned guarantees of benign behavior. |
| Evidence and immutable findings | Retained IDs are validated before insertion; only the primary event has a database foreign key. Late evidence may create an additional valid anchor finding. Incident grouping is deferred. |
| Docker/Windows | Commands are provided for local verification; no claim that this environment executed Docker or PowerShell. |

No Phase 7 risk score, Phase 8 incident creation, external reputation API or AI detection was added.
