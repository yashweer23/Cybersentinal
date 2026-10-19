# Phase 8 — Validation results

Validation completed on 2–3 October 2026 against the existing Phase 7 project plus this incremental update. Commands for reproducing the checks on Windows and Docker are in [PHASE8.md](PHASE8.md). Complete changed files are listed in [PHASE8_FILES.md](PHASE8_FILES.md).

## Execution environment and limits

The application ran with Python 3.12.14 and the project's existing locked dependencies. Database checks used PostgreSQL 17.5 through PGlite and a local wire-protocol adapter, with the application's SQLAlchemy/Psycopg stack. Each pipeline dataset used a separate disposable schema. These checks exercised PostgreSQL JSONB, enums, constraints, transactions and Alembic migrations; SQLite was not substituted.

Docker, native PostgreSQL server binaries and PowerShell were unavailable in this execution environment. Container startup, Windows commands and native multi-process PostgreSQL concurrency were therefore **not executed here**. Existing Compose configuration, Dockerfiles and dependency files remain unchanged. Run the documented local health and test commands to verify those deployment-specific checks. Swagger HTML and OpenAPI responses were verified through FastAPI TestClient; visual browser rendering was not tested.

## Regression suite and migrations

```text
516 passed, 1 warning in 31.95s
```

The suite includes the 459 earlier-phase tests and 57 new incident tests, including parameterized cases. Ruff reported `All checks passed!` for the complete backend.

The single warning is the existing Starlette TestClient/httpx deprecation warning. It did not fail a test; dependencies were not changed solely to suppress it.

Verified migration behavior:

- A clean schema upgrades through `0005_incident_workflow`.
- The existing migration round-trip test upgrades, downgrades to base, upgrades again and checks for ORM/migration drift.
- The migrated schema contains 14 application tables plus `alembic_version`.
- Existing incident constructors and earlier database/API tests remain compatible.
- Finding-link uniqueness, foreign keys and incident time constraints are enforced by PostgreSQL.

Coverage includes:

| Area | Checks |
| --- | --- |
| Promotion | Scores 49, 50 and 90; configurable minimum; deferred findings |
| Correlation | Shared identifiers, unrelated accounts, distant times, full-case span, deterministic ties, unknown-account separation |
| New context | Later lower-risk finding attaches; deferred finding reconsidered after context changes; score increases/decreases refresh the same case |
| Idempotency | Unchanged repeat, changed policy, unique finding links, shared event evidence |
| Planning | Read-only dry run across batches; projected cases and deferred reevaluation; no state, audit or metric writes |
| Failure handling | Invalid evidence, current-batch rollback, earlier committed batches, busy-lock response, batch/candidate bounds |
| Workflow | Assignment validation, transitions, resolution, false-positive reason, manual reopening and optional automatic reopening |
| Authorization | ADMIN/ANALYST writes; VIEWER read-only; unauthenticated requests rejected |
| Investigation | Filtering, pagination, details, linked findings/events, notes, chronological timeline and statistics |
| Audit and documentation | Actors and old/new values, API processing audit, all eleven OpenAPI operations and security schemes |

Busy-lock behavior was tested, but this does not establish throughput or race behavior under a distributed deployment.

## Actual generate → ingest → detect → score → process runs

All rows below came from executing the existing generator, ingestion, detection and risk CLIs followed by the new incident CLI. Findings and scores were not inserted as benchmark shortcuts. Each dataset used `seed=42`, `scenario=mixed` and unchanged seeded rule configuration.

| Dataset | Events | Findings | Risk assessments | Incidents | Finding links | Evidence references | Deferred findings |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000; 95% normal | 1,000 | 6 | 6 | 5 | 5 | 17 | 1 |
| 10,000; 95% normal | 10,000 | 36 | 36 | 29 | 29 | 160 | 7 |
| 10,000; 92% normal | 10,000 | 24 | 24 | 16 | 16 | 176 | 8 |

The 92% normal variant gives the generator enough event budget to include every scenario, including the larger API burst. A different scenario mix can yield fewer findings: findings are behavioral matches, not a fixed percentage of events.

All three runs had zero invalid/failed imports, executed ten enabled rules, left zero unprocessed events and scored every generated finding. Each incident's stored risk equaled the maximum current linked assessment. Evidence references resolved to retained events, and no finding belonged to more than one case.

All automatically created incidents initially had HIGH severity, OPEN status and no assigned analyst. Average incident risks were 56.20, 57.72 and 56.75 respectively. No severity or risk was inflated to make the demo produce critical cases. The default 10,000-event run deferred seven CS-007 findings below the promotion threshold. The 92% normal run deferred seven CS-007 findings and one CS-004 finding.

The standard mixed datasets produced **zero correlated attachments to an existing case**: their scenario identities/times did not meet the conservative matching policy. Each promoted finding created its own case. The separate two-stage behavioral check below verifies actual many-findings-to-one-case correlation without weakening that policy.

## Measured processing times

| Dataset | Ingestion | Detection | Risk scoring | Incident processing |
| --- | ---: | ---: | ---: | ---: |
| 1,000; 95% normal | 0.517 s | 0.397 s | 48.298 ms | 112.537 ms |
| 10,000; 95% normal | 4.653 s | 12.962 s | 75.122 ms | 444.862 ms |
| 10,000; 92% normal | 5.402 s | 12.968 s | 68.045 ms | 275.665 ms |

These are service/CLI-reported elapsed times from one run per dataset, not repeated-load benchmarks. Risk and incident processing evaluate 6, 36 and 24 **findings**, respectively; their times must not be presented as direct throughput over raw events. Database compilation/cache effects and this embedded environment affect timings. Native Docker results will differ.

## Detection rule distribution

| Rule | 1,000 / 95% | 10,000 / 95% | 10,000 / 92% |
| --- | ---: | ---: | ---: |
| CS-001 Brute force | 1 | 5 | 4 |
| CS-002 Password spraying | 1 | 2 | 1 |
| CS-003 Impossible travel | 1 | 4 | 1 |
| CS-004 Unusual login time | 1 | 3 | 3 |
| CS-005 Privilege escalation | 0 | 3 | 2 |
| CS-006 Suspicious ports | 0 | 3 | 1 |
| CS-007 Excessive access | 1 | 7 | 7 |
| CS-008 Synthetic suspicious IP | 1 | 5 | 2 |
| CS-009 Repeated access denied | 0 | 4 | 2 |
| CS-010 Abnormal API activity | 0 | 0 | 1 |
| **Total** | **6** | **36** | **24** |

These are finding counts, not incident counts or estimates of real-world accuracy. Phase 8 does not read simulation labels or calculate precision/recall. The earlier development evaluation script remains available for synthetic scenario coverage.

## Dry run, repeat safety and source preservation

For the three datasets, dry runs projected 5, 29 and 16 cases and the same number of links. The subsequent real runs produced those exact counts. Dry-run actual creation/attachment counters stayed zero.

Each immediate unchanged repeat reported:

```text
Findings evaluated: 0
Incidents created: 0
Incidents updated: 0
Findings attached: 0
Remaining pending: 0
Complete pass: True
```

Repeats took 7.360, 7.632 and 6.155 ms respectively. Full-row SHA-256 digests of security events, detection findings and risk assessments were identical before and after Phase 8 processing and investigation checks. Phase 8 did not rewrite source evidence, scores or event processing flags.

## Later related finding: real correlation check

This additional isolated check used ordinary synthetic event fields and **no simulation labels**. The same actual ingestion, detection, risk and incident services ran in two stages.

1. Five failed logins within four seconds for one account, IP and device produced CS-001, with a Phase 7 risk score of **56/HIGH**. Incident processing created one case in **61.789 ms**.
2. Ten access denials 90–99 seconds after the first event, sharing that account, IP and device, produced CS-009 with risk **48/MEDIUM**. Incident processing attached it to the original case in **37.582 ms**, created zero additional cases and updated one existing case.
3. The final database contained **one incident, two finding links and 15 valid event evidence references**. The original incident ID was retained, and case risk remained the maximum linked score, 56.
4. An unchanged repeat evaluated zero findings and created/attached nothing, in **7.157 ms**.

This verifies that a below-threshold finding can contribute evidence to a related active case without independently creating an incident.

## API, RBAC and investigation verification

Each pipeline dataset was also exercised through FastAPI TestClient using real JWT authentication. All eleven incident operations succeeded with authorized credentials. Reads, processing, assignment and status changes returned 200; comment creation returned 201. System health, database status, `/docs` and `/openapi.json` returned 200.

The probe assigned an analyst, added a note, transitioned OPEN → INVESTIGATING → RESOLVED and reopened to INVESTIGATING. Case counts and distributions reported above were captured **before** that investigation sequence. The sequence ended with one case INVESTIGATING; the rest remained OPEN.

The pytest suite separately verifies all four write operations return 403 for VIEWER, unauthenticated reads return 401, valid ADMIN/ANALYST actions succeed and assignment rejects a VIEWER, inactive analyst or nonexistent user. Invalid transitions, empty closure explanations and invalid request values fail cleanly. Every incident route has an explicit response model and the existing JWT security dependency.

## Issues found and resolved

- A missing-account correlation anchor could otherwise bridge two different known usernames sharing infrastructure. Cases now retain the first known account and reject contradictory known accounts. Regression checks cover both dry-run planning and persisted processing.
- The extra correlation fixture initially supplied five access denials, while the existing seeded CS-009 threshold is ten. The fixture was corrected to use the configured threshold; application rules and thresholds were preserved. The first combined benchmark command ended on this extra-fixture assertion after all three main pipelines had completed. The corrected standalone correlation run then passed.
- An overnight usage limit interrupted that final extra check. It was resumed and completed on 3 October; no result was inferred from the interrupted attempt.
- The pre-existing TestClient deprecation warning remains documented above.

All implementation checks described as passed were actually executed. Docker/Windows startup and native concurrency remain the explicit local verification limits. Synthetic behavior and these development measurements do not establish production detection accuracy or operational readiness.
