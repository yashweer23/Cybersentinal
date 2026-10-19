# Phase 9 — Executed validation

Measured on 3 October 2026. These are development results from the actual application entry points, not estimated production benchmarks.

## Environment and limits

- Python 3.12.14, SQLAlchemy 2.0.54, Psycopg 3.3.6, HTTPX 0.28.1, pytest 9.1.1; the existing dependency environment was reused.
- PostgreSQL 17.5 through the PGlite embedded PostgreSQL build and a local wire-protocol adapter. SQLAlchemy/Psycopg executed the real PostgreSQL schema, enums, JSONB, INET, constraints, queries and Alembic migrations. Tests used random isolated schemas, never development tables.
- The temporary adapter cannot fully support Psycopg pipelined `executemany`. A scratch-only harness disabled prepared statements and that pipeline path. Application code and shipped tests do not contain this override.
- Native Docker, Windows PowerShell, an independent PostgreSQL server and multi-process lock contention were unavailable here. The supplied Docker/PowerShell commands remain the local startup check; container health is not claimed as executed in this environment.
- **Zero live provider requests were made.** Live-adapter tests use deterministic `httpx.MockTransport` fixtures. No successful real AbuseIPDB, VirusTotal or OTX lookup is claimed, and no credentials are included.

## Tests, migration and dependencies

The complete regression suite finished with:

```text
595 passed, 1 warning in 33.58s
```

After the final credential-whitespace redaction fix and an explicit assertion that pre-existing audit entries remain unchanged, all three Phase 9 test modules were rerun:

```text
79 passed, 1 warning in 2.89s
```

The 79 Phase 9 cases cover public IPv4/IPv6, denied private/documentation/transition ranges, invalid inputs, all three fixed-host adapters, mock determinism, normalization, missing fields, mixed/partial results, missing keys, disabled providers, malformed/oversized/nonfinite responses, HTTP failures, timeout, retries and `Retry-After`, secret redaction, cache expiry/refresh/mode separation, provider cooldown across IPs, changed credentials, persistence rollback, bounded/resumable enrichment, shared IPs across findings/cases, preserved investigation and audit records, explicit cached rescoring, incident risk refresh, CLI restrictions, API authentication/RBAC and Swagger schemas.

The previous 516 tests remain included in the complete suite. One existing Starlette TestClient deprecation warning recommends a future transport change; it does not fail tests. Dependencies were not upgraded just to suppress that warning.

Other executed checks:

| Check | Result |
| --- | --- |
| Ruff over the full backend | All checks passed |
| Python source compilation | Passed |
| Installed dependency compatibility | 38 packages checked; all compatible |
| Alembic clean upgrade to head | `0006_threat_intelligence` |
| Repeat upgrade | No duplicate schema objects |
| Alembic model drift check | No new upgrade operations detected |
| Downgrade to base, then upgrade again | Passed in an isolated schema |
| Final schema | 16 application tables plus `alembic_version` |
| IP/mode cache uniqueness | No duplicate indicator identities or mode bundles |

## Full 10,000-event pipeline

Ran the shipped Phase 4 generator with `--count 10000 --seed 42 --scenario mixed`, preserving the default `--normal-ratio 0.95`, followed by the actual ingestion, detection, risk-scoring, incident-processing and enrichment CLI entry points. The harness redirected their database engines to an isolated schema and captured their real output.

| Stage | Measured result | CLI wall time |
| --- | --- | ---: |
| Ingestion | 10,000 valid, 10,000 inserted; 0 duplicate, invalid or failed | 4,651.073 ms |
| Detection | 10,000 processed, 10 rules executed, 36 findings; 0 remaining events | 12,341.880 ms |
| Risk | 36 assessments created; 7 MEDIUM, 29 HIGH; average 54.86 | 134.904 ms |
| Incident processing | 29 cases, 29 finding links, 160 valid event references; 7 below-threshold findings deferred | 429.613 ms |
| First mock enrichment | 29 cases evaluated, 34 unique IPs evaluated, 34 provider evaluations, 0 HTTP requests | 273.600 ms |
| Repeated mock enrichment | Same 34 IPs, **34 cache hits**, 0 provider evaluations, 0 HTTP requests | 151.398 ms |

Detection reported 810.6 events/sec; ingestion reported 2,150 events/sec. These include the embedded SQL transport's overhead and are not native PostgreSQL or cloud throughput claims.

Rule distribution:

| Rule | Findings |
| --- | ---: |
| CS-001 Brute force | 5 |
| CS-002 Password spraying | 2 |
| CS-003 Impossible travel | 4 |
| CS-004 Unusual login | 3 |
| CS-005 Privilege escalation | 3 |
| CS-006 Suspicious ports | 3 |
| CS-007 Excessive sensitive access | 7 |
| CS-008 Local suspicious IP | 5 |
| CS-009 Repeated access denied | 4 |
| CS-010 Abnormal API activity | 0 |
| **Total** | **36** |

All ten rules executed. This particular generator mix did not cross CS-010's configured burst threshold; the rule is exercised by the retained regression tests. No thresholds were lowered to manufacture matches.

### Enrichment interpretation

First-run service duration was **268.706 ms**; repeated service duration was **146.087 ms**. CLI wall times above also include summary/output/commit overhead. Both summaries reported `complete=true`, `next_offset=null`, `failed_lookups=0` and zero actual provider requests.

The cache contained **34 identities and 34 mock bundles**: 3 MALICIOUS synthetic indicators, 14 NO_ADVERSE_SIGNALS synthetic documentation indicators and 17 UNKNOWN/not-applicable contexts. Nineteen cases had at least one successful mock intelligence result; ten cases retained unavailable/not-applicable context. The implementation does not count unavailable context as a successful threat reputation or label it safe.

A forced mock refresh of `198.51.100.73` returned score **92**, synthetic reports **143**, `simulation=true`, `cache_hit=false`, one mock provider evaluation and zero external requests, in **9.493 ms CLI wall time**. Indicator identity was preserved. Mock execution created no provider-wide HTTP cooldown rows.

Ten authenticated, cached `POST /api/threats/lookup` calls had **8.879 ms median wall latency**, range **8.404–11.893 ms**. These measurements include real JWT/session checks, database reads, audit and metric writes through FastAPI TestClient; they are not raw SQL microbenchmarks or Internet latency.

## Preservation and API results

Before enrichment, one case was assigned an analyst, moved to INVESTIGATING and given a note. Full-row SHA-256 digests were identical before/after first enrichment, repeat enrichment, forced refresh and API checks for:

- `security_events`, including all original payloads and processed flags;
- `detection_findings` and `risk_assessments`;
- `incidents`, including risk, severity, status, assignment and timestamps;
- `incident_evidence`, `incident_findings`, `incident_comments` and `incident_processing`.

The service test separately compares every pre-existing audit row after enrichment and confirms new enrichment audits append without altering prior history. Evidence foreign-key references remained valid. The database retained 10,000 events, 36 findings, 36 assessments, 29 cases, 160 evidence references and the analyst note.

All seven new HTTP operations returned **200** with authorized JWTs in the pipeline check. Existing `/api/system/health`, `/api/database/status`, `/docs` and `/openapi.json` also returned 200. Tests verify both write endpoints reject VIEWER with 403; unauthenticated endpoints return 401; invalid IPs produce 422; missing cached data returns 404. Read-only endpoints were tested with lookup disabled to prove they do not initiate enrichment.

The explicit integration test used fixture-controlled live-adapter output with abuse score 95: enrichment left the old score/case unchanged; `reputation_source=cached` plus `rescore=true` added 10 points through the existing Phase 7 component; a subsequent Phase 8 run refreshed the case. Original incident ID, INVESTIGATING state and assigned analyst were preserved. The audit recorded the selected reputation source. No live HTTP occurred in that test.

## Issues encountered and fixes

1. The existing database-status test expected 14 tables. It now expects 16 after the two new cache/cooldown tables; migration-head assertions now reference `0006_threat_intelligence`.
2. Psycopg batch operations stalled in the temporary embedded wire adapter. The validation-only harness now disables its unsupported pipeline optimization. No application workaround or SQLite substitute was introduced.
3. The first pipeline preservation check incorrectly assumed `incident_processing` had an `id` column. Its scratch validation query was corrected to use the existing `detection_finding_id` primary key, then the full pipeline was rerun successfully.
4. JSON exponent overflow could become a nonfinite Python float. Provider parsing now rejects it before JSONB persistence and tests verify an explicit invalid/unknown result.
5. Credential values are trimmed before HTTP use; response redaction now uses the same trimmed values, preventing a padded configuration value from missing an echoed key. The final provider tests cover this case.
6. Cached rescoring with no usable cache could otherwise retain a misleading local-provider explanation. Cached selection is now explicit in the input snapshot and unknown-context explanation; the default local scoring snapshot remains compatible.
7. Duplicate optional key placeholders and an outdated reserved-keys comment in `.env.example` were consolidated. The actual `.env`, Docker mapping and frontend were not changed.

These checks establish behavior on the synthetic data and controlled provider fixtures only. They do not establish real-world detection accuracy, native concurrency performance, live-provider availability or cloud deployment readiness. Phase 9 is the only implemented phase in this update.
