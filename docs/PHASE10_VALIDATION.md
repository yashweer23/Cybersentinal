# Phase 10 — Executed validation

Validation date: **2026-10-08 UTC**. This report contains measured results, not illustrative dashboard totals. Full response bodies, counts, durations and `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` plans are retained in [phase10-validation.json](phase10-validation.json).

## Environment and limits

- Python 3.12.14, existing FastAPI 0.141.1, SQLAlchemy 2.0.54, Psycopg 3.3.6, Pydantic 2.13.5 and pytest 9.1.1.
- PostgreSQL 17.5 executed through PGlite's PostgreSQL wire adapter in an isolated random schema. These were real PostgreSQL JSONB, INET, enum, constraint, trigger, migration and aggregate operations, not SQLite substitutions or mocked query results.
- The validation-only transport disables Psycopg prepared statements and pipelines because the embedded adapter does not fully support them. Application dependencies, connection code and delivered tests were not changed for this adapter.
- Docker, Windows PowerShell and native PostgreSQL server binaries were unavailable. Docker startup and native concurrent backends are **not claimed verified**. The included concurrency test runs on native PostgreSQL and the guide supplies Docker/PowerShell checks.
- Endpoint timings use in-process FastAPI TestClient with actual JWT verification, database-authoritative session/user lookup, SQL execution and JSON serialization. They do not include browser rendering, HTTP TCP transport or Windows/Docker virtualization overhead.
- Synthetic data and single-user warm timings are development checks, not production capacity or detection-accuracy claims.

## Regression and migration results

```text
645 passed, 1 skipped, 1 warning in 45.51s
ruff check .: All checks passed!
ruff format --check <eight Phase 10 Python files>: 8 files already formatted
```

The **595 existing tests** remain in the suite; Phase 10 adds **51 cases**, of which 50 passed here. The one skip is `test_native_concurrent_writer_cannot_commit_ahead_of_earlier_cursor`, which requires two independent native PostgreSQL backends. The warning is the existing Starlette/httpx TestClient deprecation, not a failing application test; no unrelated dependency change was made.

Verified:

- Clean upgrade through all seven revisions to `0007_dashboard_polling`.
- Alembic metadata comparison: `No new upgrade operations detected.`
- Migration downgrade/upgrade checks and existing-data backfill ordered by `(created_at, id)`.
- Backfilled rows retain their complete pre-migration contents except the added cursor. A subsequent insert receives the next position; downgrade preserves the original event payloads.
- The original updated-at trigger checks still verify the expected function; the additional event-cursor trigger has separate coverage.
- Controlled populations cover zero data, all four incident severities/statuses, historical score versions, disabled/zero-match rules, multiple finding links per case and cases associated with additional source IPs/accounts.
- Time tests cover start/end exclusion, partial buckets, timezone offsets and a non-UTC database session, all five presets, all bucket sizes and zero-filled gaps.
- Polling tests cover older occurrence timestamps arriving later, equal timestamps, retries, multiple pages, empty pages, duplicate/rollback gaps and cursor immutability.
- Every dashboard route returns 401 without credentials and works with ADMIN, ANALYST and VIEWER. Invalid scopes, limits and cursors return 422. A simulated database failure returns sanitized 503; slow-duration/error logs exclude raw exception secrets.
- All 15 routes appear with GET response schemas and bearer security in OpenAPI. `/docs` and `/openapi.json` returned 200. Interactive CDN rendering in a browser was not exercised.

## Complete 10,000-event pipeline

Used the existing generator with **count 10,000, seed 42, mixed scenarios, default 0.95 normal ratio, start date 2026-09-26 and seven days**. Used the existing ingestion, detection, risk, incident and mock-enrichment CLIs. Each returned success.

| Stage | Measured CLI wall time (ms) |
| --- | ---: |
| Ingestion | 5452.537 |
| Detection | 15812.396 |
| Risk | 101.666 |
| Incidents | 742.097 |
| Enrichment | 452.622 |

| Stored result | Count |
| --- | ---: |
| Security events | 10,000 |
| Processed events | 10,000 |
| Invalid / failed ingestion rows | 0 / 0 |
| Findings | 36 |
| Risk assessments | 36 |
| Incidents | 29 |
| Incident-finding links | 29 |
| Incident evidence rows | 160 |
| Cached indicators / result bundles | 34 / 34 |
| External provider requests | 0 |
| Invalid incident-event evidence references | 0 |

Seven findings fell below the existing incident eligibility threshold. The resulting 29 cases were OPEN and HIGH, with average current case score **57.72**. The 36 finding scores averaged **54.86**; these are distinct populations and the dashboard correctly uses the case population for its risk distribution. No formula, threshold or case behavior was changed.

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

All ten rules executed. This fixture did not cross CS-010's existing default threshold; its positive and negative tests still pass. The repeat detection run processed zero new events and created zero findings.

The integration checks independently compared SQL event-type counts, case status/severity/risk aggregates, per-IP distinct case counts and evidence references with dashboard JSON. Timeline and event-type totals matched scoped event totals. Severity/status/risk category totals each matched the case population. Per-rule counts summed to 36.

All **15 authenticated dashboard GETs returned 200**. Hashes of all rows in **16 application tables** before and after the dashboard/API benchmark were identical: events, findings, assessments, incidents, evidence, links, notes, processing state, indicator identities, result bundles, provider state, audits, metrics, users, sessions and rules. This includes authentication reads and proves that those requests did not refresh intelligence or modify pipeline state in the measured run.

## Actual overview response

This explicit custom scope includes the original event dates and the later case-promotion/cache times. A rolling 24-hour event range would legitimately omit the older generated logs.

```json
{
  "scope": {
    "start": "2026-09-26T03:05:12Z",
    "end": "2026-10-08T16:07:53.636145Z",
    "preset": null,
    "as_of": "2026-10-08T16:07:52.722041Z",
    "boundary": "[start,end)"
  },
  "total_events": 10000,
  "events_in_range": 10000,
  "total_incidents": 29,
  "active_incidents": 29,
  "critical_incidents": 0,
  "high_risk_incidents": 29,
  "total_findings": 36,
  "suspicious_ips": 34,
  "average_risk_score": 57.72,
  "unprocessed_events": 0,
  "latest_event_timestamp": "2026-10-02T14:15:57Z"
}
```

An actual top-IP row from the same request population:

```json
{
  "ip": "10.0.1.4",
  "incident_count": 1,
  "finding_count": 1,
  "highest_risk_score": 73,
  "highest_finding_risk_score": 73,
  "latest_activity": "2026-10-02T08:09:12Z",
  "reputation_level": "UNKNOWN",
  "cached_reputation_level": "UNKNOWN",
  "intelligence_status": "fresh",
  "mode": "mock",
  "simulation": true
}
```

Full timeline, event-type, case, rule, account, cache, activity, polling and health responses are available in the validation JSON. Empty populations and unavailable/expired reputation are covered by separate controlled tests.

## 10k and 100k endpoint measurements

Ten samples per endpoint after initial verification/warmup. Durations below are wall-clock milliseconds. SQL statement counts include the existing authentication/session query; event previews additionally fetch a polling watermark. Counts remained constant across sample iterations and dataset sizes, with no per-row query expansion.

| Endpoint suffix | 10k median | 10k p95* | 100k median | 100k p95* | SQL statements/request |
| --- | ---: | ---: | ---: | ---: | ---: |
| `overview` | 20.391 | 29.666 | 76.870 | 95.261 | 2 |
| `events/timeline` | 19.168 | 23.371 | 117.157 | 163.164 | 2 |
| `events/recent` | 7.578 | 8.826 | 8.539 | 24.621 | 3 |
| `incidents/severity` | 6.616 | 9.921 | 6.444 | 7.151 | 2 |
| `threats/top-ips` | 13.940 | 20.369 | 13.228 | 121.406 | 2 |

*Nearest-rank p95 for ten observations is the maximum. The 100k top-IP maximum was a 121.406 ms outlier while its median was 13.228 ms; the report preserves it instead of discarding it. These small samples do not establish production tail latency.*

For the 100k check, the existing generator produced **90,000 additional normal events with seed 43**, and the existing importer inserted all of them with zero invalid/failed/duplicate rows. Import wall time: **56671.324 ms**, with reported throughput **1,588 events/sec**. No events were fabricated directly into SQL for the benchmark.

The resulting dataset contained 100,000 events, 36 findings, 36 assessments and 29 incidents. The additional 90,000 rows intentionally remained unprocessed. This measures larger event tables and backlog reporting, not a 100,000-event full detection pipeline or large case population. The overview reported that backlog accurately.

## Query-plan review

Single `EXPLAIN ANALYZE` execution times below are separate measurements from the HTTP samples; instrumentation and runtime variance explain differences.

| Main SQL query | 10k execution ms | 100k execution ms |
| --- | ---: | ---: |
| overview | 17.190 | 124.853 |
| timeline | 21.545 | 193.268 |
| recent_events | 0.186 | 0.146 |
| severity | 0.095 | 0.119 |
| top_ips | 3.512 | 4.373 |

- Recent-event queries used the existing `ix_security_events_timestamp` index and read 21 candidate rows for a 20-row preview. No extra timestamp index was necessary for this fixture.
- Timeline range filtering used the existing event timestamp index with a bitmap heap scan. The requested scope contains the entire population, so aggregation still examines 10k/100k selected rows.
- Overview combines independent event, case and finding aggregates. Existing pending-order, incident detection-time and finding last-seen indexes appeared in its plans. No cross-product multiplies event or case counts.
- Case/IP joins use existing case-time, association, finding primary-key, score-version and indicator/mode indexes. Pre-aggregated distinct entity/case pairs prevent duplicate case contributions.
- The new cursor uniqueness index supports insertion-order keyset polling and finding the current head. Existing indexes were preserved.
- No response cache, Redis, extra background task or speculative summary index was introduced. The measured workload did not justify them. Global totals and all-range timelines still grow with event-table size and may need future measured pre-aggregation.

## Issues found and resolved

1. Existing UUID/event timestamps could not safely identify new insertions, particularly late-arriving old logs. Added a separate trigger-owned cursor and preserved all existing identities.
2. A sequence alone can expose later committed rows while an earlier writer remains uncommitted. Allocation now follows a transaction advisory lock with `CACHE 1`. Sequential gap/rollback checks pass; native independent-writer verification remains the explicitly skipped test.
3. Alembic's naming convention double-prefixed a check-constraint name during downgrade. Marked the complete name with `op.f`; migration round trips and metadata drift checks pass.
4. A test's inline JSON colon was interpreted as a SQLAlchemy text bind. Changed the fixture to `jsonb_build_object`; application SQL was unaffected.
5. The first benchmark's temporary user placeholder failed the existing password-hash-length constraint. Reused the existing randomly generated bcrypt dummy hash for the fixture and reran the full workflow successfully. No password policy was weakened.
6. Mock/expired/policy-incompatible intelligence and historical risk rows could mislead summaries if joined indiscriminately. Mode/freshness/policy filters and current-score joins are explicit and covered by tests.

## Reproduction

[PHASE10.md](PHASE10.md) contains migration/startup commands, login and endpoint checks, real HTTP timing commands, SQL verification, polling protocol and the native regression-test command. No production credentials or generated event payload files are included in the delivery. Docker and Windows execution remain local verification steps because those runtimes are unavailable here.
