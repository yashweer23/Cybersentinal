# Phase 5 — Validation report

Validated on 2026-09-26. The complete backend suite passed: **278 passed, 1 warning in 21.79 seconds**, with no skipped tests. This includes all 207 prior tests plus 71 new ingestion tests. Ruff checks passed. No new dependencies or migrations were introduced.

## Environment and limits of verification

Tests and import measurements ran on Linux with Python 3.12.14, the project's existing SQLAlchemy/Psycopg packages, and **PostgreSQL 17.5 through PGlite**, using a disposable database and a validation-only socket adapter. Database behavior was exercised against PostgreSQL, including JSONB, unique constraints, transactions, migrations, and `ON CONFLICT`; SQLite was not substituted.

Docker Desktop, native PostgreSQL containers, and PowerShell were unavailable in this execution environment. Therefore Phase 5's Docker startup, Windows commands and browser-rendered Swagger UI still need the local checks in [PHASE5.md](PHASE5.md). The API's `/docs` HTML and `/openapi.json` responses were checked through FastAPI's test client. The supplied earlier screenshot independently confirms that the user's Phase 4 Docker suite passed its 207 tests.

The embedded adapter serializes database connections, so these measurements are neither production throughput claims nor a concurrent-writer benchmark. Atomic PostgreSQL conflict handling is implemented; real multi-worker contention was not load-tested. The application retains its existing Psycopg driver and connection configuration. Adapter workarounds and benchmark fixtures are not included in the application update.

## Test coverage

| Area | Checks exercised |
| --- | --- |
| Normalization | UTC conversion, canonical IPv4/IPv6, trimmed/case-preserved producer IDs and usernames, normalized event types/status, unchanged raw JSON values |
| Validation | Missing fields, invalid IP/date/port, booleans as ports, caller-supplied managed fields, invalid Unicode/NULs, non-finite JSON, duplicate JSON keys, depth and byte limits |
| Persistence | New rows, existing and within-batch duplicates, unchanged existing processed/raw values, one insert for 500 events without per-event existence queries |
| File imports | JSON arrays/objects, JSONL, blank lines/BOM/CRLF, malformed or oversized lines with valid neighbors, bounded errors and optional safe diagnostic output |
| Repeatability | Both 1,000-event Phase 4 JSON and JSONL datasets imported twice without increasing the stored count |
| Failure handling | Rollback and retry, importer stops after a failed batch, prior batches remain, API audit failure rolls back events, database errors do not expose credentials |
| Authorization | Existing JWT/session authentication; ADMIN and ANALYST ingestion; VIEWER read-only; unauthenticated requests rejected |
| Inspection APIs | Pagination, whitelist sorting, all filters and date bounds, ID lookup, missing ID, grouped statistics and empty table behavior |
| Transport | Actual byte limits for chunked bodies and misleading Content-Length, content type/encoding, malformed/deep JSON rejected before route processing |
| Compatibility | Prior database/authentication/generator tests, OpenAPI schema and both CLI invocation styles |

New tests are in `backend/tests/test_event_ingestion_unit.py` (43 tests) and `backend/tests/test_event_ingestion.py` (28 tests). The one warning is the pre-existing Starlette/httpx test-client deprecation; it did not fail tests and does not require a dependency change in this phase.

## Actual CLI imports and repeat-file proof

The Phase 4 generator produced mixed, seed-42 JSONL files of 1,000, 10,000 and 100,000 events. The actual importer entry point handled each file with `--batch-size 500`, then imported the identical file again. Each dataset used a fresh disposable validation database state; development data was not cleared.

| Events | Run | Inserted | Duplicates | Invalid | Failed | Import duration | Events/second |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | First | 1,000 | 0 | 0 | 0 | 0.438 s | 2,283 |
| 1,000 | Repeat | 0 | 1,000 | 0 | 0 | 0.363 s | 2,753 |
| 10,000 | First | 10,000 | 0 | 0 | 0 | 3.964 s | 2,523 |
| 10,000 | Repeat | 0 | 10,000 | 0 | 0 | 3.631 s | 2,754 |
| 100,000 | First | 100,000 | 0 | 0 | 0 | 39.262 s | 2,547 |
| 100,000 | Repeat | 0 | 100,000 | 0 | 0 | 37.402 s | 2,674 |

Every run reported `complete=true`. Durations cover file parsing, validation, batch inserts and commits; they exclude dataset generation and process/database startup. These timings describe this embedded test environment only. JSONL uses bounded line buffers and batches; no process-level peak-memory measurement was taken.

Direct SQL assertions after each first/repeat pair confirmed:

| Dataset | Stored rows | Distinct event IDs | Unprocessed rows | Incidents |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 1,000 | 1,000 | 1,000 | 0 |
| 10,000 | 10,000 | 10,000 | 10,000 | 0 |
| 100,000 | 100,000 | 100,000 | 100,000 | 0 |

The 1,000-event repeat therefore inserted **zero** rows, reported **1,000 duplicates**, and left exactly **1,000** rows in storage. All new events remained `processed=false`. No detections or incidents were generated.

## API verification against imported data

With the imported 1,000-event dataset and an authenticated test session:

| Request | Observed result |
| --- | --- |
| `GET /api/events?limit=2` | 200; two items, total 1,000 |
| `GET /api/events?event_type=LOGIN_FAILED` | 200; only matching events |
| `GET /api/events?processed=false` | 200; total 1,000 |
| `GET /api/events/stats` | 200; total 1,000, processed 0, unprocessed 1,000 |
| Producer event-ID lookup | 200; stored event returned |
| Single-event repeat POST | 200; duplicate, same stored UUID |
| Batch POST with one existing event and one invalid item | 200; received 2, inserted 0, duplicates 1, invalid 1, failed 0 |
| `GET /api/system/health` | 200 after database readiness query |
| `GET /docs` | 200 HTML |
| `GET /openapi.json` | 200; five event routes with authentication/schema documentation |

The stats response reported 13 event types for this particular small dataset and latest event timestamp `2026-10-02T14:15:57Z`. This is synthetic event time from the generator, not ingestion time or a claim of real observed activity. Larger datasets include scenarios that cannot fit the small event budget.

## Issues found and resolved

1. Large inserts exposed a protocol-framing limitation in the embedded validation socket adapter: TCP fragments were handed to the PostgreSQL engine before a complete message arrived. The validation harness was corrected to buffer complete protocol messages; the unchanged application then completed the full suite and 100,000-event import. No adapter or workaround was added to the runtime project.
2. Deep JSON required an explicit document-level nesting guard in addition to the raw-data guard. Strict JSON parsing now enforces a 64-level document limit; raw data retains its separate 32-level limit. Regression tests cover these cases.
3. Invalid neighboring JSONL records and database failure recovery were verified separately. Invalid records are reported and skipped; a database failure stops at that batch, preserves earlier commits, and permits an idempotent replay.

## Repeat locally

From the existing project root after merging the update:

```powershell
docker compose up --build -d --wait --wait-timeout 180
docker compose exec backend python scripts/ingest_events.py --file data/demo_events.jsonl --batch-size 500
docker compose exec backend python scripts/ingest_events.py --file data/demo_events.jsonl --batch-size 500
docker compose exec backend python -m scripts.run_database_tests
docker compose exec backend ruff check .
```

Use the guide for generating a sample if needed, masked PowerShell login, API requests, SQL checks, expected results and safe retry behavior. Keep your existing `.env` and host port 15432. Phase 6 has not been started.
