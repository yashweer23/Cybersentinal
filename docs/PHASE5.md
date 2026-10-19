# Phase 5 — Security log ingestion

Merge `CyberSentinel-Phase5-Update.zip` into the existing `cybersentinel` project root. It contains complete new/updated files and no extra enclosing folder. Preserve your actual `.env`, existing data, admin accounts, and `POSTGRES_PORT=15432`. The optional defaults added to `.env.example` do not require editing your working `.env`.

No database migration, dependency install, frontend edit, Dockerfile change, or Compose change is required. Alembic's head remains `0002_auth_sessions`. The API reports version `0.5.0`, phase 5; its readiness check still executes only `SELECT 1`.

## Architecture

API routes and the trusted CLI share `EventIngestionService`. The existing `SecurityEventCreate` handles canonical fields, UTC conversion and validation; `event_normalizer` adds bounded diagnostics and an event byte limit. The repository sends one PostgreSQL insert per batch with `ON CONFLICT (event_id) DO NOTHING RETURNING event_id, id`. The service commits valid events and, for manual API ingestion, one audit summary in the same transaction.

| Component | File |
| --- | --- |
| Shared normalization/JSON validation | `backend/app/core/event_validation.py` |
| Existing event request/response schemas | `backend/app/schemas/security_event.py` |
| Batch responses, diagnostics, filters and statistics | `backend/app/schemas/event_ingestion.py` |
| Ingestion orchestration and transaction ownership | `backend/app/services/event_ingestion.py` |
| Schema reuse and safe error messages | `backend/app/services/event_normalizer.py` |
| JSON/JSONL parsing and file batching | `backend/app/services/event_files.py` |
| Insert, lookup, filtered list and grouped statistics queries | `backend/app/repositories/security_event_repository.py` |
| Authenticated endpoints | `backend/app/routes/events.py` |
| Request byte limits and strict JSON transport checks | `backend/app/security/ingestion_limits.py` |
| Trusted development import entry point | `backend/scripts/ingest_events.py` |

There are no duplicate models, sessions, role enums or event schemas. Existing `get_db`, `get_current_user`, `require_roles`, `record_audit`, the `SecurityEvent` model, and its unique constraint are reused. `raw_data` remains JSONB and is preserved without inserting or overwriting ingestion/simulation metadata. The database-managed `created_at` already records persistence time. No metric is written per event; the stats endpoint aggregates persisted rows.

## Validation and normalization contract

| Field | Behavior |
| --- | --- |
| `event_id` | Required, 1–128 characters; first character alphanumeric, subsequent letters/digits/dot/colon/underscore/hyphen. Whitespace trimmed, case preserved. Phase 4 UUID IDs and earlier `evt-fixture` style IDs work. |
| `timestamp` | Required timezone-aware ISO-8601 string or aware Python datetime; converted to UTC. Malformed/naive dates and numeric epoch inputs are rejected. |
| IPs | Valid IPv4/IPv6 **host** addresses, canonically represented. Source required, destination optional. CIDR networks, scope suffixes and numeric encodings rejected. No IP is contacted. |
| Ports | Optional integers from 0–65535; booleans and out-of-range values rejected. |
| `event_type` | Trimmed and uppercased; symbolic form `[A-Z][A-Z0-9_]{0,63}`. All 15 generator types work. Additional producer types using this format are supported; ingestion does not classify them. |
| `status` | Trimmed/lowercased, nonempty, maximum 64 characters. |
| Username/service/country/device/user agent | Existing length limits retained; outer whitespace trimmed. Monitored usernames and service identifiers retain case because their source systems may be case-sensitive. Country names are not guessed/remapped. |
| `raw_data` | JSON object, default `{}`; raw values, whitespace, keys and simulation labels preserved. Non-finite/non-JSON values, NULs, invalid Unicode, oversized integers and nesting deeper than 32 levels rejected. |
| Managed fields | Caller-supplied `id`, `created_at`, `processed`, or other unknown top-level fields rejected. `processed=false` is assigned on every insertion. |

JSON inputs use UTF-8, reject duplicate object keys/non-finite constants, and have a document nesting limit of 64. JSONL accepts a UTF-8 BOM at the file start, LF/CRLF and blank lines. Blank lines are not counted as events, but physical line numbers are retained in diagnostics. Invalid UTF-8, malformed JSON, and oversized JSONL lines are rejected individually; the parser resumes at the next line.

JSON files may contain an array or one event object. JSON syntax must be valid before any item is inserted. A structurally valid document can still have invalid event objects, which are reported individually. JSON files are bounded in size; use JSONL for 100,000-event datasets.

All normalization is deterministic. Ground-truth labels are stored as supplied; they do not trigger detection, risk scores, reputation queries or incidents.

## Deduplication and transactions

The normalized, case-sensitive producer `event_id` is the idempotency key. Every record is validated before deduplication. The first valid occurrence within a batch wins. PostgreSQL's existing unique constraint and atomic `ON CONFLICT DO NOTHING` handle rows already stored and competing insert attempts; there is no per-event existence query. A duplicate never overwrites its existing timestamp, raw data, status or processed flag.

For each batch, `received = inserted + duplicates + invalid + failed`, and `valid = received - invalid`. Validation errors do not prevent valid neighbors from being stored. An SQL failure rolls back the current transaction and reports its valid inputs as failed; a connection loss around commit can leave the outcome uncertain, so responses deliberately say the write could not be confirmed. Replaying the batch/file is safe by event ID.

The CLI commits each batch (default 500 events), retains earlier successful batches, and stops reading after a database failure. `complete=false` means a file was not fully processed. It never reports unexamined lines as processed. API audit failure also rolls back the event batch. Audit summaries contain counts and the authenticated actor, without raw events, credentials or JWTs. The trusted CLI does not create a synthetic analyst account or one audit row per event.

## Endpoints and RBAC

All routes use the existing Bearer JWT authentication. Expired, revoked, disabled-user and missing sessions retain Phase 3 behavior.

| Method | Route | Access | Result |
| --- | --- | --- | --- |
| POST | `/api/events/ingest` | ADMIN, ANALYST | 201 accepted; 200 duplicate; 422 invalid; 503 unconfirmed DB write |
| POST | `/api/events/ingest/batch` | ADMIN, ANALYST | 200 counted results, including partial validation success; 503 on DB failure |
| GET | `/api/events` | ADMIN, ANALYST, VIEWER | Filtered, paginated rows |
| GET | `/api/events/stats` | ADMIN, ANALYST, VIEWER | Stored/processed/unprocessed counts, latest event time, counts by event type |
| GET | `/api/events/{event_id}` | ADMIN, ANALYST, VIEWER | Producer event-ID lookup; 404 when absent |

`database_id` in a single-event ingestion response is a **UUID**, matching the existing Phase 2 primary key. The path lookup uses `event_id`, not this internal UUID. Static `/stats` is registered before the identifier route.

Batch requests have the shape `{"events": [{...}, {...}]}`. A missing/empty/oversized envelope returns 422; exceeding a lower configured batch limit returns 413. Valid envelopes report each invalid item with a one-based `index`. Errors are capped by `INGESTION_MAX_ERRORS`, with `errors_omitted` reporting the remainder. POST bodies require `Content-Type: application/json`; unsupported content/encoding returns 415, malformed JSON returns 422, and an oversized body returns 413. Actual streamed bytes are counted regardless of `Content-Length`. Responses use `Cache-Control: no-store`.

Example batch result:

```json
{
  "received": 3,
  "inserted": 1,
  "duplicates": 1,
  "invalid": 1,
  "failed": 0,
  "valid": 2,
  "errors": [{"index": 3, "line": null, "code": "invalid_event", "message": "source_ip: value is not a valid IPv4 or IPv6 address"}],
  "errors_omitted": 0,
  "duration_ms": 4.2,
  "complete": true
}
```

This response is illustrative; timings are measured per run and error wording comes from validation. The validation report contains actual measured imports.

### Query parameters

- `limit`: default 50, 1–500; `offset`: default 0, 0–1,000,000. This matches the project's existing limit/offset convention.
- Exact-match filters: `event_type`, `username`, `source_ip`, `destination_ip`, `service`, `status`, `processed`.
- Inclusive bounds: `start_time`, `end_time`, both timezone-aware. Start after end returns 422.
- `sort_by`: `timestamp` (default), `created_at`, or `event_id`.
- `sort_order`: `desc` (default) or `asc`; UUID supplies a stable tie-breaker.

All predicates/pagination/sorting execute in PostgreSQL using SQLAlchemy expressions and a column whitelist. User input never becomes a raw SQL column/expression. Total and items are separate queries under the existing default transaction isolation, so a concurrent ingestion can change the total between them. Statistics use one grouped query; they are current storage statistics for development-scale data, without caching or security analytics.

## Configurable limits

These optional variables have defaults in `Settings`. Leave your existing `.env` intact unless changing a limit deliberately.

| Variable | Default | Meaning |
| --- | --- | --- |
| `INGESTION_MAX_BATCH_SIZE` | 1000 | Maximum valid envelope/transaction size; configurable down to 1, hard ceiling 1000 |
| `INGESTION_MAX_ERRORS` | 20 | Maximum diagnostics in a response/CLI summary; 1–100 |
| `INGESTION_MAX_EVENT_BYTES` | 262144 | Maximum canonical event size and physical JSONL line bytes; 256 KiB by default |
| `INGESTION_MAX_REQUEST_BYTES` | 8388608 | Maximum POST body bytes; 8 MiB by default |
| `INGESTION_MAX_JSON_FILE_BYTES` | 16777216 | Maximum whole JSON file bytes; 16 MiB by default; JSONL has no total-file cap |

## Docker / Windows PowerShell workflow

Run from the existing project root after merging the ZIP:

```powershell
Set-Location 'C:\Users\saiya\OneDrive\Documents\Projects\cybersentinel'
docker compose up --build -d --wait --wait-timeout 180
docker compose ps
docker compose exec backend alembic current
```

Expected: three healthy services; Alembic `0002_auth_sessions (head)`. No new migration is needed. PostgreSQL continues to use `db:5432` inside containers and your existing 15432 host mapping.

You already generated the Phase 4 sample. To create an equivalent fresh file without overwriting it:

```powershell
docker compose exec backend python scripts/generate_demo_data.py `
  --count 1000 --seed 42 --scenario mixed --output data/phase5_demo.jsonl

docker compose exec backend python scripts/ingest_events.py `
  --file data/phase5_demo.jsonl --batch-size 500

# Run the identical import again:
docker compose exec backend python scripts/ingest_events.py `
  --file data/phase5_demo.jsonl --batch-size 500
```

Alternatively, import `data/demo_events.jsonl` directly using the same two commands. The two output filenames do not change producer IDs; if either file has already been imported, those IDs will correctly be duplicates. If `phase5_demo.jsonl` already exists, reuse it or append the generator's `--overwrite` to deliberately reproduce it.

With no matching IDs initially stored:

| Run | Read | Inserted | Duplicates | Invalid | Failed | Unique demo rows |
| --- | --- | --- | --- | --- | --- | --- |
| First | 1000 | 1000 | 0 | 0 | 0 | 1000 |
| Repeat | 1000 | 0 | 1000 | 0 | 0 | 1000 |

Existing unrelated events remain in the database, so the total table count can exceed 1000. Do not clear development data to force the example count. New rows remain unprocessed.

### JSON, large JSONL, diagnostics and tests

```powershell
docker compose exec backend python scripts/generate_demo_data.py `
  --preset small --format json --output data/phase5_demo.json
docker compose exec backend python scripts/ingest_events.py --file data/phase5_demo.json

docker compose exec backend python scripts/generate_demo_data.py `
  --preset medium --output data/phase5_medium.jsonl
docker compose exec backend python scripts/ingest_events.py `
  --file data/phase5_medium.jsonl --batch-size 500

docker compose exec backend python scripts/generate_demo_data.py `
  --preset large --output data/phase5_large.jsonl
docker compose exec backend python scripts/ingest_events.py `
  --file data/phase5_large.jsonl --batch-size 500

docker compose exec backend python scripts/ingest_events.py `
  --file data/phase5_demo.jsonl --rejected-output data/phase5_rejected.jsonl

docker compose exec backend python -m scripts.run_database_tests
docker compose exec backend ruff check .
Invoke-RestMethod http://localhost:8000/api/system/health
```

The existing runner creates/drops only its own random test database. Expected current result: **278 passed**, with one pre-existing Starlette/httpx deprecation warning. Unit-only `python -m pytest -q` skips database-dependent tests without a test URL. No `httpx2` or dependency replacement is needed for this phase.

The optional rejected-output file contains only `index`, `line`, `code` and `message`, never the original event payload. It must be a new `.jsonl` filename, separate from the input. If every record is valid it is empty. Errors in a run that has already committed batches do not remove those earlier batches.

## Local Python in PowerShell

Reuse the backend virtual environment created in prior phases. The importer reads your root `.env` and connects to the published database port; unlike the generator it requires PostgreSQL to be running.

```powershell
Set-Location 'C:\Users\saiya\OneDrive\Documents\Projects\cybersentinel'
docker compose up -d db
Set-Location .\backend

.\.venv\Scripts\python.exe scripts/ingest_events.py `
  --file data/demo_events.jsonl --batch-size 500
.\.venv\Scripts\python.exe -m scripts.ingest_events `
  --file data/demo_events.jsonl --batch-size 500

.\.venv\Scripts\python.exe -m pytest -q tests/test_event_ingestion_unit.py
.\.venv\Scripts\python.exe -m scripts.run_database_tests
```

If that local environment is not installed yet, create it once with `py -3.12 -m venv .venv`, then `.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt` from `backend`. No new packages were added. Local connection settings should remain `POSTGRES_HOST=127.0.0.1` and your actual `POSTGRES_PORT=15432`; Compose supplies `db:5432` overrides inside containers.

CLI options: required `--file`, optional `--format json|jsonl`, `--batch-size`, and `--rejected-output`. Default batch size is the smaller of 500 and the configured maximum. `--help` works via either entry point. CLI use is restricted to `APP_ENV=development` or `test`, with trusted local database credentials; it does not bypass HTTP authorization through an API endpoint.

Exit codes: **0** means all input records were handled successfully (duplicates count as success); **2** means invalid records, malformed input or invalid arguments; **1** means configuration, file I/O, or database failure. A partial successful import containing invalid records exits 2 and prints its counts. Read `$LASTEXITCODE` immediately after the command if scripting checks.

## Database verification

From the project root, using the existing default database/user names:

```powershell
docker compose exec db psql -U cybersentinel -d cybersentinel
```

Inside psql:

```sql
SELECT COUNT(*) AS total_events, COUNT(DISTINCT event_id) AS unique_events
FROM security_events;

SELECT event_type, COUNT(*)
FROM security_events
GROUP BY event_type
ORDER BY COUNT(*) DESC, event_type;

SELECT processed, COUNT(*) FROM security_events GROUP BY processed;

SELECT event_id, timestamp, source_ip, username, event_type, processed
FROM security_events ORDER BY timestamp DESC LIMIT 5;

SELECT raw_data->'simulation' AS simulation
FROM security_events WHERE raw_data ? 'simulation' LIMIT 1;

SELECT COUNT(*) FROM incidents;
```

After just the initial fresh sample, both event counts are 1000 and all 1000 have `processed=false`; no incident was created. `incidents` may already contain unrelated development rows, which ingestion preserves. Exit psql with `\q`.

## API verification in PowerShell

From the root, authenticate with an existing ADMIN or ANALYST. Use your actual username if it differs from `admin`. The password prompt is masked; credentials are not put in source files.

```powershell
$credential = Get-Credential -UserName 'admin' -Message 'CyberSentinel login'
$loginBody = @{
  username = $credential.UserName
  password = $credential.GetNetworkCredential().Password
} | ConvertTo-Json
$login = Invoke-RestMethod -Method Post -Uri 'http://localhost:8000/api/auth/login' `
  -ContentType 'application/json' -Headers @{ 'X-CSRF-Guard' = '1' } -Body $loginBody
$headers = @{ Authorization = "Bearer $($login.access_token)" }
Remove-Variable loginBody, credential

Invoke-RestMethod 'http://localhost:8000/api/events?limit=5&offset=0' -Headers $headers
Invoke-RestMethod 'http://localhost:8000/api/events?event_type=LOGIN_FAILED' -Headers $headers
Invoke-RestMethod 'http://localhost:8000/api/events?processed=false' -Headers $headers
Invoke-RestMethod 'http://localhost:8000/api/events/stats' -Headers $headers

$event = Get-Content .\backend\data\demo_events.jsonl -TotalCount 1 | ConvertFrom-Json
Invoke-RestMethod "http://localhost:8000/api/events/$($event.event_id)" -Headers $headers
```

To verify a new single event and a mixed batch, use fresh producer IDs. These steps intentionally add two more events to the database:

```powershell
$event.event_id = 'EVT-API-' + [guid]::NewGuid().ToString()
$body = $event | ConvertTo-Json -Depth 30
Invoke-RestMethod -Method Post 'http://localhost:8000/api/events/ingest' `
  -Headers $headers -ContentType 'application/json' -Body $body
# Same request: duplicate=true, same database_id, no additional row.
Invoke-RestMethod -Method Post 'http://localhost:8000/api/events/ingest' `
  -Headers $headers -ContentType 'application/json' -Body $body

$second = $body | ConvertFrom-Json
$second.event_id = 'EVT-API-' + [guid]::NewGuid().ToString()
$batch = @{ events = @($event, $second, @{ event_id = 'EVT-INVALID' }) } | ConvertTo-Json -Depth 30
Invoke-RestMethod -Method Post 'http://localhost:8000/api/events/ingest/batch' `
  -Headers $headers -ContentType 'application/json' -Body $batch
```

Expected: single accepted, then duplicate; batch `received=3`, `inserted=1`, `duplicates=1`, `invalid=1`, `failed=0`. A table containing only the initial sample then has 1002 rows, all unprocessed. Repeat the login with the existing VIEWER account to check that GET succeeds and both ingestion POST routes return 403. An absent/expired JWT returns 401.

## Swagger verification

1. Open `http://localhost:8000/docs`. Locate **Authentication** and **Security Events**.
2. Execute `/api/auth/login` with your existing ADMIN/ANALYST username and password, plus the `X-CSRF-Guard` header value `1`.
3. Copy `access_token`; click **Authorize**, paste the token into **BearerAuth**, then authorize. The token field expects the JWT itself.
4. Execute `/api/events`, its filters/limit/offset/sort options, `/api/events/stats`, and the producer event-ID lookup.
5. Execute single and batch ingestion with a valid event from your JSONL file. Existing IDs return duplicates; use fresh IDs to test insertion. Invalid batch neighbors appear in the bounded `errors` array.
6. Authorize using a VIEWER token to verify read-only access. Clear authorization to verify 401. Invalid IPs, ports, naive timestamps and excessive query limits should return 422.

The same route schemas and authentication requirements are available at `/openapi.json`. Swagger's UI assets retain the project's existing CDN dependency.

## Verification and limitations

See [PHASE5_VALIDATION.md](PHASE5_VALIDATION.md) for actual runs, measured times, API results, test coverage, issues fixed and environment limits. See [PHASE5_FILES.md](PHASE5_FILES.md) for the full file manifest. Generated files remain under `backend/data/` and are excluded by the existing Git/Docker ignore rules.

This phase stops at persistent, inspectable, unprocessed events. Phase 6 will evaluate behavior, including sensitive-record batch counts, without using simulation labels as detection evidence.
