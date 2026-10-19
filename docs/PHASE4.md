# Phase 4 — Synthetic security-event generation

This update extends the existing Phase 3 project. It generates files only. It does not implement ingestion, detection, incidents, risk scores, intelligence, AI, or dashboard features.

## Install the update

Extract `CyberSentinel-Phase4-Update.zip` **into your existing `cybersentinel` folder**, merging its `backend/` and `docs/` directories. The ZIP contains complete new/updated files, with no extra enclosing project folder. Preserve your working root `.env`, including `POSTGRES_PORT=15432`. There are no dependency changes or migrations; Alembic remains at `0002_auth_sessions`.

The existing Docker service names are `db`, `backend`, and `frontend`. Inside Docker, PostgreSQL remains `db:5432`; port 15432 is the Windows host mapping. Source is already mounted from `./backend` to `/app/backend`.

## Architecture and compatibility

`SecurityEventGenerator` builds fictional profiles, plans complete scenario episodes, and merges ordered iterators by `(timestamp, event_id)`. `export_events` validates each event with the existing Phase 2 `SecurityEventCreate`, checks the simulator vocabulary and address ranges, and streams JSON/JSONL through a temporary file. Only a completed, correctly counted export replaces the destination.

| File / component | Responsibility |
| --- | --- |
| `app/simulation/config.py` | Independent Pydantic configuration; no server secrets or `.env` imports |
| `constants.py` | Event/scenario vocabulary, office locations, services, weights and presets |
| `identities.py` | Stable profiles: 100 employees, 8 managers, 4 analysts, 3 administrators by default |
| `factory.py` | Creates the existing `SecurityEventCreate`; UUID identities, geo facts, optional ground truth |
| `normal_activity.py` | User-day sessions, MFA/retries, application activity, record limits and logout |
| `scenarios.py` | Eleven independent suspicious-sequence builders and complete-episode sizes |
| `generator.py` | Count/distribution planning, namespace construction, chronological stream merge |
| `exporter.py` | Validation, JSON/JSONL export, failure cleanup and summary |
| `scripts/generate_demo_data.py` | Standalone and module CLI entry points |

No duplicate database model/schema is introduced. Phase 2 uses a string `event_type`, so the simulator's local `EventType` enum constrains its own output without changing the shared schema. Exported fields are `event_id`, `timestamp`, source/destination IPs, username, event type, service, ports, country, device, user agent, status and `raw_data`. Database-managed `id`, `created_at`, and `processed` are omitted. SQLAlchemy will supply them in the future ingestion phase.

Simulated identities are monitored employees, separate from the application's authenticated users. They never create login accounts or store passwords. Runtime application health remains the Phase 3 API contract because no server feature changes in this phase.

## Supported event types

`LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGOUT`, `ACCESS_DENIED`, `FILE_ACCESS`, `SENSITIVE_RECORD_ACCESS`, `ADMIN_LOGIN`, `PASSWORD_CHANGE`, `PRIVILEGE_CHANGE`, `PORT_CONNECTION`, `API_REQUEST`, `MALWARE_ALERT`, `MFA_SUCCESS`, `MFA_FAILED`, `ACCOUNT_LOCKED`.

## Supported scenarios

| CLI name | Pattern in generated logs |
| --- | --- |
| `normal` | Daytime login, MFA, internal requests/files, sensitive-record budget, logout; occasional isolated retries |
| `brute_force` | 10–30 failures against one account over 60 seconds by default, then a lock or success one second later |
| `password_spray` | One source targets 15–40 usernames with 1–3 failures per account over 120 seconds |
| `impossible_travel` | Same user succeeds in India and London/New York 20–55 minutes apart, with coordinates |
| `unusual_login` | Employee login at 02:00–04:29 in the profile's India timezone |
| `privilege_escalation` | Login → denied access → employee-to-administrator change → admin login |
| `port_activity` | One source and destination, 20–40 distinct ports over 45 seconds; passive log records only |
| `excessive_access` | 500 distinct fictional sensitive records over 20 minutes by default |
| `abnormal_api` | 500–3,000 actual API-request events over 45 seconds; HTTP metadata and some 429 responses |
| `access_denied` | 8–20 denials for one user across three protected paths over 90 seconds |
| `malicious_ip` | A failed login from one of three documentation IPs, with an optional simulated reputation hint |
| `malware_alert` | A fictional endpoint-security quarantine alert; no executable payload |
| `mixed` | Exact requested count with configurable normal fraction and complete scenario episodes |

Normal working times are local India time (UTC+05:30). Users have varied arrival/departure times and a small stable device set. Exports always use UTC `Z` timestamps. `--start-date`/`--days` define the UTC interval, inclusive start and exclusive end. An unusual login late in a UTC day falls on the following local India calendar day; this is intentional. Ordinary sessions include 5–30 sensitive records per observed user-day; tiny samples under six events per session represent partial observations.

### Sensitive records versus log counts

A record-access log can describe a batch of records. Each includes `record_count`, a matching list of distinct `record_ids`, the first `record_id`, `resource_type: patient_record`, and `department: simulated`. No patient names or medical information are generated.

The default excessive-access episode contains **20 log events × 25 records = 500 records**, across 20 minutes. This allows the requested 1,000-event demonstration to include all five required suspicious patterns while retaining 950 normal logs. Normal sessions also use explicit batches, capped at 30 records per user-day. The summary reports both log counts and record totals.

Use `--records-per-event 1` for one excessive-access record per log. That increases the event budget needed for a complete episode; it does not change the normal baseline. A later access-volume detector should aggregate `raw_data.record_count` and evaluate its time window. The existing CS-007 seed definition still references `FILE_ACCESS`; Phase 6 must align that rule with `SENSITIVE_RECORD_ACCESS` and the record-count contract. This phase does not edit or execute database rules.

### Complete episodes and coverage

Mixed mode first reserves minimum-sized brute-force, spray, travel, unusual-login and excessive-access episodes when they fit, then other scenarios, then weighted additional episodes. It never silently truncates an episode or changes the requested normal ratio. The summary lists omitted scenarios.

- Default 1,000/seed-42: 950 normal + 50 scenario events; all required small-demo categories.
- Default 10,000: 9,500 normal + 500 scenario events. An API burst needs at least 500 events by itself, so it is omitted when reserving other scenarios.
- `--preset medium --normal-ratio 0.92`: 9,200 normal + 800 scenario events; all scenarios fit with default parameters.
- Default 100,000: 95,000 normal + 5,000 scenario events; all scenarios fit.

Individual scenario mode defaults to one complete episode; `normal` and `mixed` default to 1,000 events. An explicit individual `--count` is partitioned into whole episodes. Impossible counts fail with an explanation rather than creating incomplete evidence: travel needs an even count, privilege escalation a multiple of four, and default excessive access a multiple of 20. An API count below 500 is invalid. The ratio option affects only mixed mode.

## CLI reference

| Option | Default / meaning |
| --- | --- |
| `--count N` | Exact count, 1–1,000,000; cannot combine with `--preset` |
| `--preset small\|medium\|large` | 1,000 / 10,000 / 100,000 events |
| `--seed N` | 42; nonnegative integer |
| `--output PATH` | `data/demo_events.<format>`, relative to the current working directory |
| `--format jsonl\|json` | `jsonl`; extension must match format |
| `--start-date YYYY-MM-DD` | Fixed `2026-09-26`, allowing repeatable demos on different days |
| `--days N` | 7 UTC days, 1–365 allowed |
| `--scenario NAME` | `mixed`; names above |
| `--normal-ratio R` | 0.95; fraction from 0 through 1, mixed mode only |
| `--run-id NAME` | `demo`; change for an independently identified dataset |
| `--records-per-event N` | 25, 1–100; excessive-access batch size |
| `--no-ground-truth` | Omit evaluation labels and simulated reputation hint |
| `--overwrite` | Explicitly allow replacement of an existing output file |
| `--help` | Full command help |

Advanced parameters live centrally in `SimulationConfig`, including profile counts, work hours, normal record bounds, brute-force/spray limits, burst sizes/windows and excessive-record totals. Use its validated Python API for overrides beyond CLI options. Locations, services and scenario frequency weights live in `constants.py`. No new environment variables or API keys are needed.

### Reproducibility and ground truth

Event IDs use `EVT-<UUIDv5>`. Scenario IDs use `SIM-<UUIDv5>`, shared by every event in that episode. The namespace includes the seed, generation configuration, generator version and run ID. Equivalent count/preset requests produce identical data. JSON and JSONL serialize the same records. Output filenames and format do not change identities. Repeating an identical request deliberately repeats IDs so later ingestion can deduplicate a replay; use another `--run-id` when both batches should coexist.

Ground truth is isolated under `raw_data.simulation`: `scenario`, `scenario_id`, `generator_version`, `run_id`, and optionally `simulation_expected_reputation`. It is evaluation metadata only. **Phase 6 must derive detections from counts, time windows, users, ports, geo facts and access volumes, never from these labels.** `--no-ground-truth` preserves event behavior and IDs while removing that whole object. `raw_data.environment` remains `simulation` so provenance is explicit. Profile working-hour expectations can be reproduced through `create_profiles(config)`; no future detector is implemented here.

## Exact Windows PowerShell commands

Run from your existing project. Docker is not required for offline generation. If a backend virtual environment already exists, reuse it and skip its creation/install lines.

```powershell
Set-Location 'C:\Users\saiya\OneDrive\Documents\Projects\cybersentinel\backend'

# First local-Python setup only (Python 3.12+ must be installed):
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt

# No activation or PowerShell execution-policy change is needed:
.\.venv\Scripts\python.exe scripts/generate_demo_data.py `
  --count 1000 `
  --seed 42 `
  --scenario mixed `
  --output data/demo_events.jsonl

.\.venv\Scripts\python.exe -m pytest -q tests/test_simulation.py tests/test_simulation_export.py
```

Expected: 1,000 events, 950 normal, 50 suspicious-scenario events; **79 new tests pass**. For deliberate repeats, append `--overwrite`, or select a new output filename. Optional activation is `.\.venv\Scripts\Activate.ps1`; after activation, plain `python` uses that environment.

From the same `backend` directory, generate JSON, a single scenario, and a dataset covering every scenario:

```powershell
.\.venv\Scripts\python.exe scripts/generate_demo_data.py `
  --preset small --seed 42 --format json --output data/demo_events.json

.\.venv\Scripts\python.exe scripts/generate_demo_data.py `
  --scenario brute_force --seed 42 --output data/brute_force_demo.jsonl

.\.venv\Scripts\python.exe scripts/generate_demo_data.py `
  --preset medium --normal-ratio 0.92 --seed 42 --output data/all_scenarios.jsonl

.\.venv\Scripts\python.exe scripts/generate_demo_data.py `
  --scenario excessive_access --records-per-event 1 --output data/record_by_record.jsonl
```

## Exact Docker commands

Run these from the project root after merging the update. No migration or seed command is required for Phase 4.

```powershell
Set-Location 'C:\Users\saiya\OneDrive\Documents\Projects\cybersentinel'
docker compose up --build -d --wait --wait-timeout 180
docker compose ps

docker compose exec backend python scripts/generate_demo_data.py `
  --count 1000 `
  --seed 42 `
  --scenario mixed `
  --output data/demo_events.jsonl

docker compose exec backend python scripts/generate_demo_data.py `
  --preset medium --normal-ratio 0.92 --output data/all_scenarios.jsonl

docker compose exec backend python scripts/generate_demo_data.py `
  --preset large --seed 42 --output data/demo_large.jsonl

docker compose exec backend python -m pytest -q tests/test_simulation.py tests/test_simulation_export.py
docker compose exec backend ruff check .

# Existing full-suite runner uses a separate temporary database:
docker compose exec backend python -m scripts.run_database_tests

Invoke-RestMethod http://localhost:8000/api/system/health
Start-Process http://localhost:8000/docs
Start-Process http://localhost:5173
```

The containers should remain healthy. The existing test runner creates/drops its own random test database and leaves development data intact. Expected full-suite result: **207 passed**; a pre-existing Starlette/httpx deprecation warning may appear. Plain `python -m pytest -q` without `TEST_DATABASE_URL` skips database-dependent tests; use `scripts.run_database_tests` to run them against PostgreSQL. Do not point `TEST_DATABASE_URL` at your development database manually.

For offline generation without starting the whole stack, after the backend image exists:

```powershell
docker compose run --rm --no-deps backend python scripts/generate_demo_data.py `
  --scenario abnormal_api --output data/api_burst.jsonl
```

The existing Compose file still requires the working root `.env` when resolving this command, although the generator itself does not read settings or connect to services.

## Inspect the generated file

From the **project root**:

```powershell
Get-Content .\backend\data\demo_events.jsonl -TotalCount 5
(Get-Content .\backend\data\demo_events.jsonl).Count

$events = @(Get-Content .\backend\data\demo_events.jsonl | ForEach-Object { $_ | ConvertFrom-Json })
$events.Count
($events.event_id | Sort-Object -Unique | Measure-Object).Count
$events | Group-Object { $_.raw_data.simulation.scenario } | Sort-Object Name | Format-Table Name, Count
$events | Group-Object event_type | Sort-Object Name | Format-Table Name, Count

$events | Where-Object { $_.raw_data.simulation.scenario -eq 'excessive_access' } |
  ForEach-Object { $_.raw_data.record_count } | Measure-Object -Sum

Get-FileHash .\backend\data\demo_events.jsonl -Algorithm SHA256
```

Expected counts: 1,000 lines, 1,000 events, 1,000 distinct IDs, excessive-access record sum 500. The PowerShell inspection above loads the small file; for a large line count use `(Get-Content .\backend\data\demo_large.jsonl | Measure-Object -Line).Lines`. From inside `backend`, the corresponding path is `data\demo_events.jsonl`.

The generated data is ignored by Git and Docker build context, while `backend/data/.gitkeep` is retained. Datasets are deliberately not included in the update ZIP. Recreate them with the commands above. [PHASE4_EXAMPLES.md](PHASE4_EXAMPLES.md) contains five complete events extracted from the verified seed-42 small dataset.

## Verification and issues resolved

See [PHASE4_VALIDATION.md](PHASE4_VALIDATION.md) for measured export results, hashes, scenario counts, test environment and limitations. [PHASE4_FILES.md](PHASE4_FILES.md) lists complete changed files.

- All existing models, request schemas, enums, session setup, ID conventions, dependencies, Docker mounts, and timezone behavior were inspected before implementation. The simulator reuses the existing schema and adds no shared-model migration.
- Small-demo coverage and a 95% normal ratio would conflict if every sensitive record required its own log. Explicit, validated record batches resolve this while preserving a real 500-record access volume.
- Large bursts cannot fit every mixed event budget. The planner reports omitted scenarios and preserves complete episodes; all-scenario commands are provided above.
- India baseline hours and UTC export times are handled explicitly with a fixed UTC+05:30 timezone; no platform-specific timezone package is needed on Windows.
- Repeated exports preserve IDs for reproducibility; `--run-id` prevents collisions between independently intended batches.
- Existing output files require `--overwrite`; failed validation/write leaves an existing destination intact and removes temporary output.
- Generated files are excluded from both version control and Docker image layers.
- No new packages were needed. The existing Starlette/httpx warning is unrelated to Phase 4 and does not fail tests.

Phase 4 stops here. JSONL → validated ingestion belongs to Phase 5; behavior-based detection belongs to Phase 6.
