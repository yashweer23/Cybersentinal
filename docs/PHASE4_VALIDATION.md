# Phase 4 validation — 2026-09-26

## Tests executed

- **79 Phase 4 tests passed**: profile baselines, schema compatibility, safe address ranges, timezone/window checks, all scenario behaviors, per-record volume, unique IDs, determinism, independent run IDs, optional labels, exact counts, invalid inputs, atomic export failure recovery, JSON/JSONL equality, and both CLI entry points.
- **207 tests passed** in the full backend suite, including all 128 pre-existing tests. Elapsed test time: **16.39 seconds**. No tests skipped in this run.
- `ruff check .`: **all checks passed**.
- Fresh-interpreter CLI tests removed database/JWT environment values and used an audit hook that rejects networking or imports of application settings/database/SQLAlchemy. Both direct script and module execution passed.
- The actual CLI generated the required 1,000/seed-42/mixed JSONL and a matching JSON array. Independent JSON parsing and `SecurityEventCreate` validation confirmed all records, unique IDs and chronological timestamps.
- The CLI also generated `--preset medium --normal-ratio 0.92`; all 15 event types and all 12 scenario categories (including normal) were present.

One existing warning remains: Starlette's test client deprecates its current httpx compatibility path. It did not fail tests; Phase 4 did not change dependency locks.

## Measured streaming exports

Times below measure generator planning-independent export, including schema revalidation and file writes, on this execution environment. They are observations, not a production benchmark. Each dataset was subsequently parsed and independently checked for schema validity, unique IDs, exact count and ordered timestamps.

| Event count | Normal | Scenario events | Export time | JSONL size | Omitted scenarios |
| --- | --- | --- | --- | --- | --- |
| 1,000 | 950 | 50 | 0.057 s | 0.87 MiB | privilege_escalation, port_activity, abnormal_api, access_denied, malware_alert |
| 10,000 | 9,500 | 500 | 0.585 s | 8.43 MiB | abnormal_api |
| 100,000 | 95,000 | 5,000 | 5.830 s | 78.04 MiB | All scenarios |

A separate fresh-process large export used **29.75 MiB peak RSS**, compared with **23.25 MiB** before generator construction; incremental peak **6.50 MiB**. This process streamed the export without loading it back into a list. The later independent validator retains an ID set, so it is not part of that memory measurement.

## Required 1,000-event summary

```text
CyberSentinel Synthetic Security Data
Generated: 1,000 events
Normal events: 950 (95.0%)
Suspicious scenario events: 50
Scenario event counts:
  brute_force: 11
  excessive_access: 20
  impossible_travel: 2
  known_malicious_ip: 1
  normal_activity: 950
  password_spray: 15
  unusual_login: 1
Event types: ACCESS_DENIED=3, ACCOUNT_LOCKED=1, ADMIN_LOGIN=3, API_REQUEST=293, FILE_ACCESS=153, LOGIN_FAILED=33, LOGIN_SUCCESS=115, LOGOUT=115, MFA_FAILED=5, MFA_SUCCESS=115, PASSWORD_CHANGE=2, PORT_CONNECTION=27, SENSITIVE_RECORD_ACCESS=135
Sensitive records (separate from log count): excessive_access=500, normal_activity=1,809
Not included in this mixed event budget: privilege_escalation, port_activity, abnormal_api, access_denied, malware_alert
UTC range: 2026-09-26T03:07:56+00:00 to 2026-10-02T14:15:57+00:00
Output (jsonl): data/demo_events.jsonl
Seed: 42
Run ID: demo
Ground truth: included
```

Sensitive records and log events are distinct units. This small demo's excessive-access scenario is 20 logs describing 500 records. Across its normal user-day sessions, 115 record-access logs describe 1,809 records, with each user-day limited to 5–30.

The default 10,000-event file omits the API burst because its entire anomalous budget is 500 events. `--preset medium --normal-ratio 0.92` was separately verified to generate 9,200 normal and 800 scenario events, including a full 500-event API burst. The default 100,000-event file includes every scenario.

## Reproduction hashes

These hashes apply to JSONL with seed 42, start date 2026-09-26, seven days, normal ratio 0.95, run ID `demo`, ground truth enabled and 25 records per excessive-access log. Paths do not affect the data.

| Events | SHA-256 |
| --- | --- |
| 1,000 | `014fbeea16304b1a883abf25adeec65568647906db5a957ecc7e48bb65718a89` |
| 10,000 | `a36a40452e53e67885334e945d92886c352b0075ccf2dd4fb6f83d8039538e50` |
| 100,000 | `572a9f3be51c9d32823f8f3238b7c42c35d6edffacf23375bf5daf6ee0f02cc6` |

## Existing project compatibility

A pre-change SHA-256 inventory of all 127 existing source/documentation files was compared after implementation. Only `README.md`, `.gitignore`, and `backend/.dockerignore` changed. There are no deleted files. Frontend files, server routes, authentication/security code, database models and schemas, Alembic revisions, dependency locks, environment configuration, Compose, Dockerfiles, and existing tests are unchanged.

The full suite used Python 3.12.14 and an isolated **PGlite PostgreSQL 17.5 engine with a Psycopg-compatible socket adapter**. Existing migrations, constraints, database routes, auth/RBAC/session behavior and health checks passed. The adapter-only harness disables Psycopg automatic prepared statements to accommodate its shared session; this does not alter application files. No developer database was used.

Docker Desktop, native PostgreSQL service, and Windows PowerShell are unavailable in this execution environment. Therefore the provided Docker/PowerShell commands have **not** been executed here. The successful database-backed run is evidence from the embedded PostgreSQL adapter, not a claim that the Windows Docker stack was re-tested. The unchanged frontend was not re-built or browser-tested in Phase 4; its prior Phase 3 verification is recorded separately.

## Data and scope

Generated datasets exist under `backend/data/` in the validation workspace and can be recreated by the exact guide commands. They are not shipped in the source update or committed. Five deliberately small, complete examples are embedded in `PHASE4_EXAMPLES.md`.

No generator path imports server settings, creates database rows, contacts an IP, invokes threat intelligence, executes malware, evaluates detection rules, assigns risk, or creates incidents. These are fictional observations for future ingestion and detection tests. No real-world detection accuracy is claimed.
