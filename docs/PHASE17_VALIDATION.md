# Phase 17 verification — documentation and portfolio polish

**Status: implemented and checked in the available environment. Native Docker/Windows/recovery gates remain explicit.** No Phase 18 cloud deployment was started.

The update contains a rewritten README, current architecture/API/database/security/setup guides, demo/interview material, real screenshots and a concise changelog/contribution guide. It preserves earlier phase evidence. The sole application edit removes the stale “Phase 15” footer label; domain behavior, API contracts, environment names, dependency locks, Docker configuration and migrations are unchanged.

## Checks actually performed

| Check | Result / boundary |
| --- | --- |
| Restore and inspect baseline | All sixteen saved phase archives restored in order; 452 baseline files inventoried before edits |
| Current ORM metadata | 17 domain tables, actual FK/index/uniqueness inventory used for documentation |
| Current OpenAPI | 87 paths, 88 unique operations in development/test; full route/role table checked |
| Clean and populated migrations | `upgrade head` and metadata drift checks passed in a disposable schema; head `0008_ai_analyses` |
| Fresh synthetic pipeline | 10,000 generated/ingested/evaluated events; 36 findings, 36 assessments, 29 incidents, 160 case-evidence rows |
| Integrity / replay | Zero bad evidence/FK references or duplicate fingerprints; unchanged raw-event hash excluding `processed`; zero pending events; replay created zero findings |
| API / docs / readiness | Existing validation runner's authenticated read/report endpoints, anonymous denial, `/docs`, OpenAPI uniqueness and readiness passed |
| Frontend | Production build passed; 86 Vitest tests across seven files passed in 5.70 seconds |
| Static Python | Ruff passed |
| Real browser | 13 screenshots in Chromium 153, 1440×900; no page exceptions or unexpected API failures in capture navigation |
| Diagrams | All 20 Mermaid blocks across current/historical docs parsed and rendered successfully |
| Documentation links | 187 local file/heading links checked; zero broken |
| CLI / example contracts | Eight CLI help commands and nine request/query schema examples passed |
| Secrets | 16 unchanged known fixture/scenario/canary candidates; no live secret identified; no Git history available |

The fresh pipeline used Python 3.12.14, Node 24.19.0, PGlite 0.5.10 / PostgreSQL 18.6 over a local TCP adapter, a single-connection pool and the real application services. Frontend screenshots used a production React bundle with Vite preview proxying FastAPI; they are not evidence of Docker/Nginx execution. An adapter framing/prepared-statement compatibility shim was confined to the temporary validation harness, not application code or dependencies.

## Measured pipeline

| Stage | Wall time (ms) |
| --- | ---: |
| generate | 1,081.116 |
| ingest | 5,332.312 |
| detect | 11,052.652 |
| risk | 88.676 |
| incidents | 401.335 |
| ingest_repeat | 5,062.447 |
| detect_replay | 7,393.134 |
| intelligence_0 | 244.145 |
| ai_fallback | 134.482 |

Detection throughput: 904.76 events/s in this embedded environment. These figures do not establish native production capacity or an improvement over the different Phase 16 runtime.

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

All ten rules executed. The existing mixed generator's suspicious-event budget did not include the API burst. One labeled denial scenario fell below threshold: 36/37 expected units covered; no claim of real-world accuracy or precision. One scripted case was assigned/investigated/commented/resolved to exercise the workflow; screenshot response-time metrics therefore describe a synthetic scripted action.

## Documentation/command review

README startup commands were checked against actual Compose service names, ports, working directories, environment initializer, seed/admin scripts and Alembic head. Eight documented CLI modules returned help successfully. Request bodies and query parameter names were checked against Pydantic/OpenAPI, including `range=7d` for reports (the frontend URL uses a separate `period` parameter). The pipeline executes the corresponding generator/ingestion/engine services and migration code.

Full `docker compose up --build`, Windows PowerShell execution, image restart/outage and native archive restore could not be run in this environment. They are **not marked passed**. Use [README quick start](../README.md#quick-start), [SETUP.md](SETUP.md) and [TESTING.md](TESTING.md) on your workstation. The complete backend suite was not rerun for this domain-unchanged documentation phase; the preserved Phase 16 result is 799 passed, one native-concurrency skip, zero failures. A Starlette TestClient httpx deprecation warning remains; no dependency was changed merely to silence it.

## Issues corrected during documentation

- Replaced historical example thresholds with fresh-seed values: spraying 8 accounts, ports 20, sensitive records 500 and API requests 200.
- Documented replaceable per-version risk assessments rather than claiming immutable scoring history.
- Distinguished native/embedded measurements, current/rolling time cohorts, and unknown/mock intelligence from real reputation.
- Corrected a draft report query parameter and a documentation link before packaging.
- Replaced the UI's stale phase label without altering navigation or business behavior.
- Preserved the dependency lockfile, `.env` contract, prior operational guides and all database migration files.

## Remaining work before deployment

1. Run native Docker Desktop and Windows PowerShell acceptance, including schema readiness after startup.
2. Verify the independent-writer case on native PostgreSQL, restart/outage recovery and archive restore into a separate database.
3. Review real Git staged/history content and choose a project license; no repository remote or publication was supplied.
4. Separately validate optional live provider/model behavior if enabled. No external calls were needed here.
5. Plan HTTPS, managed secrets/database operations and cloud deployment only in Phase 18.

See [phase17_results.json](phase17_results.json) for sanitized measurements, [PERFORMANCE.md](PERFORMANCE.md) for the dated comparison, [SCREENSHOTS.md](SCREENSHOTS.md) for capture conditions and [PHASE17_FILES.md](PHASE17_FILES.md) for installation/file inventory.
