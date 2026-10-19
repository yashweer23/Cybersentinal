# Phase 8 — Complete file manifest

This incremental package targets the existing Phase 7 project. Paths below are relative to the `cybersentinel` project root. Every packaged source file contains its complete contents, not patch fragments.

The update contains **16 new files and 12 modified files**. It deletes no existing files. SHA-256 comparison against the saved 206-file Phase 7 baseline confirms the other **194 baseline files are unchanged**.

## Files created

| Path | Purpose |
| --- | --- |
| `backend/alembic/versions/0005_incident_workflow.py` | Extends existing incident/evidence tables; creates finding links and processing state |
| `backend/app/incidents/__init__.py` | Incident domain package |
| `backend/app/incidents/correlation.py` | Pure correlation contexts, policy, hard guards, scores and deterministic tie-breaking |
| `backend/app/incidents/engine.py` | Promotion, correlation, evidence, idempotent state, read-only planning and transactional batch processing |
| `backend/app/incidents/workflow.py` | Central assignment, status transition, closure, reopening and note operations |
| `backend/app/models/incident_finding.py` | Unique case/finding links with relationship explanations |
| `backend/app/models/incident_processing.py` | Separate evaluation hashes and deferred-context state |
| `backend/app/repositories/incident_repository.py` | Bounded SQL queries, persistence, investigation projections, timeline and statistics |
| `backend/app/routes/incidents.py` | Eleven incident API operations using existing authentication and RBAC |
| `backend/scripts/run_incident_processing.py` | Trusted development CLI with five requested options and measured summaries |
| `backend/tests/test_incident_api.py` | Incident endpoints, investigation workflow, RBAC, filtering and Swagger tests |
| `backend/tests/test_incident_correlation.py` | Policy, identity, temporal, request-validation and transition tests |
| `backend/tests/test_incident_engine.py` | Persistence, promotion, later correlation, repeat safety, dry-run, rollback and evidence tests |
| `docs/PHASE8.md` | Architecture, policy, schema, API contracts and exact Windows/Docker/SQL verification commands |
| `docs/PHASE8_VALIDATION.md` | Actual regression, migration, pipeline, performance and correlation results with limits |
| `docs/PHASE8_FILES.md` | This manifest and installation instructions |

## Files modified

| Path | Modification |
| --- | --- |
| `.env.example` | Documents seven optional incident settings; existing environment values remain compatible |
| `README.md` | Phase 8 delivery, incident architecture, commands, migration, endpoints and documentation links |
| `backend/app/config.py` | Validated incident policy and batch-limit defaults |
| `backend/app/main.py` | Registers incident routes and advances application version to 0.8.0 |
| `backend/app/models/__init__.py` | Registers both new models for SQLAlchemy and Alembic |
| `backend/app/models/incident.py` | Adds observation/closure/risk-context fields, indexes and link relationship |
| `backend/app/models/incident_evidence.py` | Adds originating finding reference to existing event evidence |
| `backend/app/routes/system.py` | Updates implemented/planned component reporting for incident management |
| `backend/app/schemas/health.py` | Compatible typed health component update |
| `backend/app/schemas/incident.py` | Adds bounded workflow/request/response schemas while preserving existing Phase 2 schemas |
| `backend/tests/test_database.py` | Updates expected tables and migration head for the extended database |
| `backend/tests/test_database_api.py` | Updates expected migration head in database status checks |

## Apply to the existing project

Merge the ZIP contents directly into the existing project root, replacing only the listed modified files. Do not create a second nested `cybersentinel` directory. If you made independent edits to these files after Phase 7, compare and merge those edits before replacing them.

The archive contains no actual `.env`, credentials, generated event files, PostgreSQL data, virtual environments or dependency caches. Your Docker Compose configuration, Dockerfiles, dependency locks and frontend files are unchanged. Keep your actual `.env` and existing PostgreSQL host-port setting.

In the VS Code PowerShell terminal:

```powershell
Set-Location 'C:\Users\saiya\OneDrive\Documents\Projects\cybersentinel'
docker compose up --build -d --wait --wait-timeout 180
docker compose exec backend alembic upgrade head
docker compose exec backend alembic current
docker compose exec backend python scripts/run_incident_processing.py --dry-run --until-empty
docker compose exec backend python scripts/run_incident_processing.py --until-empty
docker compose exec backend python scripts/run_incident_processing.py --until-empty
docker compose exec backend python -m scripts.run_database_tests
```

Expected migration head: `0005_incident_workflow`. Processing requires findings already scored by Phase 7; the guide includes the full generation/import/detection/scoring sequence if needed. An unchanged second processing run creates no new incidents.

No new dependency installation or seed data is required for Phase 8. The existing seed script remains idempotent. See [PHASE8.md](PHASE8.md) for HTTP/Swagger checks, investigation requests, database queries and command variants. See [PHASE8_VALIDATION.md](PHASE8_VALIDATION.md) for the verification actually performed and the remaining environment-specific checks.
