# Phase 7 file manifest

The incremental update contains **25 complete files: 16 new and 9 modified**. Paths are relative to the existing `cybersentinel` project root. Merge these files into that root while retaining all other files. No existing source file is removed.

The actual `.env`, database volumes, generated datasets, frontend, Dockerfiles, Compose file, dependency locks, authentication, generator, ingestion and detection implementations are not replaced. Optional risk limits have defaults, so existing environment settings remain valid.

## Created files

| Path | Purpose |
| --- | --- |
| `backend/alembic/versions/0004_risk_assessments.py` | Risk table, foreign key, version uniqueness, score/category/explanation constraints and indexes |
| `backend/app/models/risk_assessment.py` | Assessment ORM model and existing-finding relationship |
| `backend/app/repositories/risk_repository.py` | Bounded evidence/context queries, version-scoped persistence, filters and statistics |
| `backend/app/risk/__init__.py` | Risk package |
| `backend/app/risk/config.py` | Central v1 recipe, validated policy and sensitivity mappings |
| `backend/app/risk/components.py` | Six deterministic components, rounding and risk category conversion |
| `backend/app/risk/calculator.py` | Evidence validation, explicit scoring facts, breakdown, total and input hash |
| `backend/app/risk/engine.py` | Transactional batches, normal/rescore/dry modes, metrics and summary audit |
| `backend/app/routes/risk.py` | Four authenticated risk API operations with existing RBAC |
| `backend/app/schemas/risk.py` | Typed requests, filters, assessment responses, statistics and run summaries |
| `backend/scripts/run_risk_scoring.py` | Development CLI with all six requested options |
| `backend/tests/test_risk_calculator.py` | 64 component, rule-specific, boundary, stability and policy tests |
| `backend/tests/test_risk_engine.py` | 34 persistence, constraints, rescoring, failure, API/RBAC and CLI tests |
| `docs/PHASE7.md` | Full architecture, formulas, schema, semantics, PowerShell/Docker, SQL and Swagger guide |
| `docs/PHASE7_VALIDATION.md` | Actual full-suite and pipeline results, distributions, issues and limits |
| `docs/PHASE7_FILES.md` | This manifest |

## Modified files

| Path | Change |
| --- | --- |
| `.env.example` | Optional risk batch/context settings; no real credentials |
| `README.md` | Phase 7 status, risk architecture/formula/example, API table and migration head |
| `backend/app/config.py` | Typed risk policy and bounded engine settings |
| `backend/app/main.py` | Risk router, private-response cache headers and Phase 7 version |
| `backend/app/models/__init__.py` | Register the risk model for ORM/Alembic discovery |
| `backend/app/routes/system.py` | Remove delivered risk scoring from planned modules |
| `backend/app/schemas/health.py` | Phase/version defaults |
| `backend/tests/test_database.py` | Expect risk table and new migration head |
| `backend/tests/test_database_api.py` | Expect new head and schema count |

Rebuild, then run `docker compose exec backend alembic upgrade head`. Expected revision: `0004_risk_assessments`. Do not generate a replacement initial migration. See [PHASE7.md](PHASE7.md) for the complete upgrade and verification sequence.
