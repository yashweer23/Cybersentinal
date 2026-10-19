# Phase 5 — Complete file manifest

`CyberSentinel-Phase5-Update.zip` is an incremental update for the existing Phase 4 project. It contains **20 complete files: 14 created and 6 modified**. Paths are relative to the existing `cybersentinel` root; there is no enclosing project folder. Merge the contents into that root and replace only the listed modified files. No existing file is deleted.

## Created files

| Path | Purpose |
| --- | --- |
| `backend/app/core/event_validation.py` | Shared field normalization and strict JSON checks |
| `backend/app/repositories/security_event_repository.py` | PostgreSQL batch insertion, conflict handling, lookup, filtering and statistics |
| `backend/app/routes/events.py` | Protected single/batch ingestion and read endpoints |
| `backend/app/schemas/event_ingestion.py` | Batch results, safe diagnostics, query parameters and statistics responses |
| `backend/app/security/ingestion_limits.py` | ASGI request byte limits, content validation and strict JSON parsing |
| `backend/app/services/event_files.py` | Bounded JSON/streaming JSONL readers and batch file orchestration |
| `backend/app/services/event_ingestion.py` | Shared normalization, transaction and counting service |
| `backend/app/services/event_normalizer.py` | Existing event-schema validation, byte limits and sanitized errors |
| `backend/scripts/ingest_events.py` | Trusted development CLI and optional diagnostic output |
| `backend/tests/test_event_ingestion.py` | PostgreSQL/API/file integration and permission tests |
| `backend/tests/test_event_ingestion_unit.py` | Pure validation, parser, transport and CLI tests |
| `docs/PHASE5.md` | Architecture, contracts, configuration and exact Windows/Docker/SQL/Swagger commands |
| `docs/PHASE5_VALIDATION.md` | Actual test results, import measurements, duplicate proof and verification limits |
| `docs/PHASE5_FILES.md` | This manifest |

## Modified files

| Path | Change |
| --- | --- |
| `.env.example` | Five optional ingestion limits with defaults; no credentials |
| `README.md` | Current Phase 5 features, pipeline diagram, endpoints and upgrade links |
| `backend/app/config.py` | Typed and bounded ingestion settings with backwards-compatible defaults |
| `backend/app/main.py` | Event router, ingress middleware, private-response caching headers and Phase 5 version metadata |
| `backend/app/schemas/health.py` | Version/phase metadata; existing health response structure retained |
| `backend/app/schemas/security_event.py` | Shared normalization/validation on the existing event schema |

The existing database models, migrations, connection/session management, authentication implementation, generator, previous tests, package locks, frontend, Compose file and Dockerfiles are unchanged. Alembic remains at `0002_auth_sessions`. No dependency installation or new migration is required.

Your actual `.env`, generated datasets, virtual environments, database contents and validation-only tooling are not in this update. Preserve your working secrets and `POSTGRES_PORT=15432`. Optional settings work without adding anything to your existing `.env`.

Start with [PHASE5.md](PHASE5.md); measured results are in [PHASE5_VALIDATION.md](PHASE5_VALIDATION.md). Stop after Phase 5 verification.
