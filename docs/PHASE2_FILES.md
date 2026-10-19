# Phase 2 file manifest

Paths are relative to your existing `cybersentinel/` project root. The update ZIP contains the complete contents of every listed file. Copy these files into that same root; do not create a second nested project.

## Modified files

11 existing files were modified:

- `README.md`
- `backend/alembic.ini`
- `backend/alembic/env.py`
- `backend/app/main.py`
- `backend/app/models/__init__.py`
- `backend/app/schemas/health.py`
- `backend/requirements-dev.txt`
- `backend/requirements.in`
- `backend/requirements.txt`
- `backend/tests/conftest.py`
- `docs/FILE_GUIDE.md`

## Created files

43 new files were created:

- `backend/alembic/versions/0001_core_create_core_cybersentinel_tables.py`
- `backend/app/core/__init__.py`
- `backend/app/core/enums.py`
- `backend/app/core/validation.py`
- `backend/app/models/audit_log.py`
- `backend/app/models/common.py`
- `backend/app/models/detection_rule.py`
- `backend/app/models/incident.py`
- `backend/app/models/incident_comment.py`
- `backend/app/models/incident_evidence.py`
- `backend/app/models/security_event.py`
- `backend/app/models/system_metric.py`
- `backend/app/models/threat_intelligence.py`
- `backend/app/models/user.py`
- `backend/app/repositories/__init__.py`
- `backend/app/repositories/threat_cache.py`
- `backend/app/routes/database.py`
- `backend/app/schemas/audit_log.py`
- `backend/app/schemas/common.py`
- `backend/app/schemas/database.py`
- `backend/app/schemas/detection_rule.py`
- `backend/app/schemas/incident.py`
- `backend/app/schemas/incident_comment.py`
- `backend/app/schemas/incident_evidence.py`
- `backend/app/schemas/security_event.py`
- `backend/app/schemas/system_metric.py`
- `backend/app/schemas/threat_intelligence.py`
- `backend/app/schemas/user.py`
- `backend/app/security/passwords.py`
- `backend/scripts/run_database_tests.py`
- `backend/scripts/seed_demo_users.py`
- `backend/scripts/seed_detection_rules.py`
- `backend/tests/__init__.py`
- `backend/tests/database_fixtures.py`
- `backend/tests/test_database.py`
- `backend/tests/test_database_api.py`
- `backend/tests/test_database_test_runner.py`
- `backend/tests/test_schemas.py`
- `backend/tests/test_seeds_and_cache.py`
- `docs/PHASE2.md`
- `docs/PHASE2_FILES.md`
- `docs/PHASE2_VALIDATION.md`
- `scripts/Verify-Phase2.ps1`

## Preserved Phase 1 files

The entire frontend, Compose configuration, both Dockerfiles, `.env.example`, the existing settings/URL builder, SQLAlchemy engine and request session dependency, original health route implementation, original connectivity scripts, and existing configuration/health tests remain unchanged. `health.py` response defaults now report phase 2/version 0.2.0 without changing the response structure.

Only bcrypt was added to runtime dependencies; all original locked package versions were retained. No actual `.env`, generated data, test database, virtual environment, dependency directory, or cache is included.

## Where to start

Read `docs/PHASE2.md` for exact PowerShell installation, migration, seed, test, and SQL inspection commands. Read `docs/PHASE2_VALIDATION.md` for executed validation and environment limitations.
