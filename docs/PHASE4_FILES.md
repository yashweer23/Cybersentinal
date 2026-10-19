# Phase 4 file guide

The update contains 17 new files and 3 modified files, each with complete contents. Extract into the existing project root and merge folders. No existing file is deleted.

## Files created

- `backend/app/simulation/__init__.py`
- `backend/app/simulation/config.py`
- `backend/app/simulation/constants.py`
- `backend/app/simulation/exporter.py`
- `backend/app/simulation/factory.py`
- `backend/app/simulation/generator.py`
- `backend/app/simulation/identities.py`
- `backend/app/simulation/normal_activity.py`
- `backend/app/simulation/scenarios.py`
- `backend/data/.gitkeep`
- `backend/scripts/generate_demo_data.py`
- `backend/tests/test_simulation.py`
- `backend/tests/test_simulation_export.py`
- `docs/PHASE4.md`
- `docs/PHASE4_EXAMPLES.md`
- `docs/PHASE4_FILES.md`
- `docs/PHASE4_VALIDATION.md`

## Files modified

- `README.md` — delivery status, generator commands, data contract, scenario coverage and documentation links.
- `.gitignore` — generated JSON/JSONL/CSV datasets and temporary export files.
- `backend/.dockerignore` — exclude generated datasets from image layers while retaining `data/.gitkeep`.

## Preserved existing files

All frontend files, FastAPI routes, authentication/RBAC, models, request/response schemas, core enums, database connections, Alembic revisions, dependencies/lockfiles, `.env.example`, Dockerfiles, Docker Compose, existing scripts and tests are unchanged. No new environment variables, database migration or dependency install is required when using the existing Docker image. Your actual `.env` is not part of the update.

## Files deliberately excluded

Generated data, virtual environments, caches, `node_modules`, build outputs, actual environment secrets, and local validation tooling are not in this update. Commands and five complete generated examples are in the included guides. The ZIP is an additive Phase 3 update, not a replacement standalone project.
