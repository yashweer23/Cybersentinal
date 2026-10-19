# Phase 15 — Complete file inventory

This incremental update creates **21 files** and modifies **18 files**. It deletes no files. Paths are relative to your existing `cybersentinel` root. Every listed code file is supplied in full. Preserve `.env`, generated datasets and PostgreSQL volumes.

## Created

- `.gitattributes`
- `backend/app/operations/__init__.py`
- `backend/app/operations/http.py`
- `backend/app/operations/logging.py`
- `backend/app/server.py`
- `backend/scripts/inspect_operations.py`
- `backend/tests/test_operations.py`
- `compose.dev.yml`
- `docs/PHASE15.md`
- `docs/PHASE15_FILES.md`
- `docs/PHASE15_RESULTS.json`
- `docs/PHASE15_VALIDATION.md`
- `frontend/nginx/cybersentinel.conf.template`
- `frontend/nginx/start-frontend.sh`
- `frontend/src/components/ErrorBoundary.jsx`
- `frontend/src/tests/operations.test.jsx`
- `scripts/Backup-Database.ps1`
- `scripts/Compose-Helpers.ps1`
- `scripts/Restore-Database.ps1`
- `scripts/Verify-Phase15.ps1`
- `scripts/database-maintenance.sh`

## Modified

- `.env.example`
- `.gitignore`
- `README.md`
- `backend/.dockerignore`
- `backend/Dockerfile`
- `backend/app/config.py`
- `backend/app/database.py`
- `backend/app/main.py`
- `backend/app/routes/system.py`
- `backend/app/schemas/health.py`
- `docker-compose.yml`
- `frontend/.dockerignore`
- `frontend/Dockerfile`
- `frontend/package-lock.json`
- `frontend/package.json`
- `frontend/src/components/Layout.jsx`
- `frontend/src/main.jsx`
- `frontend/src/styles.css`

## Explicitly unchanged

- All eight Alembic migrations; no new revision and no `create_all()` startup shortcut.
- All 105 protected detection, risk, incident, intelligence, AI, service, model, authorization and migration files, verified against the Phase 14 baseline.
- Existing event/detection/incident API contracts and all role checks.
- `backend/requirements.txt` and `backend/requirements-dev.txt`; frontend dependency versions remain the same.
- Existing source outside this inventory, existing `.env`, usernames/passwords and stored data.

## Applying the update

Merge the archive's `cybersentinel` contents into your existing project root; do not replace the whole project folder. Read `docs/PHASE15.md` before rebuilding. Default containers now use production builds; `compose.dev.yml` restores hot reload explicitly. Keep your existing Compose project name so the existing PostgreSQL volume is selected.

The archive contains source, operational guides and a sanitized validation summary. It does not include secrets, generated databases, database dumps, node_modules, virtual environments or browser screenshots. See `docs/PHASE15_VALIDATION.md` for the pending native Docker/restore checks.
