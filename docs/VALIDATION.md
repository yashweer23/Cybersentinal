# Phase 1 validation

Validation performed while preparing this source delivery on 23 September 2026.

| Check | Result | Scope |
| --- | --- | --- |
| Python tests | **11 passed** | Readiness success, DB outage, credential redaction, independent liveness, documentation, CORS, configuration validation |
| Ruff | **Passed** | Python import, syntax-style and static checks |
| Python compilation | **Passed** | Application, migration environment and database-check script |
| Frontend production build | **Passed** | Vite built the React application with all current imports and styles |
| Frontend HTML over HTTP | **Passed** | Vite served the application entry document |
| Direct live API | **Passed** | `/api/system/live`, `/docs`, `/openapi.json` returned HTTP 200 |
| Vite-to-backend proxy | **Passed** | The same API / documentation routes worked through port 5173 |
| Real unavailable-DB behavior | **Passed** | Direct and proxied `/api/system/health` returned 503 and `database: disconnected` without leaking the configured test password |
| Compose YAML and source mounts | **Passed, static check only** | YAML parsed; service names, mount paths and loopback port bindings checked |
| Real PostgreSQL success path | **Not executed here** | A PostgreSQL server / Docker daemon was unavailable; successful health unit tests use a controlled engine substitute |
| Docker image builds / Compose boot | **Not executed here** | Docker is not installed in the build workspace |
| Windows PowerShell scripts | **Not executed here** | PowerShell / Windows runtime unavailable |
| Browser visual verification | **Not executed here** | Browser binary unavailable and its download failed; frontend compilation is not visual QA |

The test run reported one non-failing upstream Starlette warning about its transitional `httpx` TestClient support. This affects the current test client dependency path, not the production application routes. Dependency versions are recorded in the lock files.

## Required local acceptance check

Follow the Docker instructions in the root README, then run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Verify-Phase1.ps1
docker compose exec backend python -m scripts.check_database
```

Open `http://localhost:5173` to confirm the React page renders correctly. Verify the frontend says **Running**, API says **Connected**, and PostgreSQL says **Connected**. Also open `http://localhost:8000/docs`.

The intended acceptance condition is a **real** PostgreSQL-backed health response with `status: healthy`. This document does not claim that a Docker / PostgreSQL integration run succeeded in the delivery workspace.
