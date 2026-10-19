# Project file guide

Phase 2 additions and every modified path are listed in [PHASE2.md](PHASE2.md).

All paths below are relative to `cybersentinel/`. All source files are supplied in full.

| File or directory | Responsibility |
| --- | --- |
| `docker-compose.yml` | Local PostgreSQL, API and UI services; health checks; host ports; source mounts |
| `.env.example` | Documented non-secret configuration template |
| `.gitignore` | Excludes secrets, virtual environments, dependencies, caches and build output |
| `scripts/Initialize-Environment.ps1` | Creates a root `.env` and independent random development secrets |
| `scripts/Verify-Phase1.ps1` | Tests direct and proxied health, database query status, frontend HTML and API docs |
| `backend/app/main.py` | FastAPI factory, lifecycle, CORS, root metadata and route registration |
| `backend/app/config.py` | Typed settings, secret validation, safe SQLAlchemy URL construction |
| `backend/app/database.py` | Declarative metadata, engine factory, request-scoped sessions |
| `backend/app/routes/system.py` | `/api/system/live` and real database-backed `/api/system/health` |
| `backend/app/schemas/health.py` | API response models |
| `backend/app/models/` | Nine PostgreSQL ORM models with relationships, native types and constraints |
| `backend/app/security/` | bcrypt seed helper; full identity and permission code remains Phase 3 |
| `backend/app/detection/` | Package reserved for Phase 6 rules |
| `backend/app/services/` | Package reserved for ingestion, risk, intelligence and AI services |
| `backend/alembic.ini`, `backend/alembic/` | Complete model discovery and initial migration `0001_core` |
| `backend/scripts/check_database.py` | Direct PostgreSQL connectivity smoke check |
| `backend/tests/` | Existing foundation tests plus schema validation and isolated PostgreSQL integration tests |
| `backend/requirements*.in` | Human-maintained dependency ranges |
| `backend/requirements*.txt` | Resolved cross-platform dependency locks |
| `backend/pyproject.toml` | Pytest and Ruff configuration |
| `backend/Dockerfile` | Non-root Python development image with reload and test dependencies |
| `frontend/package.json`, `frontend/package-lock.json` | Scripts, frontend dependencies and resolved lock |
| `frontend/vite.config.js` | React / Tailwind plugins, server-side proxy and hot reload configuration |
| `frontend/index.html`, `frontend/public/favicon.svg` | Browser entry document and local vector icon |
| `frontend/src/main.jsx` | React bootstrap and browser router |
| `frontend/src/App.jsx` | Implemented routes and 404 handling |
| `frontend/src/styles.css` | Tailwind import, visual theme, responsive layout and focus states |
| `frontend/src/components/Layout.jsx` | Navigation, header, build status and footer |
| `frontend/src/components/ConnectionCards.jsx` | Actual frontend, API and database states |
| `frontend/src/components/StatusBadge.jsx` | Shared status indicator |
| `frontend/src/services/api.js` | Shared Axios client and typed-by-contract health-response validation |
| `frontend/src/hooks/useHealth.js` | Polling, manual refresh, request cancellation and stale-state clearing |
| `frontend/src/pages/Overview.jsx` | Foundation readiness and planned development milestones |
| `frontend/src/pages/SystemHealth.jsx` | Real health details and raw response inspection |
| `frontend/src/pages/Settings.jsx` | Current environment configuration guidance |
| `frontend/Dockerfile` | Non-root Node development image with locked installation |
| `backend/.dockerignore`, `frontend/.dockerignore` | Excludes local build artifacts and secrets from image context |

`__init__.py` files make Python directories importable. The first complete migration now lives in `alembic/versions`.

No manual file-by-file reconstruction is needed: extract the archive with its directory structure intact.
