# Setup and configuration

[Quick start](../README.md#quick-start) · [Demo](DEMO.md) · [Testing](TESTING.md)

## Windows / Docker

Use Docker Desktop with Linux containers and Compose v2. From VS Code's PowerShell, open your existing `cybersentinel` directory (the previous local path was `C:\Users\saiya\OneDrive\Documents\Projects\cybersentinel`). Paths below are relative to that project root. No Git remote or clone URL is assumed.

Run the [README quick start](../README.md#quick-start). The initializer preserves `.env` if it already exists; otherwise it copies `.env.example` and generates random database/JWT secrets locally. It does not create users or reset the database. Do not overwrite an existing `.env` with example placeholders.

Production build here means optimized build targets, not a claim that this local HTTP setup is a completed production deployment. Keep `APP_ENV=development` for the local HTTP demo; `APP_ENV=production` requires HTTPS for secure refresh cookies. Do not disable cookie protections to make a remote HTTP deployment work.

| Address | Purpose |
| --- | --- |
| `http://localhost:5173` | React via Nginx; `/api` and `/docs` proxied to FastAPI |
| `http://localhost:8000` | Direct backend, including `/docs` and `/openapi.json` |
| `db:5432` | PostgreSQL from containers only |
| `127.0.0.1:15432` | PostgreSQL on the host only when `compose.dev.yml` is enabled |

The application derives its SQLAlchemy URL from `POSTGRES_*`; it does not require a new `DATABASE_URL` variable. Compose overrides host/port to `db:5432`. A changed host port must never become the backend's internal database port.

## Configuration groups

The full supported example is [`.env.example`](../.env.example); validation/defaults live in [`config.py`](../backend/app/config.py). Values prefixed `VITE_` are public browser configuration; never put provider credentials there.

| Variables | Purpose / default |
| --- | --- |
| `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | Local database connection; preserve existing role/database/volume |
| `JWT_SECRET_KEY`, `JWT_ACCESS_TOKEN_EXPIRE_MINUTES`, `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | Generated signing secret; access 30 minutes and refresh 7 days |
| `FRONTEND_PORT`, `BACKEND_PORT` | Loopback published ports, 5173 / 8000 |
| `CORS_ORIGINS`, `AUTH_TRUSTED_ORIGINS`, `ALLOWED_HOSTS` | Explicit origin/host allowlists; update if using different ports/hosts |
| `APP_ENV`, `API_DOCS_ENABLED`, `LOG_LEVEL` | Local environment, Swagger availability and logging |
| `SERVER_WORKERS` | Must remain 1 with the current process-local limiter |
| `DETECTION_BATCH_SIZE`, `RISK_BATCH_SIZE`, `INCIDENT_BATCH_SIZE` | Bounded processing, defaults 500 / 250 / 100 |
| `THREAT_INTELLIGENCE_MOCK_MODE` | Keep `true` for a safe repeatable demo |
| `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY` | Optional server-side provider secrets; leave empty for demo |
| `AI_PROVIDER`, `AI_API_KEY`, `AI_MODEL` | Use `fallback` with no key for demo; optional `openai` requires key/model |

Changing environment settings requires recreating the affected container; restarting alone does not reload Compose's environment. Changing `POSTGRES_PASSWORD` after a volume has initialized does not change the database role password. Resolve a mismatch using the correct existing credential/role administration rather than deleting the volume.

## Development with Docker

```powershell
docker compose -f docker-compose.yml -f compose.dev.yml up --build -d --wait --wait-timeout 180
if ($LASTEXITCODE -ne 0) { throw 'Development startup failed.' }
docker compose -f docker-compose.yml -f compose.dev.yml exec backend alembic upgrade head
docker compose -f docker-compose.yml -f compose.dev.yml exec backend python -m scripts.seed_detection_rules
```

This enables source mounts, dev dependencies and Vite, and publishes PostgreSQL on the configured host port. It preserves the named database volume. Return to normal builds with `docker compose up --build -d --wait --wait-timeout 180`. Production backend images intentionally exclude pytest and development tooling.

## Host Python and React development

Prerequisites: Python 3.12+ and Node 22.12+ with npm. Keep `.env` host/port at `127.0.0.1` / your published port (normally 15432). Stop container frontend/backend first if they occupy the same ports; keep the database.

Terminal 1, project root:

```powershell
docker compose stop frontend backend
docker compose -f docker-compose.yml -f compose.dev.yml up -d --wait db
py -3.12 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r .\backend\requirements-dev.txt
if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed.' }
Set-Location .\backend
& ..\.venv\Scripts\alembic.exe upgrade head
& ..\.venv\Scripts\python.exe -m scripts.seed_detection_rules
& ..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Terminal 2, project root:

```powershell
Set-Location .\frontend
npm ci --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
npm run dev
```

Vite loads only the server port configuration and proxies `/api`, `/docs`, `/openapi.json` and `/redoc`. Avoid loading private backend environment variables into the client. Use the equivalent `python -m scripts...` commands from `backend` for host CLI workflows.

## Troubleshooting without resetting data

| Symptom | Check / correction |
| --- | --- |
| Port 5432 cannot bind on Windows | Default stack does not publish PostgreSQL. For development use host 15432 or another unused allowed port; leave container 5432 unchanged. |
| `npm ci` fails | Read the first npm error, preserve the lockfile and rebuild the frontend. A later `Built` line is not the original npm failure. |
| PowerShell shows `NativeCommandError` for build progress | Some native stderr progress is colored as an error by older PowerShell. Check `$LASTEXITCODE` immediately; preserve actual error output. |
| Healthy container but readiness 503 | Apply `alembic upgrade head`; inspect backend/database logs and existing credentials. Liveness does not mean schema readiness. |
| Login fails | Use the username you created. Registration defaults to VIEWER. There is no universal admin password. |
| Refresh fails after switching to production | Use HTTPS and a matching trusted origin; production cookies are Secure. |
| Empty charts | Generate/ingest/process data, select the correct UTC/date range, and inspect unprocessed counts. |
| Live events stop increasing | Polling is working only if new events are being ingested. It does not run the generator. |

```powershell
docker compose ps
docker compose logs --tail=80 backend db frontend
Invoke-RestMethod http://localhost:8000/api/system/health
Invoke-RestMethod http://localhost:5173/api/system/ready
```

Back up before operational changes. `docker compose down -v` deletes named volumes and is not a troubleshooting step. See [Testing](TESTING.md#native-restart-and-restore-gates) for verification against a separate restore database.
