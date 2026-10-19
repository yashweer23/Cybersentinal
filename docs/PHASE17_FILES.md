# Phase 17 file manifest and installation

This is an incremental update for the existing project through Phase 16. The archive supplies **complete files**, not fragments. Merge its `cybersentinel/` contents into your existing project. Keep your `.env`, database volumes and local datasets. Do not recreate the project or use `docker compose down -v`.

Only the files listed below are included. No migration, package requirement, lockfile, authentication/detection/risk/incident/provider behavior or Compose configuration is changed. `Layout.jsx` replaces a stale footer phase label; the other edits are documentation. Application version remains 0.15.0 and Alembic head remains `0008_ai_analyses`.

## Created

- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `docs/API.md`
- `docs/ARCHITECTURE.md`
- `docs/DATABASE.md`
- `docs/DEMO.md`
- `docs/INTERVIEW.md`
- `docs/PERFORMANCE.md`
- `docs/PHASE17_FILES.md`
- `docs/PHASE17_VALIDATION.md`
- `docs/README.md`
- `docs/SCREENSHOTS.md`
- `docs/SECURITY.md`
- `docs/SETUP.md`
- `docs/phase17_results.json`
- `docs/screenshots/phase17-ai.png`
- `docs/screenshots/phase17-analytics.png`
- `docs/screenshots/phase17-events.png`
- `docs/screenshots/phase17-health.png`
- `docs/screenshots/phase17-incidents.png`
- `docs/screenshots/phase17-intelligence.png`
- `docs/screenshots/phase17-investigation.png`
- `docs/screenshots/phase17-login.png`
- `docs/screenshots/phase17-overview.png`
- `docs/screenshots/phase17-reports.png`
- `docs/screenshots/phase17-risk.png`
- `docs/screenshots/phase17-rules.png`
- `docs/screenshots/phase17-timeline.png`

## Modified

- `README.md`
- `docs/TESTING.md`
- `frontend/src/components/Layout.jsx`

## Apply and review

Extract the archive outside the existing project, then copy the nested `cybersentinel` contents into the project root, allowing replacement of only the listed modified files. No new environment variables, credentials or seed run are required for this update.

From your existing project root, rebuild the frontend to show the footer polish:

```powershell
docker compose up --build -d --wait --wait-timeout 180 frontend
if ($LASTEXITCODE -ne 0) { throw 'Frontend update failed.' }
Invoke-RestMethod http://localhost:5173/api/system/ready
Start-Process http://localhost:5173
```

For a fresh installation use the [README quick start](../README.md#quick-start). For a populated synthetic demonstration use [DEMO.md](DEMO.md). For native acceptance use [TESTING.md](TESTING.md). No deployment, Git commit/push or license assignment is performed by this update.
