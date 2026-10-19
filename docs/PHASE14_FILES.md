# Phase 14 file manifest

This update contains **22 new files and 11 modified files**, all with complete contents. It is based on the 394-file Phase 13 source snapshot and requires the existing application. No files are deleted.

## Created

- `backend/app/repositories/analytics_entities.py`
- `backend/app/repositories/analytics_repository.py`
- `backend/app/repositories/synthetic_analytics.py`
- `backend/app/routes/analytics.py`
- `backend/app/routes/reports.py`
- `backend/app/schemas/analytics.py`
- `backend/app/schemas/reports.py`
- `backend/app/services/reporting_service.py`
- `backend/app/services/security_analytics.py`
- `backend/tests/test_advanced_analytics.py`
- `docs/PHASE14.md`
- `docs/PHASE14_FILES.md`
- `docs/PHASE14_VALIDATION.md`
- `docs/phase14_results.json`
- `frontend/src/analytics.css`
- `frontend/src/components/analytics/AnalyticsCharts.jsx`
- `frontend/src/components/analytics/AnalyticsSections.jsx`
- `frontend/src/components/analytics/ReportPanel.jsx`
- `frontend/src/hooks/useAnalytics.js`
- `frontend/src/services/analyticsApi.js`
- `frontend/src/tests/analytics.test.jsx`
- `scripts/Verify-Phase 14.ps1`

## Modified

- `README.md`
- `backend/app/main.py`
- `backend/app/schemas/dashboard.py`
- `backend/app/schemas/health.py`
- `backend/app/services/analytics_service.py`
- `frontend/package-lock.json`
- `frontend/package.json`
- `frontend/src/components/Layout.jsx`
- `frontend/src/context/DashboardContext.jsx`
- `frontend/src/pages/Analytics.jsx`
- `frontend/src/tests/dashboard.test.jsx`

## Compatibility

- Existing Docker Compose/Dockerfiles, `.env.example`, Python dependencies and migrations are byte-identical to the Phase 13 baseline. The actual `.env` is excluded.
- Frontend package and lock metadata change to 0.14.0; dependency entries are unchanged.
- Existing authentication/RBAC, database sessions, Phase 10 dashboard contracts and Phase 13 AI flows are reused. Dashboard presets additionally accept 90d.
- `main.py` registers the analytics/report routers, applies no-store to those routes and reports the new application version. Health metadata and the workspace footer reflect Phase 14.
- `Analytics.jsx` replaces the earlier basic page. The old navigation test now checks the dedicated heading and inherited 7D period.
- No schema/index migration was added. `alembic upgrade head` remains the command for ensuring all earlier migrations are applied.
- All changed source files are supplied in full. The ZIP includes a root upgrade note and SHA-256 checksums. No generated datasets, dependency folders, secrets or browser screenshots are included.
