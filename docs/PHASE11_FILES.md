# Phase 11 files

Incremental update: complete contents of each new/modified file. No Phase 1–10 file is deleted.

**12 existing files modified; 74 new files**, including 44 captured screenshots. **248 of the 260 Phase 10 baseline files remain byte-for-byte unchanged.**

## Modified files

- `README.md`
- `backend/app/repositories/dashboard_repository.py`
- `backend/app/schemas/dashboard.py`
- `backend/tests/test_dashboard.py`
- `frontend/package-lock.json`
- `frontend/package.json`
- `frontend/src/App.jsx`
- `frontend/src/components/Layout.jsx`
- `frontend/src/main.jsx`
- `frontend/src/pages/Overview.jsx`
- `frontend/src/pages/Settings.jsx`
- `frontend/src/pages/SystemHealth.jsx`

## New source, tests and documentation

- `docs/PHASE11.md`
- `docs/PHASE11_FILES.md`
- `docs/PHASE11_VALIDATION.md`
- `docs/phase11_results.json`
- `frontend/src/components/common/UI.jsx`
- `frontend/src/components/dashboard/Charts.jsx`
- `frontend/src/components/dashboard/Tables.jsx`
- `frontend/src/context/DashboardContext.jsx`
- `frontend/src/hooks/useDashboardQuery.js`
- `frontend/src/hooks/useLiveEvents.js`
- `frontend/src/pages/AIAnalyst.jsx`
- `frontend/src/pages/Analytics.jsx`
- `frontend/src/pages/DetectionRules.jsx`
- `frontend/src/pages/IncidentSummary.jsx`
- `frontend/src/pages/Incidents.jsx`
- `frontend/src/pages/LiveEvents.jsx`
- `frontend/src/pages/ThreatIntelligence.jsx`
- `frontend/src/services/contracts.js`
- `frontend/src/services/dashboardApi.js`
- `frontend/src/services/incidentsApi.js`
- `frontend/src/services/rulesApi.js`
- `frontend/src/services/threatsApi.js`
- `frontend/src/soc.css`
- `frontend/src/tests/api.test.js`
- `frontend/src/tests/dashboard.test.jsx`
- `frontend/src/tests/fixtures.js`
- `frontend/src/tests/setup.js`
- `frontend/src/utils/format.js`
- `frontend/vitest.config.js`
- `scripts/Verify-Phase11.ps1`

## Captured screenshots

- `docs/screenshots/phase11/admin-1366.png`
- `docs/screenshots/phase11/admin-1440.png`
- `docs/screenshots/phase11/admin-1920.png`
- `docs/screenshots/phase11/admin-390.png`
- `docs/screenshots/phase11/ai-analyst-1366.png`
- `docs/screenshots/phase11/ai-analyst-1440.png`
- `docs/screenshots/phase11/ai-analyst-1920.png`
- `docs/screenshots/phase11/ai-analyst-390.png`
- `docs/screenshots/phase11/analytics-1366.png`
- `docs/screenshots/phase11/analytics-1440.png`
- `docs/screenshots/phase11/analytics-1920.png`
- `docs/screenshots/phase11/analytics-390.png`
- `docs/screenshots/phase11/collapsed.png`
- `docs/screenshots/phase11/events-1366.png`
- `docs/screenshots/phase11/events-1440.png`
- `docs/screenshots/phase11/events-1920.png`
- `docs/screenshots/phase11/events-390.png`
- `docs/screenshots/phase11/health-1366.png`
- `docs/screenshots/phase11/health-1440.png`
- `docs/screenshots/phase11/health-1920.png`
- `docs/screenshots/phase11/health-390.png`
- `docs/screenshots/phase11/health-error.png`
- `docs/screenshots/phase11/incidents-1366.png`
- `docs/screenshots/phase11/incidents-1440.png`
- `docs/screenshots/phase11/incidents-1920.png`
- `docs/screenshots/phase11/incidents-390.png`
- `docs/screenshots/phase11/intelligence-1366.png`
- `docs/screenshots/phase11/intelligence-1440.png`
- `docs/screenshots/phase11/intelligence-1920.png`
- `docs/screenshots/phase11/intelligence-390.png`
- `docs/screenshots/phase11/lookup.png`
- `docs/screenshots/phase11/mobile-drawer.png`
- `docs/screenshots/phase11/overview-1366.png`
- `docs/screenshots/phase11/overview-1440.png`
- `docs/screenshots/phase11/overview-1920.png`
- `docs/screenshots/phase11/overview-390.png`
- `docs/screenshots/phase11/rules-1366.png`
- `docs/screenshots/phase11/rules-1440.png`
- `docs/screenshots/phase11/rules-1920.png`
- `docs/screenshots/phase11/rules-390.png`
- `docs/screenshots/phase11/settings-1366.png`
- `docs/screenshots/phase11/settings-1440.png`
- `docs/screenshots/phase11/settings-1920.png`
- `docs/screenshots/phase11/settings-390.png`

## Compatibility

The auth client/context/guards, environment example, actual environment, both Dockerfiles, Compose file, migration history, event pipeline and existing domain services are unchanged. The API preview adds nullable `destination_ip` from the existing column, with a regression test. No new table, migration or backend dependency is needed. Frontend pages stop at Phase 11; incident investigation, AI and advanced reporting remain deferred.
