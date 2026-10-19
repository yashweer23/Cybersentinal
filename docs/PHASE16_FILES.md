# Phase 16 — Files in this update

Merge these complete files into the existing Phase 15 project. Preserve `.env`, data and volumes. Nothing is deleted. No new migration, production Python dependency, model or API contract is introduced.

## Created

| Path | Purpose |
| --- | --- |
| `backend/scripts/validate_system.py` | Disposable schema, full pipeline/replay, integrity/migration/API checks and optional JMeter orchestration. |
| `backend/tests/test_detection_boundaries.py` | Thirty threshold/timezone checks supplement existing tests for every rule. |
| `backend/tests/test_query_bounds.py` | Cold-ORM investigation query-count and response-bound regression. |
| `backend/tests/test_security_matrix.py` | Thirty-one cross-module authorization and literal-filter cases. |
| `docs/PHASE16_FILES.md` | This complete incremental file inventory. |
| `docs/PHASE16_VALIDATION.md` | Executed evidence, timings, security fixes, limitations and native completion gates. |
| `docs/TESTING.md` | Test matrix, isolation/measurement definitions, exact Windows/Docker commands and pending gates. |
| `docs/performance/phase16-load10.csv` | Actual 10-user JMeter timing/status samples without auth headers or bodies. |
| `docs/performance/phase16-load25.csv` | Actual 25-user JMeter timing/status samples without auth headers or bodies. |
| `docs/phase16_results.json` | Sanitized machine-readable test, pipeline, scan, browser and performance results. |
| `frontend/src/tests/route-security.test.jsx` | Six role-route/loading/error/escaped-text checks. |
| `scripts/Verify-Phase16.ps1` | Checked native Docker development verification and report collection. |
| `scripts/verify-browser.mjs` | Three-role Chromium acceptance with SPA and deep-link navigation. |
| `tests/performance/read_only.jmx` | Nine authenticated read samplers with HTTP assertions and bounded load duration. |

## Modified

| Path | Purpose |
| --- | --- |
| `.gitignore` | Ignore optional tool installs and local browser/JMeter outputs. |
| `README.md` | Phase 16 entry point and test-guide links; prior guides retained. |
| `backend/tests/database_fixtures.py` | Optional engine pool arguments while retaining random-schema isolation. |
| `backend/tests/test_advanced_analytics.py` | Expand multi-join fixture with four comments per case. |
| `backend/tests/test_database_api.py` | Use an allowed localhost origin in production-route test. |
| `backend/tests/test_incident_engine.py` | Add promotion category boundary at score 75. |
| `frontend/package-lock.json` | Patch only source-map-js 1.2.1 to 1.2.2. |
| `frontend/src/tests/api.test.js` | Additional HTTP/network failure contracts. |

## Verification entry points

- Windows/native Docker: `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Verify-Phase16.ps1`
- Optional host pipeline/load: `python -m scripts.validate_system --help` from `backend/` with development requirements installed.
- Browser acceptance: `node scripts/verify-browser.mjs` with three role credentials in environment variables.
- Full instructions and expected results: [TESTING.md](TESTING.md).
- Measured results and outstanding checks: [PHASE16_VALIDATION.md](PHASE16_VALIDATION.md).

The ZIP is an incremental update, not a replacement project. There is no `.env`, real credential, database archive, generated event dataset, browser runtime or `node_modules` directory in it.
