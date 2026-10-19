# Phase 12 — Complete file manifest

This incremental delivery contains **31 new files** and **13 modified files**. Every included source file has complete updated contents. No existing project file was deleted. Merge the archive's `cybersentinel/` directory into the existing Phase 11 project, then rebuild both app containers.

## Files created

| File | Category |
| --- | --- |
| `backend/tests/test_investigation_api.py` | Regression test coverage |
| `docs/PHASE12.md` | Guide, measured results or complete file manifest |
| `docs/PHASE12_FILES.md` | Guide, measured results or complete file manifest |
| `docs/PHASE12_VALIDATION.md` | Guide, measured results or complete file manifest |
| `docs/phase12_results.json` | Guide, measured results or complete file manifest |
| `docs/screenshots/phase12/analyst-activity.png` | Actual browser screenshot with synthetic evidence |
| `docs/screenshots/phase12/event-drawer.png` | Actual browser screenshot with synthetic evidence |
| `docs/screenshots/phase12/finding-expanded.png` | Actual browser screenshot with synthetic evidence |
| `docs/screenshots/phase12/intelligence-providers.png` | Actual browser screenshot with synthetic evidence |
| `docs/screenshots/phase12/overview-1440.png` | Actual browser screenshot with synthetic evidence |
| `docs/screenshots/phase12/overview-390.png` | Actual browser screenshot with synthetic evidence |
| `docs/screenshots/phase12/resolution-dialog.png` | Actual browser screenshot with synthetic evidence |
| `frontend/src/components/incidents/AssignmentControl.jsx` | Investigation UI component |
| `frontend/src/components/incidents/Dialog.jsx` | Investigation UI component |
| `frontend/src/components/incidents/EventDetailDrawer.jsx` | Investigation UI component |
| `frontend/src/components/incidents/EvidenceFields.jsx` | Investigation UI component |
| `frontend/src/components/incidents/FindingsPanel.jsx` | Investigation UI component |
| `frontend/src/components/incidents/IncidentComments.jsx` | Investigation UI component |
| `frontend/src/components/incidents/IncidentEvents.jsx` | Investigation UI component |
| `frontend/src/components/incidents/IncidentHeader.jsx` | Investigation UI component |
| `frontend/src/components/incidents/IncidentOverview.jsx` | Investigation UI component |
| `frontend/src/components/incidents/IncidentTimeline.jsx` | Investigation UI component |
| `frontend/src/components/incidents/RiskBreakdown.jsx` | Investigation UI component |
| `frontend/src/components/incidents/StatusControl.jsx` | Investigation UI component |
| `frontend/src/components/incidents/ThreatIntelligencePanel.jsx` | Investigation UI component |
| `frontend/src/components/threats/IntelligenceResult.jsx` | Shared existing intelligence rendering |
| `frontend/src/hooks/useIncident.js` | Query, polling and mutation lifecycle |
| `frontend/src/investigation.css` | Responsive investigation styles |
| `frontend/src/pages/IncidentInvestigation.jsx` | Investigation route orchestration |
| `frontend/src/tests/investigation.test.jsx` | Regression test coverage |
| `scripts/Verify-Phase12.ps1` | Read-only PowerShell verification |

## Files modified

| File | Change |
| --- | --- |
| `README.md` | Current phase, investigation workflows, upgrade links and screenshots. |
| `backend/app/repositories/incident_repository.py` | Bounded eligible-analyst search, stored risk selection, event filters and ordered timeline context. |
| `backend/app/routes/incidents.py` | Directory route and compatible response projections; existing mutations reused. |
| `backend/app/schemas/incident.py` | Directory/filter schemas, timeline context, event ports and stored assessment/transitions. |
| `frontend/package-lock.json` | Matching root version; dependency graph unchanged. |
| `frontend/package.json` | Version 0.12.0; dependency versions unchanged. |
| `frontend/src/App.jsx` | Lazy investigation route at the existing incident URL. |
| `frontend/src/components/Layout.jsx` | Investigation title and Phase 12 label. |
| `frontend/src/components/dashboard/Tables.jsx` | Optional queue return URL in incident links. |
| `frontend/src/pages/IncidentSummary.jsx` | Compatibility export of the new workspace. |
| `frontend/src/pages/Incidents.jsx` | URL-backed filters/pagination retained on return. |
| `frontend/src/pages/ThreatIntelligence.jsx` | Reuse extracted existing intelligence rendering. |
| `frontend/src/services/incidentsApi.js` | Response validation and existing read/write operations through authenticated Axios. |

## Compatibility boundary

No migration was added. Existing migration head remains `0007_dashboard_polling`. Both Dockerfiles, Compose, `.env.example`, requirements, configuration, database/session setup, authentication/RBAC, model files, detection/risk/correlation/enrichment services and all prior tests are unchanged. The new frontend uses the existing dependency versions. No `.env`, credentials, generated event dataset, database file, node_modules, build output or scratch validation dependency is included.

See `PHASE12.md` for exact commands and architecture, and `PHASE12_VALIDATION.md` for actual results and environment limits. The root `PHASE12-START-HERE.txt` explains how to merge the archive.
