# Changelog

## GitHub repository preparation — 2026-10-19

- Set GitHub source publication and local Docker execution as the current delivery path.
- Added Windows PowerShell instructions for first publication and existing repositories.
- Expanded exclusions for runtime data, backups, private keys and generated test artifacts.
- Preserved optional cloud utilities and dated test results without requiring Render or claiming a live deployment.
- Removed trailing blank lines/whitespace reported by the initial Git import check.
- No application behavior, dependencies, database migration logic or version numbers changed.

## Phase 17 documentation update — 2026-10-17

- Replaced the accumulated phase-by-phase README with a current project overview and quick start.
- Added architecture, database, API, threat-model, setup, demo and interview guides, with actual configuration and API roles.
- Added real synthetic-data application screenshots and a documentation verification report.
- Replaced the stale “Phase 15” footer badge with “SOC workspace.”
- Preserved Phase 16 measured results and outstanding native Docker/recovery gates.
- No application version bump, schema migration, cloud deployment or new product feature. Application version remains 0.15.0.

## Implemented baseline through Phase 16

FastAPI/PostgreSQL/React foundation; authentication/RBAC; deterministic synthetic generation and ingestion; ten behavioral rules; explainable risk; incident correlation and workflow; optional intelligence adapters and mock cache; dashboard/investigation UI; constrained AI assistance/fallback; analytics/reports; hardened Docker build targets; isolated correctness, security and performance verification.

Earlier phase guides retain their detailed change and validation history. This changelog does not invent release tags or publication dates for those phases.
