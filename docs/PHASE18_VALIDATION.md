# Phase 18 deployment-preparation verification

> **Scope update — 2026-10-19:** GitHub repository publication has replaced the cloud-hosting goal. The results below remain the dated record of preparation; outstanding Render checks are not requirements for using the repository locally. See [GITHUB.md](GITHUB.md).

Date: **2026-10-18**. This is a local verification record. **Phase 18 is not complete: no cloud deployment has been created or verified.**

## What changed

The existing Phase 1–17 models, migrations, domain engines, API contracts, frontend features and Compose port configuration are preserved. The update adds:

- A proposed Render Blueprint for the existing Nginx/React container, private FastAPI container and managed PostgreSQL 17.
- Provider `DATABASE_URL` normalization, explicit TLS configuration and cloud-port support while keeping local `POSTGRES_*` settings.
- Exact `PUBLIC_ORIGIN` configuration, canonical HTTPS for the private API, and database-URL log redaction.
- Portable Nginx listener/private upstream/DNS settings.
- A guarded, transactional Alembic release command, a bounded HTTPS smoke runner, and an explicit synthetic-data initializer using existing authenticated APIs.
- Deployment, recovery and validation documentation, with no live URL or cloud-success claims.

No new database revision, provider integration, detection feature, AI feature or runtime dependency was introduced. New application code is listed in [PHASE18_FILES.md](PHASE18_FILES.md).

## Executed checks

| Check | Actual result | Boundary |
| --- | --- | --- |
| Full backend pytest | 837 passed, 1 skipped; 62.34 seconds | Isolated migrated schemas in embedded PostgreSQL 18.6 / PGlite 0.5.10 |
| Cloud-specific tests | URL parsing/TLS/secrets, origin/Host/forwarding, migrations/schema checks, all three roles, synthetic initialization/replay/guards pass | Real application/ORM APIs through TestClient; no remote network |
| Frontend unit tests | 86 passed in 7 files, 4.04 seconds | Vitest, unchanged application UI |
| Frontend production build | Passed, 363 ms | Installed Node 24.19 toolchain; production assets generated |
| Backend Ruff lint | Passed | Entire backend |
| Changed Python formatting | All 8 changed/new Python files pass | Four pre-existing unrelated files do not satisfy a whole-tree format check and were preserved |
| Native Nginx | Passed | Nginx 1.30.0; actual built SPA/template and entrypoint, local paths/test user |
| Render Blueprint | Official public JSON Schema passed | Account-side preview/CLI/API acceptance not yet performed |
| Existing 10,000-event validation | Passed | Seed 42, mixed scenarios, start 2026-10-11, mock TI, AI fallback |
| New cloud population utility | 1,000 events inserted and processed through authenticated APIs; explicit replay inserted zero, reported 1,000 duplicates and no new findings | Local production-mode TestClient, not a cloud seed |

The single skipped backend case requires native independent-connection concurrency. The embedded database/socket adapter has one PostgreSQL backend and cannot prove those semantics. The environment also emits an existing Starlette warning about future TestClient HTTP-client compatibility; dependencies were not upgraded as part of deployment preparation.

Docker, native PostgreSQL 17, PowerShell, Render CLI and real public TLS were unavailable for execution here. Native local Nginx testing uses test-only filesystem paths and a single root worker because of this environment; the production Dockerfile still runs its existing non-root image. Its checks cover six SPA deep paths, API/missing-asset 404 behavior, request forwarding and five rejected invalid runtime configurations. They do not verify Render's ingress or private DNS.

The official Blueprint schema accepted one project/environment, two services and one database. That validates structure, not billing availability, permissions, image builds, connectivity or operational health in the user's account.

## Measured local pipeline

[phase18_local_results.json](phase18_local_results.json) stores the compact machine-readable results. The original `validate_system` service/API workflow was rerun once on the deployment-compatible application; it was not run against Render.

| Stage | Wall time | Result |
| --- | ---: | --- |
| Generate | 1,244.589 ms | 10,000 synthetic events |
| Ingest | 5,594.478 ms | 10,000 inserted; zero invalid/failed; 1,787.48 events/sec |
| Detect | 11,384.684 ms | 10,000 processed; 36 findings; all ten enabled rules executed; 878.37 events/sec |
| Risk | 74.470 ms | 36 assessments |
| Incident processing | 417.829 ms | 29 incidents, 29 linked findings, 160 evidence records |
| Re-ingest | 4,970.852 ms | Zero inserted; 10,000 duplicates |
| Detection replay | 7,127.725 ms | Zero created; 36 duplicate findings recognized |
| Mock enrichment | 260.478 ms | 29 cases evaluated, 19 enriched; zero external requests |
| Deterministic analysis | 113.534 ms | FALLBACK result using stored case context |

All processed flags were updated, raw-event hashes stayed unchanged, and integrity queries found zero invalid references, duplicate fingerprints, duplicate incident links or out-of-range scores. Clean and populated Alembic checks passed. The HTTP validation inspected 88 OpenAPI operations, denied anonymous protected access and exercised dashboard, analytics, case details and report APIs.

These are serial local measurements, with a one-connection test pool and embedded PostgreSQL. They are not throughput guarantees for a 512 MB Render instance or evidence of production concurrency. No JMeter or public load test ran during this update. Phase 16 contains earlier measurements for comparison.

| Rule | Findings |
| --- | ---: |
| CS-001 | 5 |
| CS-002 | 2 |
| CS-003 | 4 |
| CS-004 | 3 |
| CS-005 | 3 |
| CS-006 | 3 |
| CS-007 | 7 |
| CS-008 | 5 |
| CS-009 | 4 |
| CS-010 | 0 |

Synthetic evaluation covered 36 of 37 expected scenario units (97.30% scenario recall), with one missed unit and zero unexpected findings. CS-010 executed but did not match this mixed dataset's generated API volume. Its positive/negative rule tests pass. This is a dataset-specific diagnostic, not real-world accuracy or statistical precision; the evaluator explicitly leaves precision unset.

## Issues found and resolved

1. **Provider URL compatibility:** the previous configuration required separate local PostgreSQL fields. It now accepts a secret provider URL, normalizes the driver, preserves encoded credentials and stronger TLS options, and retains production password-length checks.
2. **Cloud proxy portability:** the previous frontend listener/DNS assumptions were Docker-specific. Runtime port, upstream and resolver validation now support the proposed platform without changing local Compose ports.
3. **HTTPS recognition:** the private API now supports a configured canonical HTTPS origin without trusting spoofed forwarding headers. Host validation and exact-origin auth remain active. End-user IP attribution remains deliberately unverified; login budgets may be shared through the gateway.
4. **New verification code:** tests caught an incorrect dashboard route assumption; the runner now uses the existing `/api/dashboard/overview`. The population runner uses the existing generator's `iter_events()` API.
5. **Local validation transport:** the embedded PostgreSQL adapter initially failed on prepared/pipelined queries, simultaneous socket allocation and a timezone setting leaking between sessions. Test-harness-only changes disabled unsupported protocol features, allowed sufficient socket clients and reset UTC on new connections. These are not application patches and are not shipped. A native PostgreSQL rerun remains required.
6. **Style checks:** lint passes; whole-tree formatting reports four existing files outside the update. They were not rewritten just for this phase. All eight Python files in this update pass formatting.

## Remaining deployment gates

| Gate | Status |
| --- | --- |
| Render connection | Connected; workspace list visible |
| Workspace selection | Waiting for explicit user confirmation required by Render's tool |
| Repository | No Git remote is available in this restored workspace; repository URL/source publication required |
| Paid resource approval | Proposed base compute about US$20/month; no resources purchased |
| Render builds/migrations/secrets/admin | Pending actual deployment |
| 10,000 cloud events | Pending; local result is not a remote seed |
| Live HTTPS/CORS/auth/RBAC/API checks | Pending |
| Cloud Chromium/deep links/mobile/exports | Pending |
| Managed backup and separate restore | Pending |
| Cloud CPU/memory/latency/log retention | Pending |
| Live screenshots/demo URL/resume deployment claim | Pending verified success |

Use [DEPLOYMENT.md](DEPLOYMENT.md) for the concrete launch and acceptance steps. The Render deployment workflow explicitly requires confirmed workspace selection and a provider-accessible Git repository. Installing the Render connection does not resolve those requirements or approve recurring costs.
