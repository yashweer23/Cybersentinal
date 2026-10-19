# Phase 3 file guide

**30 files created; 25 files modified.** No source files were deleted.

Paths below are relative to your existing `cybersentinel` project root. The update ZIP contains complete versions of these files only, with no extra wrapper directory. Expand it into the existing project; it is not a standalone replacement for Phase 1/2.

## Files created

| Path | Purpose |
| --- | --- |
| `backend/alembic/versions/0002_auth_sessions.py` | Add and remove only the revocable-session table. |
| `backend/app/core/errors.py` | Safe service errors shared by route handlers. |
| `backend/app/models/auth_session.py` | Persist refresh digests and session expiry/revocation. |
| `backend/app/routes/access_checks.py` | Development-only authenticated/analyst/admin checks. |
| `backend/app/routes/auth.py` | Register, login, profile, refresh and logout HTTP contracts. |
| `backend/app/routes/users.py` | ADMIN-only listing and role/status changes. |
| `backend/app/schemas/auth.py` | Typed registration/login/token/admin payloads; no hash output. |
| `backend/app/security/dependencies.py` | Bearer identity, DB-authoritative permissions and browser guard. |
| `backend/app/security/jwt.py` | Strict signed access/refresh token creation and validation. |
| `backend/app/security/rate_limit.py` | Bounded process-local authentication rate limiter. |
| `backend/app/services/audit_service.py` | Explicit audit snapshots and recoverable auth-audit savepoints. |
| `backend/app/services/auth_service.py` | Account registration, bcrypt login, rotation and revocation. |
| `backend/app/services/user_service.py` | Audited role/status updates and last-admin protection. |
| `backend/scripts/create_admin.py` | Interactive operator bootstrap without public role selection. |
| `backend/tests/test_auth_api.py` | Database-backed auth, roles, sessions, admin and audit tests. |
| `backend/tests/test_auth_migration.py` | Preserve Phase 2 users through upgrade/downgrade. |
| `backend/tests/test_auth_security.py` | JWT claims, signature/type checks, passwords and limiter tests. |
| `docs/PHASE3.md` | Windows installation, API/Swagger use, design and troubleshooting. |
| `docs/PHASE3_FILES.md` | This exact list of new and modified paths. |
| `docs/PHASE3_VALIDATION.md` | Recorded tests, browser checks, screenshots and limitations. |
| `docs/screenshots/phase3-admin-desktop.png` | Verified screenshot using disposable test accounts. |
| `docs/screenshots/phase3-login-desktop.png` | Verified screenshot using disposable test accounts. |
| `docs/screenshots/phase3-login-mobile.png` | Verified screenshot using disposable test accounts. |
| `frontend/src/auth.css` | Responsive login, role-denied and admin-access styles. |
| `frontend/src/components/ProtectedRoute.jsx` | Authentication/loading/error states and role guard. |
| `frontend/src/context/AuthContext.jsx` | React auth provider and current-user checks. |
| `frontend/src/pages/Admin.jsx` | Real user list with audited role/status operations. |
| `frontend/src/pages/Login.jsx` | Login and default-VIEWER registration screens. |
| `frontend/src/services/auth.js` | Memory-only access tokens, cookie refresh and tab synchronization. |
| `scripts/Verify-Phase3.ps1` | Masked-password login, role, refresh and logout HTTP checks. |

## Files modified

| Path | Purpose |
| --- | --- |
| `.env.example` | Reference auth defaults; existing actual .env is excluded. |
| `README.md` | Current Phase 3 capabilities and links to detailed guides. |
| `backend/alembic/env.py` | Correct the model-registration comment; migration logic retained. |
| `backend/app/config.py` | Validate JWT settings and explicit browser origins. |
| `backend/app/main.py` | Register auth/admin routers, error redaction, CORS and no-store headers. |
| `backend/app/models/__init__.py` | Register/export AuthSession for SQLAlchemy and Alembic. |
| `backend/app/models/user.py` | Add the relationship to sessions, retaining existing user fields. |
| `backend/app/routes/database.py` | Require authentication on the existing rule listing. |
| `backend/app/routes/system.py` | Remove authentication from the future-module list. |
| `backend/app/schemas/health.py` | Report the current phase/version. |
| `backend/app/security/passwords.py` | Retain bcrypt hashing; add safe verification and dummy-account hash. |
| `backend/requirements-dev.txt` | Pin PyJWT 2.15.0; retain existing resolved dependencies. |
| `backend/requirements.in` | Add PyJWT to direct runtime dependencies. |
| `backend/requirements.txt` | Pin PyJWT 2.15.0; retain existing resolved dependencies. |
| `backend/scripts/seed_demo_users.py` | Update the completion message now that login exists. |
| `backend/tests/conftest.py` | Provide a test-only JWT signing secret. |
| `backend/tests/test_database.py` | Expect the new table/head while retaining existing constraint tests. |
| `backend/tests/test_database_api.py` | Adapt existing API checks to authenticated rules/new migration head. |
| `frontend/src/App.jsx` | Public auth routes, protected workspace and ADMIN route. |
| `frontend/src/components/Layout.jsx` | Show account/role, sign-out and conditional admin navigation. |
| `frontend/src/main.jsx` | Mount the provider and auth stylesheet. |
| `frontend/src/pages/Overview.jsx` | Reflect delivered identity/data phases; no new dashboard data. |
| `frontend/src/pages/Settings.jsx` | Show current account and update phase descriptions. |
| `frontend/src/services/api.js` | Bearer attachment, one refresh retry and clean error messages. |
| `scripts/Verify-Phase2.ps1` | Check current migration head; support protected rule listing. |

## Compatibility preserved

The following existing files were compared with the Phase 2 baseline and remain unchanged:

- `docker-compose.yml`
- `backend/Dockerfile`
- `frontend/Dockerfile`
- `frontend/package.json`
- `frontend/package-lock.json`
- `frontend/vite.config.js`
- `backend/app/database.py`
- `backend/alembic/versions/0001_core_create_core_cybersentinel_tables.py`
- `scripts/Initialize-Environment.ps1`
- `scripts/Verify-Phase1.ps1`

The actual root `.env`, PostgreSQL data volume, historical documentation, existing frontend dependency lock, and original migration are not replaced. Existing bcrypt credentials remain usable.

## Where to begin

Read `docs/PHASE3.md`, then run the startup, migration, bootstrap and verification commands from the project root. `docs/PHASE3_VALIDATION.md` records the completed checks and what still needs confirmation on Windows.
