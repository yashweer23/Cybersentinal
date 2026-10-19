# Phase 6 update file manifest

This incremental archive contains **45 complete files: 32 new and 13 modified**. Paths are relative to your existing `cybersentinel` project root. Merge the archive into that root; retain all other Phase 1–5 files. It is not a standalone replacement project. No existing source file is deleted.

Your actual `.env`, database volumes, generated datasets, frontend, Dockerfiles, Compose configuration, dependency locks, authentication implementation and ingestion/generation implementation are not included or replaced. `.env.example` documents four optional detection settings; their defaults work without changing your `.env`.

Run `docker compose exec backend alembic upgrade head` after rebuilding. The supplied migration is the only new migration required. Read [PHASE6.md](PHASE6.md) for commands, architecture, configuration, SQL, API and Swagger verification; [PHASE6_VALIDATION.md](PHASE6_VALIDATION.md) contains measured results and execution limits.

## Created files

| Path | Purpose |
| --- | --- |
| `backend/alembic/versions/0003_detection_findings.py` | Findings table, constraints and four compound event indexes; conditional correction of the legacy synthetic-IP rule description |
| `backend/app/detection/base.py` | Common rule interface, structured match and safe metadata helpers |
| `backend/app/detection/configuration.py` | Typed, bounded validation for the ten database rule configurations |
| `backend/app/detection/engine.py` | Transactional batch orchestration, persistence, processing flags, metrics and run audits |
| `backend/app/detection/reputation.py` | Reputation interface and independent local synthetic indicator provider |
| `backend/app/detection/rules/__init__.py` | Registry of the ten rule implementations |
| `backend/app/detection/rules/brute_force.py` | CS-001 repeated failures per IP/account |
| `backend/app/detection/rules/password_spray.py` | CS-002 failures across many accounts with few attempts each |
| `backend/app/detection/rules/impossible_travel.py` | CS-003 geographic distance and required travel speed |
| `backend/app/detection/rules/unusual_login.py` | CS-004 historical/configured local-hour login baseline |
| `backend/app/detection/rules/privilege_escalation.py` | CS-005 significant successful role changes requiring review |
| `backend/app/detection/rules/suspicious_ports.py` | CS-006 passive unique-port activity per source/destination |
| `backend/app/detection/rules/excessive_access.py` | CS-007 sensitive-record access volume |
| `backend/app/detection/rules/malicious_ip.py` | CS-008 local synthetic reputation matches |
| `backend/app/detection/rules/repeated_access_denied.py` | CS-009 repeated denials per user/source |
| `backend/app/detection/rules/abnormal_api.py` | CS-010 API volume per source or account |
| `backend/app/detection/utils/__init__.py` | Shared-helper package |
| `backend/app/detection/utils/baselines.py` | Completed-day volume baselines and effective thresholds |
| `backend/app/detection/utils/fingerprints.py` | Canonical SHA-256 logical finding identity |
| `backend/app/detection/utils/geo.py` | Coordinate validation and Haversine distance |
| `backend/app/detection/utils/time_windows.py` | Inclusive rolling windows, threshold crossings and explainable confidence |
| `backend/app/models/detection_finding.py` | Findings ORM model, evidence, relationships and constraints |
| `backend/app/repositories/detection_repository.py` | Bounded SQL context, row claims, evidence validation, upsert, lists and statistics |
| `backend/app/routes/detection.py` | Run, read, statistics and ADMIN rule-configuration APIs |
| `backend/app/schemas/detection.py` | Validated API requests, responses, filters and summaries |
| `backend/scripts/run_detection.py` | Trusted development CLI, dry runs, replay and actual run summaries |
| `backend/scripts/evaluate_detections.py` | Optional standalone synthetic-label evaluation; never imported by runtime detection |
| `backend/tests/test_detection_rules.py` | 64 rule, configuration, helper and CLI tests |
| `backend/tests/test_detection_engine.py` | 19 database, engine, API and integration tests |
| `docs/PHASE6.md` | Architecture, thresholds, schema, semantics and exact Windows/Docker verification instructions |
| `docs/PHASE6_VALIDATION.md` | Actual test results, benchmark counts, evaluation and limitations |
| `docs/PHASE6_FILES.md` | This complete file manifest |

## Modified files

| Path | Change |
| --- | --- |
| `.env.example` | Four optional detection batch/context/evidence limits |
| `README.md` | Phase 6 status, architecture, migration head, API operations and documentation links |
| `backend/app/config.py` | Validated detection settings with defaults |
| `backend/app/main.py` | Register detection routes, private-response cache handling and Phase 6 version |
| `backend/app/models/__init__.py` | Register the new findings model for ORM/Alembic discovery |
| `backend/app/models/security_event.py` | Match the four new compound query indexes |
| `backend/app/routes/database.py` | Retain development database checks; move existing rule listing to the shared detection router |
| `backend/app/routes/system.py` | Update delivered/planned module health metadata |
| `backend/app/schemas/health.py` | Phase 6 version/phase defaults |
| `backend/scripts/seed_detection_rules.py` | Correct CS-008 description; preserve all existing thresholds and idempotent seeding |
| `backend/tests/test_database.py` | Expect the findings table and new migration head |
| `backend/tests/test_database_api.py` | Match the new head/table count and authenticated rule route availability |
| `scripts/Verify-Phase3.ps1` | Compare installed migration with the API's expected head instead of hardcoding the old revision |

Existing package initializers, database session management, role enums, JWT dependencies, event validation, generators and import services are reused. No parallel implementation is introduced.
