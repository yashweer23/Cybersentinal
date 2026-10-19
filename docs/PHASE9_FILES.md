# Phase 9 — Complete file manifest

This incremental package targets the existing Phase 8 project. All paths are relative to its `cybersentinel` root. Every packaged source file contains the complete updated contents.

The update contains **26 new files and 21 modified files**. No existing file is deleted. SHA-256 comparison against the saved **222-file Phase 8 baseline** confirms the other **201 baseline files are unchanged**.

## Files created

| Path | Purpose |
| --- | --- |
| `backend/alembic/versions/0006_threat_intelligence.py` | Mode-specific cache/cooldown tables and unknown-compatible legacy columns |
| `backend/app/models/threat_intelligence_result.py` | Two new cache-result and provider-state models tied to the existing indicator identity |
| `backend/app/routes/threats.py` | Seven authenticated lookup, cache, enrichment and status operations |
| `backend/app/services/incident_enrichment.py` | Bounded canonical-IP association, shared-IP deduplication and resumable bulk work |
| `backend/app/threat_intelligence/__init__.py` | Python package marker |
| `backend/app/threat_intelligence/aggregator.py` | Explainable maximum-signal aggregation and explicit unknown/partial coverage |
| `backend/app/threat_intelligence/cache.py` | PostgreSQL upserts, mode separation, expiry, filtering and compact projections |
| `backend/app/threat_intelligence/providers/__init__.py` | Python package marker |
| `backend/app/threat_intelligence/providers/abuseipdb.py` | AbuseIPDB v2 check adapter and confidence mapping |
| `backend/app/threat_intelligence/providers/base.py` | Provider protocol and bounded, sanitized, fixed-host HTTP transport |
| `backend/app/threat_intelligence/providers/mock_provider.py` | Offline deterministic results using the Phase 6 indicator set |
| `backend/app/threat_intelligence/providers/otx.py` | OTX IPv4/IPv6 general adapter and contextual pulse mapping |
| `backend/app/threat_intelligence/providers/virustotal.py` | VirusTotal v3 adapter, engine counts and separate community reputation |
| `backend/app/threat_intelligence/reputation.py` | Read-only bridge to the existing risk reputation abstraction |
| `backend/app/threat_intelligence/schemas.py` | Validated provider/result/query/enrichment/status contracts |
| `backend/app/threat_intelligence/service.py` | Cache-aware lookups, shared cooldowns, transactions, audit and metrics |
| `backend/app/threat_intelligence/utils/__init__.py` | Python package marker |
| `backend/app/threat_intelligence/utils/ip_validation.py` | Canonical IPv4/IPv6 validation and external-query eligibility |
| `backend/app/threat_intelligence/utils/normalization.py` | Safe numeric/text/time parsing, identity checks and credential redaction |
| `backend/scripts/run_threat_enrichment.py` | Trusted development CLI with bounded targets, mock mode and refresh |
| `backend/tests/test_threat_api.py` | RBAC, input, cached reads, Swagger and explicit Phase 7/8 integration tests |
| `backend/tests/test_threat_providers.py` | Provider fixtures, IP gate, errors, normalization, retries and secret safety tests |
| `backend/tests/test_threat_service.py` | Cache/cooldown, persistence, enrichment, preservation, limits and CLI tests |
| `docs/PHASE9.md` | Architecture, providers, mappings, API/CLI contracts, Windows/Docker setup and SQL checks |
| `docs/PHASE9_FILES.md` | This exact created/modified file manifest |
| `docs/PHASE9_VALIDATION.md` | Executed regression, migration, pipeline, performance and preservation results |

## Files modified

| Path | Modification |
| --- | --- |
| `.env.example` | Optional provider secrets/switches and bounded cache/HTTP/enrichment defaults |
| `README.md` | Phase 9 features, architecture, upgrade, endpoints and documentation links |
| `backend/app/config.py` | Existing settings extended with validated optional Phase 9 defaults |
| `backend/app/detection/reputation.py` | Optional context field on the existing reputation value; original provider behavior preserved |
| `backend/app/main.py` | Registers threat routes, no-store response coverage and version 0.9.0 |
| `backend/app/models/__init__.py` | Registers both new models for the existing SQLAlchemy/Alembic metadata |
| `backend/app/models/threat_intelligence.py` | Four nullable fields distinguish unavailable data from zero/false |
| `backend/app/risk/calculator.py` | Explicit cached source in the existing score input snapshot/hash |
| `backend/app/risk/components.py` | Cached signal/unknown explanations without changing point bands |
| `backend/app/risk/engine.py` | Explicit cached-provider selection and source context through the existing scorer |
| `backend/app/routes/system.py` | Removes delivered intelligence from the planned-modules list |
| `backend/app/schemas/health.py` | Application health version/phase 9 |
| `backend/app/schemas/risk.py` | Validated opt-in reputation_source setting, default local |
| `backend/app/schemas/threat_intelligence.py` | Legacy create/response schemas accept unknown fields as null |
| `backend/requirements-dev.in` | Removes redundant development-only HTTPX declaration |
| `backend/requirements-dev.txt` | Preserves versions and updates HTTPX source annotation |
| `backend/requirements.in` | Promotes HTTPX to runtime requirements |
| `backend/requirements.txt` | Adds already-locked HTTPX, httpcore and certifi runtime dependencies |
| `backend/scripts/run_risk_scoring.py` | Adds --reputation-source local|cached to the existing CLI |
| `backend/tests/test_database.py` | Expected cache models, tables and current Alembic head |
| `backend/tests/test_database_api.py` | Expected migration head and 16 application tables |

## Apply the update

Merge the archive directly into the existing project root; do not create a second nested `cybersentinel` directory. If you made independent edits to a listed file after Phase 8, compare and merge those changes before replacement.

The archive excludes the actual `.env`, credentials, generated datasets, PostgreSQL data, virtual environments and dependency caches. Docker Compose, Dockerfiles, existing migrations 0001–0005, detection rules, frontend and original database connection configuration remain unchanged. Preserve the existing PostgreSQL host mapping, including port 15432 where configured.

Rebuild the backend dependencies, then apply **`0006_threat_intelligence`**. Do not generate another initial migration. Full PowerShell startup, CLI/API demonstrations, authenticated Swagger verification and SQL checks are in [PHASE9.md](PHASE9.md). Executed tests and actual measurements, including untested live/Docker limits, are in [PHASE9_VALIDATION.md](PHASE9_VALIDATION.md).

The default configuration is offline mock mode; no API keys are needed. External providers require explicit live mode and backend-only optional keys. Enrichment preserves existing scores and investigation records. Cached rescoring is a separate explicit Phase 7 operation followed by the existing Phase 8 processor.
