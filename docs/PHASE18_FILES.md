# Phase 18 update file manifest

This is an incremental update for the existing Phase 1–17 project. Every included source file is complete. Apply these paths at the existing project root after reviewing your local modifications. Do not recreate the project, overwrite `.env`, remove volumes, reseed users, or replace unrelated files.

The update ZIP contains these files under `cybersentinel/`. It excludes runtime data, secrets, dependencies, built assets, backups and the temporary verification harness. No files are deleted and no database migration is added.

## Created

- `backend/scripts/cloud_release.py`
- `backend/scripts/populate_cloud_demo.py`
- `backend/scripts/verify_cloud.py`
- `backend/tests/test_cloud_deployment.py`
- `docs/DEPLOYMENT.md`
- `docs/PHASE18_FILES.md`
- `docs/PHASE18_VALIDATION.md`
- `docs/phase18_local_results.json`
- `render.yaml`

## Modified

- `.env.example`
- `README.md`
- `backend/app/config.py`
- `backend/app/main.py`
- `backend/app/operations/http.py`
- `backend/app/operations/logging.py`
- `docs/README.md`
- `frontend/Dockerfile`
- `frontend/nginx/cybersentinel.conf.template`
- `frontend/nginx/start-frontend.sh`

## Applying and validating

Read [DEPLOYMENT.md](DEPLOYMENT.md) before cloud resource creation. It includes Windows PowerShell commands for local compatibility checks and remote smoke/demo utilities, the managed database release sequence, environment ownership, backup and rollback steps. See [PHASE18_VALIDATION.md](PHASE18_VALIDATION.md) for actual local results and remaining deployment gates.

Existing local Compose service names, ports, `.env` keys, database models/migrations, APIs, frontend features and provider safeguards remain intact. The new optional cloud keys do not require editing a working local `.env`.
