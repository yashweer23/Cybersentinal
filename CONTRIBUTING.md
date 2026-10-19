# Contributing and local changes

Read the [architecture](docs/ARCHITECTURE.md), [security boundaries](docs/SECURITY.md) and [test guide](docs/TESTING.md) before making changes. Preserve the distinction between events, findings, assessments and incidents.

- Keep domain logic outside routes; reuse existing sessions, models, validation and RBAC dependencies.
- Add focused rule/constraint/authorization tests for behavioral changes. Use isolated test databases/schemas; never reset development data.
- Use Alembic for schema changes and review generated DDL. Preserve old evidence and documented migration compatibility.
- Update the current docs and CLI examples when behavior changes. Describe configuration defaults and any existing-installation differences.
- Keep `.env`, secrets, database dumps, logs, generated datasets and dependency directories out of commits. Use synthetic fixtures only.
- Run the relevant checks in [TESTING.md](docs/TESTING.md); report skipped native/environment checks explicitly.

No public contribution workflow or license is assumed. The owner should select a project license and private vulnerability-reporting channel before inviting public reuse/contributions. Do not post real credentials or operational security logs in public issues.
