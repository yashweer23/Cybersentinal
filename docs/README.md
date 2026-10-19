# Documentation index

Start with the [project README](../README.md). The project is intended for GitHub repository publication and local Docker execution. The following guides cover the application and its optional deployment preparation.

| Guide | Use it for |
| --- | --- |
| [GitHub publication](GITHUB.md) | Repository setup, exact Windows PowerShell upload commands and local-demo scope |
| [Deployment](DEPLOYMENT.md) | Optional prior Render preparation; not required for GitHub publication |
| [Phase 18 verification](PHASE18_VALIDATION.md) | Local results and the cloud checks still pending |
| [Phase 18 file manifest](PHASE18_FILES.md) | Complete files changed in the deployment update |
| [Setup](SETUP.md) | Docker, Windows PowerShell, host development, environment and troubleshooting |
| [Demo](DEMO.md) | Generate → ingest → detect → score → correlate → enrich; four-minute walkthrough |
| [Architecture](ARCHITECTURE.md) | Component/infrastructure/data-flow diagrams, policy and design trade-offs |
| [Database](DATABASE.md) | All 17 tables, fields, actual FK relationships, indexes and migrations |
| [API](API.md) | Authentication examples, pagination and complete route/role inventory |
| [Security](SECURITY.md) | Threat model, controls, AI boundary and limitations |
| [Testing](TESTING.md) | Repeatable native verification commands and acceptance criteria |
| [Performance](PERFORMANCE.md) | Dated pipeline/read-load figures and interpretation |
| [Screenshots](SCREENSHOTS.md) | Current synthetic-data capture gallery |
| [Interview](INTERVIEW.md) | Resume bullets, GitHub description/topics, explanations and STAR story |
| [Phase 17 verification](PHASE17_VALIDATION.md) | What was actually checked in this documentation update |
| [Phase 17 file manifest](PHASE17_FILES.md) | Complete updated-file list and installation boundary |

## Historical phase records

The `PHASE1…PHASE16` guides/manifests and saved measurement reports document earlier implementation stages. Their proposed thresholds, port layouts or statements about future pages may have been superseded. Use the guides above and the source as current references; do not apply old phase commands to reset an existing installation.

In particular, [Phase 15 operations](PHASE15.md) and [Phase 16 validation](PHASE16_VALIDATION.md) retain detailed operational/test evidence. [phase16_results.json](phase16_results.json) is a preserved dated measurement artifact, not a claim that every check was rerun during Phase 17.
