# Application screenshots

[Project overview](../README.md) · [Demo guide](DEMO.md) · [Verification](PHASE17_VALIDATION.md)

Captured from the actual React production build against FastAPI and an isolated PGlite database on 2026-10-17, using Chromium 153 at **1440 × 900**, UTC, 100% device scale. The capture used Vite preview as a local reverse proxy, not Docker/Nginx; this does not verify native deployment. The only Phase 17 UI change replaces a stale footer phase label; no dashboard content is fabricated or overlaid.

The pipeline generated 10,000 events with seed 42, mixed scenarios and a 2026-10-10 UTC start. Accounts/resources are fictional. No external intelligence or LLM call was made. Login fields were blank for capture; temporary credentials remained in process memory and the disposable database was removed after verification.

The rolling seven-day charts show fewer than 10,000 events because their cutoff is the capture time minus seven days, while generation began at midnight. System Health shows all 10,000 retained events. Use a custom UTC range starting at midnight or 30 days to see the full generated dataset. Findings/cases shown use their own documented time/cohort definitions.

## Login

Blank credential fields; no password or token is shown.

![Login with synthetic CyberSentinel data](screenshots/phase17-login.png)

## Security overview

Seven-day event cohort with current incident state. All cases in this dataset are High, so Critical correctly shows zero.

![Security overview with synthetic CyberSentinel data](screenshots/phase17-overview.png)

## Live security events

Stored synthetic telemetry; new data appears only after ingestion.

![Live security events with synthetic CyberSentinel data](screenshots/phase17-events.png)

## Incident queue

Risk, severity, status and case links from the database.

![Incident queue with synthetic CyberSentinel data](screenshots/phase17-incidents.png)

## Incident investigation

A real synthetic privilege-change finding promoted into an analyst case.

![Incident investigation with synthetic CyberSentinel data](screenshots/phase17-investigation.png)

## Explainable risk

Six stored contributions: 25 + 13 + 20 + 0 + 15 + 0 = 73. Critical rule severity and High case risk are distinct.

![Explainable risk with synthetic CyberSentinel data](screenshots/phase17-risk.png)

## Case timeline

Evidence and workflow context for the selected case.

![Case timeline with synthetic CyberSentinel data](screenshots/phase17-timeline.png)

## Threat intelligence

Simulated mode and unconfigured live providers remain visibly labeled.

![Threat intelligence with synthetic CyberSentinel data](screenshots/phase17-intelligence.png)

## AI analyst

Deterministic fallback with validated evidence references; not a claim of a live LLM call.

![AI analyst with synthetic CyberSentinel data](screenshots/phase17-ai.png)

## Advanced analytics

UTC cohort and response definitions. Timings reflect a scripted synthetic investigation, not analyst productivity.

![Advanced analytics with synthetic CyberSentinel data](screenshots/phase17-analytics.png)

## Reports and exports

Existing role-controlled report generation interface.

![Reports and exports with synthetic CyberSentinel data](screenshots/phase17-reports.png)

## System health

10,000 stored/evaluated events, zero pending; provider modes are configuration states.

![System health with synthetic CyberSentinel data](screenshots/phase17-health.png)

## Detection rules

Current seeded configuration and enabled rules.

![Detection rules with synthetic CyberSentinel data](screenshots/phase17-rules.png)

## Refreshing the gallery

Follow the demo guide with synthetic-only data, choose a populated case, and capture the listed screens at the same viewport. Keep simulation/fallback labels and empty-state/error truth intact. Do not show `.env`, credentials, bearer tokens, real employee identifiers, patient data or unsupported accuracy claims. Old phase screenshots remain historical evidence; the root README uses this current gallery.
