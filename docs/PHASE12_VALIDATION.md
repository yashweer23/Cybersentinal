# Phase 12 — Executed validation

Validated on 2026-10-11 against the existing Phase 11 project, with the complete Phase 12 frontend and compatible backend projections. Machine-readable results are in `phase12_results.json`. The update does not change models, migrations, environment variables, ports, dependencies, authentication, detection, risk calculations or incident workflow rules.

## Test and build results

| Check actually executed | Result |
| --- | --- |
| Full frontend Vitest suite | **48 passed**, three files, 3.37 seconds |
| New frontend investigation coverage | 22 tests, included in the full suite |
| Full backend pytest suite | **654 passed, 1 skipped**, 41.24 seconds |
| Targeted new projections plus existing incident API tests | 24 passed |
| Ruff, all four changed/new Python files | Passed |
| Fresh database Alembic upgrade through existing head | Passed, `0007_dashboard_polling` |
| Alembic model/schema comparison | No drift |
| Production Vite build | Passed, 2,606 modules; no oversized-chunk warning |
| Actual Chromium / Vite / Uvicorn / database workflow | Passed |
| Responsive investigation checks | Six tabs × four screen sizes = **24 passed** |
| Browser JavaScript exceptions / console warnings | **0 / 0** |
| Unexpected API failures | **0** |

Backend tests used an isolated **PGlite PostgreSQL 17.5** schema through the scratch socket adapter. The one skipped test requires independent native PostgreSQL writer concurrency; the embedded engine cannot validate that behavior. The one warning is the existing Starlette TestClient/httpx deprecation. Neither was hidden or converted into a pass. A scratch driver adapter disabled prepared statements/pipelining for this embedded transport; production driver settings were not changed.

Docker Desktop and PowerShell are unavailable in this build environment. Consequently, **native Docker startup, native PostgreSQL concurrency, and `Verify-Phase12.ps1` execution on Windows are not claimed as tested**. The script was reviewed against the existing routes and PowerShell conventions. Run the exact Docker/test commands in `PHASE12.md` on the user's machine. The database test runner creates and removes only its temporary test database.

## Regression coverage

Frontend tests cover case loading/missing states, stored risk components and a rescore mismatch, finding evidence, event drawer and escaped raw content, focus restoration, event filters, ascending/descending timelines, simulated and partially failed intelligence, notes and retained drafts, assignment, start/resolve/false-positive/reopen forms, required inputs, 403 handling, all three roles, queue filter restoration, tab keyboard navigation and rejection of unsafe return URLs. A deferred enrichment test switches away and back while the write is pending and confirms the button stays disabled and only one POST occurs.

Backend additions are tested for active-operator eligibility, literal search and bounded pagination, authorization and field projection, incident transitions and stored assessment selection, read operations that do not mutate risk, case-specific event filtering and ports, timeline ordering and actor/context fields, enrichment audit inclusion, missing cases and invalid filters. Existing authentication, detection, risk, incident, threat-intelligence and dashboard tests remain in the full regression suite.

## Synthetic pipeline

The existing generator produced **10,000 mixed events**, seed **42**, starting 2026-10-05 across seven days, with 95% normal activity. The actual existing importer, detection runner, risk runner, incident processor and mock enrichment service executed against the isolated database. No endpoint response, risk score, finding or incident was fabricated for the browser.

| Stage | Measured wall time for the base 10,000-event run |
| --- | ---: |
| Ingestion | 5,168.65 ms |
| Detection | 13,724.46 ms |
| Risk assessment | 88.24 ms |
| Incident processing | 489.38 ms |
| Mock intelligence enrichment | 340.11 ms |

Detection's own measured timer was 13.717 seconds, **729.0 events/second**. It executed all ten enabled rules, processed all 10,000 events, and produced **36 findings**. Those yielded **36 assessments**, **29 incidents** and **34 cached intelligence bundles**. The base budget contains no abnormal API burst, so CS-010 correctly produced zero matches here; rule regression tests still cover that rule. The base data also produced no CRITICAL incident.

To exercise the required critical-case workflow without changing thresholds or scores, the harness ingested **51 additional synthetic behavioral events**: 50 failed admin-console logins within 49 seconds from documentation address `198.51.100.73`, followed by one success. The original detection/risk/incident/enrichment services produced the additional records. The resulting critical case had a genuine stored score of **75**, 52 linked findings and 51 event references. These are synthetic observations, not evidence of a real intrusion.

| Database after the supplemental fixture | Count |
| --- | ---: |
| Security events | 10,051 |
| Processed events | 10,051 |
| Detection findings | 88 |
| Risk assessments | 88 |
| Incidents | 30 |
| Cached intelligence bundles | 35 |
| Invalid retained evidence references | **0** |

| Rule | Base 10,000-event findings | Final with supplemental fixture |
| --- | ---: | ---: |
| CS-001 | 5 | 6 |
| CS-002 | 2 | 2 |
| CS-003 | 4 | 4 |
| CS-004 | 3 | 3 |
| CS-005 | 3 | 3 |
| CS-006 | 3 | 3 |
| CS-007 | 7 | 7 |
| CS-008 | 5 | 56 |
| CS-009 | 4 | 4 |
| CS-010 | 0 | 0 |

Mock enrichment made **zero external provider requests**. It retained unknown results accurately. These timings are observations on the embedded validation runtime, not a production PostgreSQL benchmark or detection-accuracy claim. Existing Phase 6–10 guides document their previous performance and evaluation results.

## Browser acceptance results

Playwright drove a real Chromium browser against the running Vite frontend, Uvicorn backend, actual authenticated accounts and the pipeline database. The browser was not fed mocked successful incident API responses. Only the explicit failure-isolation test intercepted an intelligence GET to return 503. Accounts and events were temporary, synthetic and isolated from development data.

The following workflow passed:

1. ANALYST sign-in, critical queue filter, open case, return with the filter intact, navigate directly and reload.
2. Inspect all six stored risk components, expand a finding and its evidence, open an event drawer and escaped raw JSON, trap/restore focus, close with Escape, and apply a backend event-type filter.
3. Order the whole paginated timeline newest-first; inspect simulated provider results; explicitly refresh intelligence with exactly one permitted POST.
4. Assign to the signed-in analyst, start investigation, type a note, refresh without losing it, save and observe the persisted note.
5. Reject an empty resolution form, submit a summary, verify RESOLVED, unchanged risk, and assignment/status/resolution/comment/enrichment audit context.
6. Confirm reopen, require a false-positive reason, close the case, and verify event/finding/incident totals remain **10,051 / 88 / 30** with linked evidence still present.
7. Observe exactly **one detail poll in 16.202 seconds**, then navigate away and observe **zero case requests during the following 15.5 seconds**.
8. Inject an intelligence read failure without hiding risk/case content; show a clear missing-case state for an invalid ID.
9. VIEWER reads notes, evidence and intelligence but sees no write controls. Direct assignment/status/comment/enrichment requests all receive 403 without logging the user out. ADMIN sees permitted controls.
10. Retrieve `/docs` successfully and confirm the added eligible-analyst route in OpenAPI.

The run made 168 API requests, including deliberate denied mutations. In `phase12_results.json`, mutation counts include one intentionally rejected VIEWER request for each of assignment, status, comment and intelligence refresh; they are not duplicate successful writes. Three 401 responses were expected refresh-cookie bootstrap checks before sign-in. The deliberately invalid case returned 404, including a mounted-page refresh. The injected 503 and these intentional denial cases are excluded from the unexpected-error count.

## Responsive and performance observations

Overview, Timeline, Findings, Events, Threat intel and Notes were each opened at **1366×768, 1440×900, 1920×1080 and 390×844**. Every check found zero document-level horizontal overflow and no unexpected error alert. Long JSON and event tables scroll inside their own containers. Selected real screenshots are in `screenshots/phase12/` and linked from the README.

The full page-check timings (navigation, loading wait, 180 ms settling delay, assertions **and PNG capture**) are recorded per page in `phase12_results.json`. They are not isolated API response times or user-perceived load benchmarks. The median was **1,214.5 ms**, with a **1,125–1,339 ms** range in this runtime.

The lazy investigation JavaScript chunk is **33.59 kB / 9.68 kB gzip**, with **11.30 kB / 2.78 kB gzip** CSS. The shared entry is **374.26 kB / 121.24 kB gzip**. Existing chart code remains in its separate lazy chunk. No dependency was added. Production bundles were built; browser acceptance used the development server, not a deployed production host.

## Issues found and resolved

- A large correlated case made the overview excessively long. It now previews three relationship decisions with a route to all paginated findings. Mobile reading order places risk immediately after the case summary.
- A notes label wrapped the textarea, allowing the accessible name to vary after a draft remounted. An explicit label/textarea association now keeps the label stable.
- A tab could remount while its mutation was pending. Shared case/operation mutation keys keep controls disabled across remounts; the regression test verifies one request.
- The first browser harness checked a heading before authentication completed after reload. It now waits for the actual case heading and loading state.
- The first harness treated a later polling 404 for its deliberately invalid case as unexpected. Error accounting now identifies that exact intentional case; other unplanned failures remain assertions.
- The default mixed dataset lacked a critical case. The independent behavioral fixture above exercises it through the unchanged pipeline instead of altering persisted scores or labeling arbitrary cases critical.
- A cached native `psycopg_binary` runtime installation was damaged. The same pinned wheel was restored only in the scratch validation environment. Application requirements and Dockerfiles remain unchanged.

All application issues listed above were retested. Phase 13 AI, Phase 14 advanced reporting and deployment were not started.
