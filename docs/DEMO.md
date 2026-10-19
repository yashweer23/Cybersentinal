# Demo workflow and four-minute walkthrough

[Setup](SETUP.md) · [Interview answers](INTERVIEW.md) · [Screenshot gallery](SCREENSHOTS.md)

## Prepare the data

Use a local synthetic-data installation with migrations, ten seeded rules and an administrator already created. Set `THREAT_INTELLIGENCE_MOCK_MODE=true` and `AI_PROVIDER=fallback` in `.env`, leave all provider/AI keys empty, and recreate the backend if those settings changed. The generator includes fictional account/device/resource metadata and documentation/private IPs; it contains no patient information.

These PowerShell commands run from project root. A timestamped output name avoids overwriting an existing file. Event IDs remain deterministic for the same generator parameters, so re-importing the same dataset reports duplicates instead of multiplying evidence.

```powershell
$StartDate = [DateTime]::UtcNow.Date.AddDays(-7).ToString('yyyy-MM-dd')
$Stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
$DemoFile = "data/demo-$Stamp.jsonl"
docker compose exec backend python -m scripts.generate_demo_data --count 10000 --seed 42 --scenario mixed --start-date $StartDate --days 7 --output $DemoFile
if ($LASTEXITCODE -ne 0) { throw 'Demo generation failed.' }
docker compose exec backend python -m scripts.ingest_events --file $DemoFile
if ($LASTEXITCODE -ne 0) { throw 'Demo ingestion failed.' }
docker compose exec backend python -m scripts.run_detection --until-empty
if ($LASTEXITCODE -ne 0) { throw 'Detection failed.' }
docker compose exec backend python -m scripts.run_risk_scoring --until-empty
if ($LASTEXITCODE -ne 0) { throw 'Risk scoring failed.' }
docker compose exec backend python -m scripts.run_incident_processing --until-empty
if ($LASTEXITCODE -ne 0) { throw 'Incident processing failed.' }
docker compose exec backend python -m scripts.run_threat_enrichment --all --limit 50 --offset 0 --mock
if ($LASTEXITCODE -ne 0) { throw 'Mock enrichment failed.' }
Start-Process http://localhost:5173
```

If enrichment returns a non-null `next_offset`, repeat the last command using that offset until it is null. On a populated installation the CLI may process other pending local events/cases too. Use the isolated validation runner instead when comparing reproducible counts without changing the visible workspace.

Expected: 10,000 records generated; first import into a clean dataset inserts 10,000; all enabled detection rules execute; findings are scored and eligible cases are created; mock enrichment reports zero external lookups. Repeating an import/replay should not create duplicate findings/cases. Exact counts depend on retained data, configuration, start date and threshold windows.

The recorded Phase 16 clean run had 36 findings and 29 incidents. Its 95%-normal mixed dataset used a 500-event suspicious budget and **did not include the large API-burst scenario**; CS-010 executed but had zero matches. One access-denied episode fell below the seeded threshold. Do not lower thresholds or relabel results just to claim perfect coverage. Rule-specific tests cover all ten rules. See [actual results](PHASE16_VALIDATION.md).

A rolling seven-day range can exclude the first morning of a week generated from midnight. For all 10,000 events, choose 30 days or a custom UTC range starting at `$StartDate` midnight. System Health always shows retained totals.

## Verify the stored evidence

This command uses the database container's configured username/database, including installations that changed the defaults:

```powershell
docker compose exec db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
```

In psql:

```sql
\dt
SELECT version_num FROM alembic_version;
SELECT processed, count(*) FROM security_events GROUP BY processed;
SELECT r.rule_id, r.name, count(f.id) AS findings
FROM detection_rules r LEFT JOIN detection_findings f ON f.detection_rule_id = r.id
GROUP BY r.rule_id, r.name ORDER BY r.rule_id;
SELECT finding_id, severity, confidence, event_count, first_seen, last_seen
FROM detection_findings ORDER BY created_at DESC LIMIT 10;
SELECT risk_level, count(*) FROM risk_assessments GROUP BY risk_level;
SELECT status, count(*) FROM incidents GROUP BY status;
\q
```

## Four-minute presentation

| Time | Screen / action | What to say |
| --- | --- | --- |
| 0:00–0:30 | Sign in, Overview; select 7 days | “This is a synthetic SOC workflow. The summary comes from stored events and cases; it is not a static dashboard.” |
| 0:30–1:00 | Live Events; filter `LOGIN_FAILED` | “Ingestion validates and deduplicates telemetry. The raw evidence is preserved. The live view polls new stored events.” |
| 1:00–1:50 | Incidents → a high or critical case → Findings / Events | “The detector first produces findings. This case links eligible findings, their event references and a timeline. A rule match is not automatically a confirmed compromise.” |
| 1:50–2:25 | Expand a finding's risk breakdown | “Risk is a separate six-component policy. Each contribution has points and a reason; confidence describes evidence strength.” |
| 2:25–2:55 | Threat intel tab | “This demo uses labeled synthetic reputation. Real provider adapters have caching, timeouts and unknown/error states. Enrichment does not silently rescore a case.” |
| 2:55–3:30 | AI Analysis → generate if needed | “This is labeled deterministic fallback without a key. With an LLM, validated fact/action references constrain the result. The model cannot create evidence or change case status.” |
| 3:30–4:00 | Analytics, then notes/status if time permits | “Analysts retain the workflow decisions. Analytics uses defined UTC cohorts; reports are role-controlled. Tests and replay checks verify the synthetic pipeline.” |

Use whichever actual high/critical case exists; do not fabricate a critical incident. Prefer a brute-force or privilege-change case with clear linked evidence. Be ready to show the rule module, risk policy and a boundary test in VS Code. Do not resolve or edit real investigation records for a demo.

## Demo checklist

- Ready endpoint returns `ready`; migrations and rule seed have completed.
- Sign in once beforehand with a known username; do not show passwords, tokens, `.env` or terminal history in the recording.
- All data shown is synthetic. Mock mode and AI fallback labels remain visible.
- Select a date range that includes the generated week; preselect a case with findings and analysis.
- Confirm charts load, no error banners appear, and the chosen risk breakdown has actual component reasons.
- Keep [Testing](TESTING.md) available for precise numbers and the remaining native acceptance gates.
- Explain that synthetic coverage is not production detection accuracy, and cloud deployment is not implemented.

For a 60–90 second optional recording, use Overview → case → risk → intelligence → analysis → analytics. Capture a 1440×900 browser viewport with consistent zoom and hide operating-system notifications. Screenshots are supplied; no video or hosted demo is claimed in this update.
