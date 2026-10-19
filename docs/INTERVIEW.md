# Portfolio and interview guide

[Demo walkthrough](DEMO.md) · [Architecture](ARCHITECTURE.md) · [Actual measurements](PHASE16_VALIDATION.md)

Prepared for Sai Yashweer Potelu's placement portfolio. Use only statements you can explain from the source and demonstrate locally. This is a project description, not a claim of enterprise deployment, clinical data handling or independently measured real-world detection accuracy.

## GitHub presentation

**Repository description**

SOC-style security analytics platform with configurable detections, explainable risk, incident investigation, threat intelligence and grounded AI assistance. Built with FastAPI, React, PostgreSQL and Docker.

**Suggested topics**

`cybersecurity`, `soc`, `fastapi`, `python`, `react`, `postgresql`, `docker`, `threat-intelligence`, `security-analytics`, `incident-response`, `explainable-ai`, `portfolio-project`

**Pinned-project blurb**

CyberSentinel turns synthetic security events into traceable findings and investigation cases. Explore ten behavioral rules, six-component risk explanations, analyst workflows and an evidence-grounded assistant. Includes a no-key demo, screenshots, migrations and verification reports.

No repository URL, public demo address or remote publication is invented in this update. Set the description/topics and pin the repository after reviewing/publishing your own source. Licensing remains an owner decision. Existing application version 0.15.0 is retained; documentation completion is not a reason to invent a v1.0 production release.

## Resume entry: detailed version

**CyberSentinel — AI-Powered Cyber Threat Intelligence & Security Analytics Platform**

Python · FastAPI · React · PostgreSQL · Docker

- Built a SOC-style application with validated telemetry ingestion and ten configurable behavioral rules for suspicious authentication, privilege changes, sensitive access and API activity.
- Designed a separate findings → explainable risk → incident pipeline with evidence references, duplicate prevention, conservative correlation and audited analyst workflows.
- Developed a React investigation workspace with timelines, risk breakdowns, threat-intelligence caching, analytics/reports and an evidence-grounded assistant with deterministic offline fallback.
- Verified a 10,000-event synthetic pipeline with replay and integrity checks; added JWT/RBAC, Alembic migrations and isolated backend/frontend tests.

## One-page resume: compact version

**CyberSentinel | FastAPI, React, PostgreSQL, Docker, Threat Intelligence, GenAI**

- Developed a SOC-style platform with ten behavioral detection rules, explainable risk scoring and auditable incident investigation over synthetic security telemetry.
- Built threat-intelligence enrichment, analytics and evidence-grounded AI assistance with JWT/RBAC; verified a 10,000-event pipeline and replay-safe persistence.

Keep these two bullets for a one-page resume. SQLAlchemy, Pydantic, Alembic, pytest, Vitest, Nginx and optional provider adapters can be discussed in the interview rather than crowding the technology line. AWS/Azure, Kafka, Kubernetes and autonomous remediation are future work and do not belong in the implemented stack.

## Thirty-second explanation

“CyberSentinel is a defensive SOC-style application built with FastAPI, React and PostgreSQL. It ingests synthetic security logs, uses ten configurable Python rules to identify suspicious behavior, then separately calculates explainable risk and groups eligible findings into investigation cases. Analysts can inspect the evidence, manage the case and use optional threat intelligence and a grounded assistant. The demo works offline, and I verified a 10,000-event pipeline with duplicate-prevention and evidence-integrity checks.”

## Two-minute explanation

“I built CyberSentinel to understand the full path from a security observation to an analyst decision. A chart alone doesn't explain why an alert matters, so I separated the system into ingestion, behavioral detection, risk scoring, incident correlation and investigation.

“FastAPI validates incoming telemetry, and PostgreSQL preserves its original fields. Ten modular Python rules analyze time windows—for example, five failed logins against one account within two minutes. Rule configuration lives in the database. A match creates a finding with confidence, metrics and event references. It does not immediately become an incident.

“The next engine calculates a six-component risk score and stores the points and reason for every contribution. Eligible findings can be linked into a case, but correlation requires multiple matching identity attributes. A shared source IP alone isn't enough. Analysts then inspect timelines, linked evidence, intelligence and notes in React, with role-controlled changes and audit records.

“The assistant sits after those decisions. Detection never depends on an LLM. Optional model output selects validated facts and defensive action references; a deterministic fallback keeps the demo usable without keys. Threat intelligence also has an explicitly labeled mock mode and separate caches.

“I tested boundary conditions, authorization, replay and evidence integrity, including a 10,000-event synthetic workflow. The major limits are synthetic telemetry, heuristic rules and a single-worker local architecture. Native recovery checks and cloud deployment remain separate acceptance work; I don't present this as a production SIEM or claim real-world detection accuracy.”

## Explain one detection end to end

1. `LOGIN_FAILED` records arrive with stable event IDs, timestamps, source IP and target account.
2. Ingestion validates and deduplicates them. Detection can read previously processed records as window context.
3. CS-001 reaches five failures for the same IP/account within 120 seconds; a structured match retains metrics and event references.
4. A fingerprint based on rule, entity and anchor event prevents duplicate findings during replay.
5. The risk engine computes independent bounded contributions; the finding itself still has rule confidence and severity.
6. Incident processing checks eligibility and multiple identity signals, creating or linking a case.
7. An analyst can explicitly enrich its IP, inspect stored score reasons and request a grounded explanation. AI does not change the score or decide to block an IP.

Use a real case from your running demo to state its count/confidence/risk. Avoid memorizing invented values such as “15 failures always equals risk 92.”

## Questions and defensible answers

| Question | Answer grounded in this implementation |
| --- | --- |
| Why FastAPI after Flask experience? | It adds typed Pydantic request/response contracts, dependency-based authorization and generated OpenAPI. Domain logic is kept outside routes, so framework choice doesn't become the architecture. |
| Why PostgreSQL? | Transactions, native enums/JSONB/INET, constraints and selective indexes fit evidence and relationship data. JSONB complements relational fields rather than replacing the model. |
| Why findings separate from incidents? | A behavioral match and a human investigation case have different lifecycles. The separation preserves evidence and permits independent scoring/correlation. |
| Why not classify from simulation labels? | That would measure the generator rather than a detector. Rules use observed attributes; labels are only evaluation ground truth. |
| What does processed mean? | Evaluated successfully, not excluded forever. New events still use processed history in their time windows. Failed batches roll back. |
| How are duplicates prevented? | Producer event-ID uniqueness for ingestion; canonical SHA-256 fingerprints plus a unique constraint for findings; explicit unique links/checkpoints for later stages. |
| How does a rule become configurable? | PostgreSQL supplies enabled, severity and typed configuration. ADMIN can update it; idempotent seeding preserves edits. |
| Is confidence the risk score? | No. Confidence describes the rule/evidence match. Risk adds policy and context across six bounded components, with reasons. Neither is a calibrated compromise probability. |
| Is risk history immutable? | There is one row per finding/version. Explicit rescore replaces that version row; version labels and hashes support reproducibility, not a ledger of every calculation. |
| Why not merge everything from one IP? | NAT, VPNs and shared gateways make IP-only correlation unsafe. The implementation requires multiple identity matches and rejects conflicting usernames. |
| How do you prevent AI hallucinations? | The model selects approved fact/action IDs, which are validated with schema, case identity and context hash; server-authored facts are rendered locally. Invalid output falls back. This limits unsupported claims but still needs analyst review. |
| Can prompt injection execute a response? | No tool execution, model SQL or automated remediation exists. Untrusted text is not an instruction source; Q&A uses controlled query intents. |
| How are API roles enforced? | Backend dependencies validate the active session and current database role on each request. UI hiding is not the security boundary. |
| What about refresh-token theft? | HttpOnly/SameSite cookies, production Secure transport, server-side hashed rotation/revocation and reuse handling; access tokens remain in browser memory. SSO/MFA is future work. |
| What happens when a provider fails? | Typed unknown/error results, bounded timeout/retry, cooldown and expiring cache. Mock/live separation prevents a simulated verdict masquerading as real intelligence. |
| How did you verify performance? | Dated 1k/10k isolated pipelines and authenticated read-load measurements. Report environment, throughput and p95; don't extrapolate embedded single-worker figures into production capacity. |
| Does 97.3% synthetic coverage prove accuracy? | No. It measures expected scenario/rule pairs in one generator configuration. One denial episode was below threshold; no operational precision estimate is claimed. |
| Why healthcare-style access monitoring? | Sensitive-record access illustrates least privilege and unusual access volume. The data is fictional, with no patient records or compliance certification. |

## STAR story

**Situation:** A security portfolio needed to demonstrate investigation logic rather than only attractive charts or an LLM wrapper.

**Task:** Connect validated logs to explainable detections and cases while keeping raw evidence intact and making the demo repeatable without external keys.

**Action:** Separate the domain engines, add time-window rules and deterministic fingerprints, persist explicit risk reasons, constrain correlation, implement role-controlled analyst workflows and grounded assistant output, then verify boundary cases and end-to-end replay.

**Result:** The recorded 10,000-event synthetic run produced 36 findings and 29 cases with valid evidence references, zero unprocessed events and no duplicate growth on replay. The Phase 16 suite recorded 799 backend passes with one native-concurrency skip and 86 frontend passes. Native Docker recovery and deployment remain clearly identified gates rather than overstated accomplishments.

## Scaling and honest limitations

Start by measuring native PostgreSQL query plans, lock contention, worker time and retention volume. The current API deliberately has one worker and process-local rate limits. Before scaling replicas, introduce shared rate limiting and coordinated job ownership, then consider a durable queue for long-running processing. Partition event tables and archive cold evidence only after measuring volume and defining retention. Managed PostgreSQL, HTTPS, secret management and centralized operational logs are deployment work, not current features.

Rules are explainable heuristics and can miss behavior outside the configured model. Geography is supplied/simulated. Mock reputation is not live reputation. Analysts decide responses; no malware, unauthorized scanning, exploitation or automated blocking is implemented. These limits make the project easier to assess, not less useful to explain.

## Final presentation checklist

- Be able to open and explain a rule, fingerprint, risk component and transaction test.
- Rehearse the [four-minute demo](DEMO.md#four-minute-presentation) with actual loaded data.
- Attribute benchmark numbers to the dated environment; avoid “enterprise-grade,” accuracy percentages without context and made-up speed improvements.
- Use a repository URL only after you own and publish it; verify staged files contain no secrets.
- Know the remaining [native acceptance gates](TESTING.md#native-restart-and-restore-gates) and license decision before deployment/public distribution.
