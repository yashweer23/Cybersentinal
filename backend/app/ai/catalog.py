"""Server-authored, reference-backed facts and conditional defensive guidance.

Providers select opaque IDs, never author factual claims. This is deliberately a
constrained analyst, not free-form generation followed by unverifiable prose checks.
"""

from app.ai.schemas import AnalysisContent, Evidence, EvidencePlan, Reference

RULE_NAMES = {
    "CS-001": "brute-force authentication",
    "CS-002": "password spraying",
    "CS-003": "impossible travel",
    "CS-004": "unusual login time",
    "CS-005": "privilege escalation",
    "CS-006": "suspicious port activity",
    "CS-007": "excessive sensitive-record access",
    "CS-008": "local suspicious-IP activity",
    "CS-009": "repeated access denials",
    "CS-010": "abnormal API activity",
}
METRIC_NAMES = {
    "attempt_count": "failed attempts",
    "unique_username_count": "distinct targeted accounts",
    "access_count": "record accesses",
    "denial_count": "denials",
    "request_count": "API requests",
    "unique_port_count": "distinct destination ports",
    "threshold": "stored threshold",
    "window_seconds": "configured window (seconds)",
    "duration_seconds": "observed duration (seconds)",
    "distance_km": "distance (km)",
    "elapsed_hours": "elapsed hours",
    "required_speed_kmh": "required travel speed (km/h)",
    "speed_threshold_kmh": "speed threshold (km/h)",
    "normal_start_hour": "normal start hour",
    "normal_end_hour": "normal end hour",
    "baseline_event_count": "baseline events",
    "reputation_score": "local reputation score",
}


class EvidenceCatalog:
    def __init__(self, context):
        self.context = context
        self.facts = {}
        self.references = {}
        self.finding_facts = []
        self.representative_findings = []
        self.risk_facts = []
        self.intelligence_facts = []
        self.investigations = {
            "review": (
                "Review the linked findings and original events before making a security decision."
            ),
        }
        self.recommendations = {
            "monitor": (
                "Consider monitoring related activity and follow the "
                "organization's incident-response procedures."
            ),
        }
        self._build()

    def add(self, key, statement, refs):
        self.facts[key] = Evidence(statement=statement, reference_ids=[r[0] for r in refs])
        for identifier, kind, label in refs:
            self.references[identifier] = Reference(reference_id=identifier, kind=kind, label=label)

    def _build(self):
        data = self.context.data
        case, coverage = data["incident"], data["coverage"]
        case_ref = (self.context.incident_id, "incident", "Incident")
        self.add(
            "case",
            (
                f"This {case['status']} incident has a stored risk "
                f"score of {case['risk_score']}/100, severity {case['severity']}, "
                f"and {coverage['findings_total']} linked findings. "
                f"Detection confidence describes rule evidence strength, "
                f"not certainty of compromise."
            ),
            [case_ref],
        )
        seen_rules = set()
        for i, finding in enumerate(data["findings"]):
            rule = finding["rule_id"]
            name = RULE_NAMES.get(rule, "a configured detection rule")
            metrics = "; ".join(
                f"{METRIC_NAMES[k]}: {v:g}"
                for k, v in finding["metrics"].items()
                if k in METRIC_NAMES
            )
            text = (
                f"{rule if rule in RULE_NAMES else 'Rule'} flagged "
                f"{name}: {finding['event_count']} contributing events, "
                f"confidence {finding['confidence']:g}%, severity "
                f"{finding['severity']}."
            )
            if finding.get("account_alias"):
                text += f" Target alias: {finding['account_alias']}."
            shared = [
                key.replace("_", " ")
                for key, value in finding["correlation"].items()
                if key.startswith("same_") and value is True
            ]
            if shared:
                text += " Recorded correlation attributes: " + ", ".join(shared) + "."
            if metrics:
                text += f" Stored evidence — {metrics}."
            attributes = finding.get("attributes", {})
            if "previous_role" in attributes and "new_role" in attributes:
                text += (
                    f" Recorded role transition: {attributes['previous_role']}"
                    f" to {attributes['new_role']}; authorization requires review."
                )
            if "local_login_time" in attributes:
                text += f" Recorded local login time: {attributes['local_login_time']}."
            if "timezone" in attributes:
                text += f" Normal activity hours use timezone {attributes['timezone']}."
            if attributes.get("simultaneous_logins"):
                text += " The geographical login timestamps are simultaneous."
            if finding["synthetic_reputation"]:
                text += (
                    " This finding uses synthetic local reputation, not an "
                    "external maliciousness verdict."
                )
            key = f"finding_{i}"
            self.add(key, text, [(finding["finding_id"], "finding", f"Finding {i + 1}")])
            self.finding_facts.append(key)
            if rule not in seen_rules:
                self.representative_findings.append(key)
                seen_rules.add(rule)
        risk = data["risk"]
        if risk:
            for i, component in enumerate(risk["components"]):
                key = f"risk_{i}"
                self.add(
                    key,
                    (
                        f"Stored {component['component'].replace('_', ' ')} "
                        f"contribution: {component['points']}/{component['max']} "
                        f"points in the leading assessment ({risk['risk_score']}/100). "
                        f"The analyst does not recalculate this score."
                    ),
                    [(risk["assessment_id"], "risk", "Stored risk assessment")],
                )
                self.risk_facts.append(key)
        for i, event in enumerate(data["events"]):
            account = f" for {event['account_alias']}" if event["account_alias"] else ""
            self.add(
                f"event_{i}",
                f"{event['event_type']}{account} at {event['timestamp']} (UTC).",
                [(event["event_id"], "event", f"{event['event_type']} event")],
            )
        for kind, count in data["event_type_counts"].items():
            self.add(
                f"count_{kind}",
                (
                    f"The incident's linked evidence contains {count} "
                    f"{kind} event records. Counts describe linked evidence "
                    f"only."
                ),
                [case_ref],
            )
        for i, value in enumerate(data["threat_intelligence"]):
            key = f"indicator_{i}"
            mode = "synthetic mock" if value["simulation"] else "cached provider"
            text = f"Related indicator {i + 1}: {mode} reputation {value['reputation']}."
            if value["score"] is not None:
                text += (
                    f" Stored normalized reputation score: {value['score']}/100 "
                    f"(not incident risk)."
                )
            if value["stale"]:
                text += " Cache is expired or incompatible; it cannot establish current reputation."
            if value["simulation"]:
                text += " Simulation data is not real-world threat intelligence."
            self.add(key, text, [(value["indicator"], "indicator", f"Threat indicator {i + 1}")])
            self.intelligence_facts.append(key)
        if data["missing_indicators"]:
            self.add(
                "missing_intelligence",
                (
                    "Some related indicators have no compatible cached intelligence. "
                    "Missing reputation does not establish that an indicator "
                    "is benign or malicious."
                ),
                [case_ref],
            )
            self.intelligence_facts.append("missing_intelligence")
        for i, item in enumerate(data["timeline"]):
            self.add(
                f"timeline_{i}",
                f"Recorded workflow action {item['action']} at {item['timestamp']}.",
                [(item["id"], "audit", "Timeline action")],
            )
        rules = {f["rule_id"] for f in data["findings"]}
        if rules & {"CS-001", "CS-002", "CS-003", "CS-004"}:
            self.investigations["authentication"] = (
                "Check for successful logins after failures, review MFA "
                "records, and verify the activity with the account owner. "
                "A successful login alone does not prove compromise."
            )
            self.recommendations["identity"] = (
                "If unauthorized access is confirmed, consider credential "
                "rotation and session review under organizational policy; "
                "verify MFA enforcement."
            )
        if "CS-005" in rules:
            self.investigations["privilege"] = (
                "Review the previous and new roles, authorizing change "
                "record, and activity by the account that made the privilege "
                "change."
            )
            self.recommendations["access"] = (
                "If a privilege change was unauthorized, follow the approved "
                "access-review and restoration process."
            )
        if "CS-007" in rules or "CS-009" in rules:
            self.investigations["records"] = (
                "Review resource access counts, authorization, and the "
                "user's expected duties without copying sensitive record "
                "contents."
            )
            self.recommendations["records"] = (
                "If access exceeded authorization, consider a scoped "
                "access review and increased monitoring through the approved "
                "response process."
            )
        if rules & {"CS-006", "CS-008", "CS-010"}:
            self.investigations["network"] = (
                "Review related connection or API logs, destinations, "
                "request rates, and cached reputation provenance; confirm "
                "whether the activity was authorized."
            )
            self.recommendations["network"] = (
                "If the activity is confirmed unauthorized, consider "
                "scoped rate limits or containment through the approved "
                "change process."
            )

    def payload(self):
        # Raw logs, names, notes, and original evidence identifiers stay local.
        return {
            "incident_id": self.context.incident_id,
            "context_hash": self.context.context_hash,
            "risk_score": self.context.data["incident"]["risk_score"],
            "facts": {key: value.statement for key, value in self.facts.items()},
            "investigation_actions": self.investigations,
            "recommendation_actions": self.recommendations,
        }

    def default_plan(self):
        return EvidencePlan(
            incident_id=self.context.incident_id,
            context_hash=self.context.context_hash,
            risk_score=self.context.data["incident"]["risk_score"],
            summary_fact_ids=["case"] + self.representative_findings[:1],
            evidence_fact_ids=(
                self.representative_findings[:6]
                + self.intelligence_facts[:3]
                + [k for k in self.facts if k.startswith("count_")][:3]
            )
            or ["case"],
            investigation_action_ids=list(self.investigations),
            recommendation_action_ids=list(self.recommendations),
        )

    def render(self, plan):
        data = self.context.data
        coverage = data["coverage"]
        uncertainty = (
            f"This report uses {coverage['findings_included']}/{coverage['findings_total']} "
            f"findings and {coverage['events_included']}/{coverage['events_total']} "
            f"representative event records. "
            "Suspicious behaviour does not establish compromise, "
            "intent, or attribution. Account labels are local aliases. "
            "Raw text and analyst-note contents are excluded; review "
            "originals for context."
        )
        if not data["risk"]:
            uncertainty += (
                " No current leading risk assessment is available to "
                "explain the stored incident score."
            )
        elif data["risk"]["risk_score"] != data["incident"]["risk_score"]:
            uncertainty += (
                " The leading finding assessment differs from the stored incident score. "
                "Review the deterministic scoring and incident reconciliation state; "
                "this report preserves both values."
            )
        if any(v["simulation"] for v in data["threat_intelligence"]):
            uncertainty += " Reputation includes explicitly synthetic data."
        used = list(
            dict.fromkeys(
                ["case"]
                + plan.summary_fact_ids
                + plan.evidence_fact_ids
                + self.representative_findings[:5]
                + self.risk_facts
            )
        )
        refs = {r for key in used for r in self.facts[key].reference_ids}
        return AnalysisContent(
            summary=" ".join(self.facts[k].statement for k in plan.summary_fact_ids),
            why_flagged=" ".join(self.facts[k].statement for k in self.representative_findings[:5])
            or "No linked detection finding is available; detection reasons cannot be established.",
            risk_explanation=[self.facts[k] for k in self.risk_facts],
            key_evidence=[self.facts[k] for k in plan.evidence_fact_ids],
            potential_impact=(
                "If the observed activity was unauthorized, it could "
                "affect the confidentiality or integrity of the involved "
                "accounts, services, or records. The supplied evidence "
                "does not by itself confirm that outcome."
            ),
            investigation_steps=[self.investigations[k] for k in plan.investigation_action_ids],
            recommended_actions=[self.recommendations[k] for k in plan.recommendation_action_ids],
            uncertainty=uncertainty,
            references=[r for key, r in self.references.items() if key in refs],
            coverage=coverage,
        )
