"""A fixed read-only query catalog. User text is never interpolated into SQL."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import distinct, func, select

from app.ai.schemas import OverviewResponse
from app.core.enums import IncidentStatus, SeverityLevel
from app.core.errors import ServiceError
from app.models import DetectionFinding, DetectionRule, Incident, IncidentFinding, SecurityEvent


def overview(session, question):
    q = question.lower()
    active = Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING])
    now = datetime.now(UTC)
    if any(word in q for word in ("delete", "execute", "sql", "shell", "ignore", "secret")):
        raise ServiceError(422, "Choose a supported read-only overview question")
    if "critical" in q:
        name, clauses = "critical_incidents", [active, Incident.severity == SeverityLevel.CRITICAL]
    elif "highest" in q or "open incidents" in q:
        name, clauses = "highest_risk_incidents", [active]
    else:
        name, clauses = None, None
    if name:
        total = session.scalar(select(func.count()).select_from(Incident).where(*clauses))
        rows = session.execute(
            select(Incident.incident_id, Incident.risk_score, Incident.status)
            .where(*clauses)
            .order_by(Incident.risk_score.desc(), Incident.detected_at.desc(), Incident.id)
            .limit(20)
        )
        evidence = [
            {"incident_id": r.incident_id, "risk_score": r.risk_score, "status": r.status.value}
            for r in rows
        ]
        scope, answer = (
            "Current OPEN and INVESTIGATING incidents",
            f"{total} incidents match. Showing up to 20 ordered by stored risk score.",
        )
    elif "rule" in q:
        name = "top_detection_rules"
        query = (
            select(
                DetectionRule.rule_id,
                func.count(distinct(IncidentFinding.incident_id)).label("incidents"),
            )
            .join(DetectionFinding, DetectionFinding.detection_rule_id == DetectionRule.id)
            .join(IncidentFinding, IncidentFinding.detection_finding_id == DetectionFinding.id)
            .group_by(DetectionRule.rule_id)
        )
        total = session.scalar(select(func.count()).select_from(query.subquery()))
        evidence = [
            dict(r)
            for r in session.execute(
                query.order_by(
                    func.count(distinct(IncidentFinding.incident_id)).desc(), DetectionRule.rule_id
                ).limit(20)
            ).mappings()
        ]
        scope, answer = (
            "All retained incidents; distinct incident count per linked rule",
            (
                f"{total} rules contributed findings to incidents. "
                f"A multi-rule incident may count once under each "
                f"rule."
            ),
        )
    elif "account" in q:
        name = "suspicious_accounts"
        query = (
            select(DetectionFinding.username, func.count().label("findings"))
            .where(DetectionFinding.username.is_not(None))
            .group_by(DetectionFinding.username)
            .having(func.count() >= 2)
        )
        total = session.scalar(select(func.count()).select_from(query.subquery()))
        evidence = [
            dict(r)
            for r in session.execute(
                query.order_by(func.count().desc(), DetectionFinding.username).limit(20)
            ).mappings()
        ]
        scope, answer = (
            "All retained findings; at least two findings per account",
            f"{total} accounts have multiple findings. Finding count is not proof of compromise.",
        )
    elif "summary" in q or "summarize" in q or "activity" in q:
        name = "security_activity_summary"
        since = now - timedelta(hours=24)
        total = session.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.timestamp >= since, SecurityEvent.timestamp <= now)
        )
        findings = session.scalar(
            select(func.count())
            .select_from(DetectionFinding)
            .where(DetectionFinding.last_seen >= since, DetectionFinding.last_seen <= now)
        )
        evidence = [{"events": total, "findings": findings}]
        scope, answer = (
            "Last 24 hours, UTC event timestamps",
            f"{total} security events and {findings} findings fall within the last 24 hours.",
        )
    else:
        raise ServiceError(
            422,
            (
                "Supported questions: critical incidents, highest-risk "
                "open incidents, top detection rules, suspicious accounts, "
                "or activity summary"
            ),
        )
    return OverviewResponse(
        query=name,
        scope=scope,
        answer=answer,
        evidence=evidence,
        total=total,
        truncated=total > len(evidence) if name != "security_activity_summary" else False,
        generated_at=now,
    )
