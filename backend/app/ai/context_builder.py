"""Read only case-linked records. SQL digests cover even evidence outside bounded samples."""

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from time import perf_counter
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import String, cast, func, select
from sqlalchemy.dialects.postgresql import aggregate_order_by

from app.core.errors import ServiceError
from app.models import (
    AuditLog,
    DetectionFinding,
    Incident,
    IncidentComment,
    IncidentFinding,
    RiskAssessment,
    SecurityEvent,
    ThreatIntelligence,
    ThreatIntelligenceResult,
)
from app.repositories.incident_repository import event_condition, leading_assessment
from app.services.incident_enrichment import indicator_query, read_related
from app.threat_intelligence.schemas import RelatedQuery
from app.threat_intelligence.service import ThreatIntelligenceService

CONTEXT_VERSION = "1"
NUMERIC_EVIDENCE = {
    "attempt_count",
    "threshold",
    "window_seconds",
    "duration_seconds",
    "access_count",
    "log_event_count",
    "unique_username_count",
    "qualifying_username_count",
    "max_attempts_per_user",
    "distance_km",
    "elapsed_hours",
    "required_speed_kmh",
    "speed_threshold_kmh",
    "normal_start_hour",
    "normal_end_hour",
    "baseline_event_count",
    "unique_port_count",
    "reputation_score",
    "denial_count",
    "request_count",
    "baseline_mean",
    "baseline_multiplier",
}
EVENT_TYPES = {
    "LOGIN_SUCCESS",
    "LOGIN_FAILED",
    "ADMIN_LOGIN",
    "ACCESS_DENIED",
    "FILE_ACCESS",
    "PRIVILEGE_CHANGE",
    "SENSITIVE_RECORD_ACCESS",
    "API_REQUEST",
    "PORT_CONNECTION",
    "MALWARE_ALERT",
    "PASSWORD_CHANGE",
    "MFA_SUCCESS",
    "MFA_FAILED",
    "LOGOUT",
    "ACCOUNT_LOCKED",
}


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), default=str, allow_nan=False
        ).encode()
    ).hexdigest()


def numeric_metrics(value):
    if not isinstance(value, dict):
        return {}
    # Phase 6 stores the evaluated configuration, not only today's editable rule row.
    configuration = value.get("configuration")
    snapshot = configuration if isinstance(configuration, dict) else {}
    value = {**{k: v for k, v in snapshot.items() if k == "window_seconds"}, **value}
    return {
        k: v
        for k, v in value.items()
        if k in NUMERIC_EVIDENCE and type(v) in (int, float) and math.isfinite(v) and abs(v) <= 1e12
    }


def safe_attributes(value):
    """Constrained nonnumeric rule evidence; arbitrary text stays out of prompts."""
    result = {}
    roles = {"EMPLOYEE", "USER", "ADMIN", "ADMINISTRATOR", "ANALYST", "VIEWER"}
    for key in ("previous_role", "new_role"):
        if isinstance(value.get(key), str) and value[key].upper() in roles:
            result[key] = value[key].upper()
    zone = value.get("timezone")
    if isinstance(zone, str) and len(zone) < 64:
        try:
            ZoneInfo(zone)
            result["timezone"] = zone
        except (ValueError, ZoneInfoNotFoundError):
            pass
    try:
        stamp = datetime.fromisoformat(value.get("local_login_time", ""))
        if stamp.tzinfo:
            result["local_login_time"] = stamp.isoformat()
    except (ValueError, TypeError):
        pass
    if value.get("simultaneous_logins") is True:
        result["simultaneous_logins"] = True
    return result


@dataclass
class IncidentContext:
    incident_pk: object
    incident_id: str
    context_hash: str
    data: dict
    build_ms: float


class AIContextBuilder:
    def __init__(self, session, settings):
        self.session, self.settings = session, settings

    def _digest_query(self, query, columns, order):
        # Return a fixed-size digest, never all raw rows or JSON payloads to Python/provider.
        def sha(value):
            return func.encode(func.sha256(func.convert_to(value, "UTF8")), "hex")

        row_hash = sha(cast(func.jsonb_build_array(*columns), String)).label("h")
        rows = (
            query.with_only_columns(row_hash, order.label("ordering"), maintain_column_froms=True)
            .order_by(None)
            .subquery()
        )
        return self.session.scalar(
            select(
                sha(
                    func.coalesce(
                        func.string_agg(rows.c.h, aggregate_order_by("", rows.c.ordering)), ""
                    )
                )
            )
        )

    def revision(self, incident):
        linked = select(IncidentFinding.detection_finding_id).where(
            IncidentFinding.incident_id == incident.id
        )
        queries = [
            (
                select(Incident).where(Incident.id == incident.id),
                [
                    Incident.id,
                    Incident.updated_at,
                    Incident.risk_score,
                    Incident.status,
                    Incident.severity,
                    Incident.assigned_analyst_id,
                ],
                Incident.id,
            ),
            (
                select(IncidentFinding).where(IncidentFinding.incident_id == incident.id),
                [
                    IncidentFinding.detection_finding_id,
                    IncidentFinding.correlation_data,
                    IncidentFinding.relationship_reason,
                ],
                IncidentFinding.id,
            ),
            (
                select(DetectionFinding).where(DetectionFinding.id.in_(linked)),
                [
                    DetectionFinding.finding_id,
                    DetectionFinding.evidence_data,
                    DetectionFinding.evidence_event_ids,
                    DetectionFinding.confidence,
                    DetectionFinding.severity,
                    DetectionFinding.event_count,
                ],
                DetectionFinding.id,
            ),
            (
                select(RiskAssessment).where(RiskAssessment.detection_finding_id.in_(linked)),
                [
                    RiskAssessment.assessment_id,
                    RiskAssessment.breakdown,
                    RiskAssessment.input_hash,
                    RiskAssessment.calculated_at,
                ],
                RiskAssessment.id,
            ),
            (
                select(SecurityEvent).where(event_condition(incident)),
                [
                    column
                    for column in SecurityEvent.__table__.columns
                    if column.name != "processed"
                ],
                SecurityEvent.id,
            ),
            (
                select(IncidentComment).where(IncidentComment.incident_id == incident.id),
                [IncidentComment.id, IncidentComment.comment, IncidentComment.updated_at],
                IncidentComment.id,
            ),
            (
                select(AuditLog).where(
                    AuditLog.entity_type == "incident", AuditLog.entity_id == str(incident.id)
                ),
                [AuditLog.id, AuditLog.action, AuditLog.old_value, AuditLog.new_value],
                AuditLog.id,
            ),
        ]
        ips = indicator_query(self.session, incident.incident_id, "incident").subquery()
        bundles = (
            select(ThreatIntelligenceResult)
            .join(ThreatIntelligence)
            .where(ThreatIntelligence.indicator.in_(select(func.host(ips.c.ip))))
        )
        queries.append(
            (
                bundles,
                [
                    ThreatIntelligenceResult.id,
                    ThreatIntelligenceResult.payload,
                    ThreatIntelligenceResult.policy_hash,
                    ThreatIntelligenceResult.checked_at,
                    ThreatIntelligenceResult.reputation_level,
                    ThreatIntelligenceResult.normalized_score,
                    ThreatIntelligenceResult.expires_at,
                    ThreatIntelligenceResult.expires_at <= datetime.now(UTC),
                ],
                ThreatIntelligenceResult.id,
            )
        )
        return [self._digest_query(*q) for q in queries]

    def build(self, identifier):
        started = perf_counter()
        for _ in range(2):
            incident = self.session.scalar(
                select(Incident)
                .where(Incident.incident_id == identifier)
                .execution_options(populate_existing=True)
            )
            if incident is None:
                raise ServiceError(404, "Incident not found")
            before = self.revision(incident)
            data = self._project(incident)
            after = self.revision(incident)
            if before == after:
                return IncidentContext(
                    incident.id,
                    identifier,
                    digest({"revision": after, "context": data, "version": CONTEXT_VERSION}),
                    data,
                    round((perf_counter() - started) * 1000, 3),
                )
        raise ServiceError(409, "Incident evidence changed while building context; try again")

    def _project(self, incident):
        finding_total = self.session.scalar(
            select(func.count())
            .select_from(IncidentFinding)
            .where(IncidentFinding.incident_id == incident.id)
        )
        findings = self.session.execute(
            select(DetectionFinding, IncidentFinding.correlation_data)
            .join(IncidentFinding)
            .outerjoin(
                RiskAssessment,
                (RiskAssessment.detection_finding_id == DetectionFinding.id)
                & (RiskAssessment.score_version == incident.risk_score_version),
            )
            .where(IncidentFinding.incident_id == incident.id)
            .order_by(
                RiskAssessment.risk_score.desc().nulls_last(),
                DetectionFinding.first_seen,
                DetectionFinding.id,
            )
            .limit(self.settings.ai_max_context_findings)
        ).all()
        counts = dict(
            self.session.execute(
                select(SecurityEvent.event_type, func.count())
                .where(event_condition(incident))
                .group_by(SecurityEvent.event_type)
            ).all()
        )
        event_total = sum(counts.values())
        limit = self.settings.ai_max_context_events
        query = select(SecurityEvent).where(event_condition(incident))
        # Include boundaries plus representatives of each event type. Every read stays bounded.
        selected = {}
        for row in self.session.scalars(
            query.order_by(SecurityEvent.timestamp, SecurityEvent.id).limit(limit // 2)
        ):
            selected[row.id] = row
        for row in self.session.scalars(
            query.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()).limit(
                limit - len(selected)
            )
        ):
            selected[row.id] = row
        representatives = self.session.scalars(
            query.distinct(SecurityEvent.event_type)
            .order_by(SecurityEvent.event_type, SecurityEvent.timestamp, SecurityEvent.id)
            .limit(min(limit, 20))
        ).all()
        for row in representatives:
            if row.id not in selected:
                if len(selected) >= limit:
                    # Prefer type diversity over a duplicate middle-of-window type.
                    removable = next(
                        (
                            key
                            for key, e in reversed(list(selected.items()))
                            if sum(v.event_type == e.event_type for v in selected.values()) > 1
                        ),
                        None,
                    )
                    if removable is None:
                        continue
                    selected.pop(removable)
                selected[row.id] = row
        events = sorted(selected.values(), key=lambda e: (e.timestamp, str(e.id)))
        account_aliases = {
            name: f"account_{i + 1}"
            for i, name in enumerate(
                sorted(
                    {e.username for e in events if e.username}
                    | {f.username for f, _ in findings if f.username}
                )
            )
        }
        risk = leading_assessment(self.session, incident)
        breakdown = []
        if risk:
            for name in (
                "severity",
                "confidence",
                "behavioural_intensity",
                "event_frequency",
                "asset_sensitivity",
                "reputation",
            ):
                component = risk.breakdown.get(name, {})
                if type(component.get("points")) is int and type(component.get("max")) is int:
                    breakdown.append(
                        {"component": name, "points": component["points"], "max": component["max"]}
                    )
        intelligence = read_related(
            ThreatIntelligenceService(self.session, self.settings),
            incident.incident_id,
            "incident",
            RelatedQuery(limit=20),
        )
        notes = self.session.execute(
            select(func.count(), func.max(IncidentComment.updated_at)).where(
                IncidentComment.incident_id == incident.id
            )
        ).one()
        timeline = self.session.execute(
            select(AuditLog.id, AuditLog.action, AuditLog.timestamp)
            .where(
                AuditLog.entity_type == "incident",
                AuditLog.entity_id == str(incident.id),
                AuditLog.action.in_(
                    [
                        "INCIDENT_CREATED",
                        "INCIDENT_ASSIGNED",
                        "INCIDENT_STATUS_CHANGED",
                        "INCIDENT_RESOLVED",
                        "INCIDENT_FALSE_POSITIVE",
                        "INCIDENT_REOPENED",
                    ]
                ),
            )
            .order_by(AuditLog.timestamp.desc(), AuditLog.id)
            .limit(10)
        ).all()
        return {
            "incident": {
                "incident_id": incident.incident_id,
                "risk_score": incident.risk_score,
                "severity": incident.severity.value,
                "status": incident.status.value,
                "confidence": float(incident.confidence),
                "first_seen": incident.first_seen.isoformat(),
                "last_seen": incident.last_seen.isoformat(),
            },
            "risk": {
                "assessment_id": risk.assessment_id,
                "finding_id": risk.finding_id,
                "risk_score": risk.risk_score,
                "version": risk.score_version,
                "components": breakdown,
            }
            if risk
            else None,
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "account_alias": account_aliases.get(f.username),
                    "rule_id": f.rule.rule_id,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "event_count": f.event_count,
                    "first_seen": f.first_seen.isoformat(),
                    "last_seen": f.last_seen.isoformat(),
                    "metrics": numeric_metrics(f.evidence_data),
                    "attributes": safe_attributes(f.evidence_data),
                    "synthetic_reputation": f.evidence_data.get("synthetic") is True,
                    "correlation": {
                        k: v
                        for k, v in correlation.items()
                        if k
                        in {"same_source_ip", "same_username", "same_device", "matched_attributes"}
                        and (type(v) is bool or type(v) is int)
                    },
                }
                for f, correlation in findings
            ],
            "events": [
                {
                    "event_id": e.event_id,
                    "timestamp": e.timestamp.isoformat(),
                    "event_type": e.event_type if e.event_type in EVENT_TYPES else "OTHER",
                    "status": e.status
                    if e.status
                    in {"failed", "success", "successful", "allowed", "denied", "blocked"}
                    else "other",
                    "account_alias": account_aliases.get(e.username),
                }
                for e in events
            ],
            "event_type_counts": {key: counts[key] for key in sorted(counts) if key in EVENT_TYPES},
            "threat_intelligence": [
                {
                    "indicator": t.indicator,
                    "reputation": "UNKNOWN"
                    if t.stale or t.configuration_changed
                    else t.reputation_level,
                    "score": None if t.stale or t.configuration_changed else t.normalized_score,
                    "simulation": t.simulation,
                    "stale": t.stale or t.configuration_changed,
                    "checked_at": t.checked_at.isoformat(),
                    "expires_at": t.expires_at.isoformat(),
                }
                for t in intelligence.indicators
            ],
            "missing_indicators": intelligence.missing_indicators,
            "timeline": [
                {"id": str(a.id), "action": a.action, "timestamp": a.timestamp.isoformat()}
                for a in timeline
            ],
            "notes": {
                "count": notes[0],
                "last_changed": str(notes[1]) if notes[1] else None,
                "contents_included": False,
            },
            "coverage": {
                "findings_total": finding_total,
                "findings_included": len(findings),
                "events_total": event_total,
                "events_included": len(events),
                "indicators_total": intelligence.total_indicators,
                "indicators_included": len(intelligence.indicators)
                + len(intelligence.missing_indicators),
            },
        }
