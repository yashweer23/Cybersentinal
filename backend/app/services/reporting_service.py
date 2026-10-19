"""Bounded, authenticated exports. Projections only; never store public report files."""

import csv
import io
from datetime import datetime
from decimal import Decimal
from enum import Enum

from sqlalchemy import and_, case, func, select

from app.models import DetectionFinding as F
from app.models import DetectionRule as R
from app.models import Incident as I
from app.models import RiskAssessment as Risk
from app.models import ThreatIntelligence as Indicator
from app.models import ThreatIntelligenceResult as Intel
from app.repositories.analytics_repository import cohort, current_risk_join
from app.repositories.dashboard_repository import window
from app.schemas.analytics import AnalyticsQuery, RiskQuery
from app.schemas.reports import ReportResponse
from app.services.analytics_service import resolve_scope
from app.services.security_analytics import SecurityAnalyticsService
from app.threat_intelligence.service import ThreatIntelligenceService

COLUMNS = {
    "incidents": [
        "incident_id",
        "title",
        "created_at",
        "detected_at",
        "status",
        "severity",
        "risk_score",
        "source_ip",
        "username",
        "resolved_at",
    ],
    "detection-findings": [
        "finding_id",
        "rule_id",
        "title",
        "first_seen",
        "last_seen",
        "severity",
        "confidence",
        "source_ip",
        "username",
        "event_count",
    ],
    "risk-assessments": [
        "assessment_id",
        "finding_id",
        "rule_id",
        "risk_score",
        "risk_level",
        "score_version",
        "calculated_at",
    ],
    "threat-indicators": [
        "indicator",
        "indicator_type",
        "mode",
        "reputation_level",
        "normalized_score",
        "cache_status",
        "checked_at",
        "expires_at",
    ],
    "analyst-workload": [
        "analyst_id",
        "username",
        "assigned",
        "open",
        "investigating",
        "resolved",
        "average_resolution_seconds",
    ],
    "detection-rules": [
        "rule_id",
        "name",
        "enabled",
        "findings",
        "incidents",
        "average_risk",
        "critical_incidents",
        "false_positives",
        "closed_incidents",
        "false_positive_rate",
        "latest_detection",
    ],
    "security-summary": ["section", "metric", "value"],
}


def csv_cell(value):
    if value is None:
        return ""
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, datetime):
        value = value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, str):
        # QUOTE_ALL handles delimiters/newlines; apostrophe also neutralizes spreadsheet formulas.
        trimmed = value.lstrip(" \t\r\n\x00\ufeff\u200b\u00a0")
        if (trimmed and trimmed[0] in "=+-@") or (value and value[0] in "\t\r\n\x00"):
            return "'" + value
    return value


def csv_document(report):
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(report.columns)
    for row in report.rows:
        writer.writerow([csv_cell(row.get(k)) for k in report.columns])
    return "\ufeff" + buffer.getvalue()


def export_statement(kind, s, policy_hashes=None):
    if kind == "incidents":
        return (
            select(
                I.incident_id,
                I.title,
                I.created_at,
                I.detected_at,
                I.status,
                I.severity,
                I.risk_score,
                func.host(I.source_ip).label("source_ip"),
                I.username,
                I.resolved_at,
            )
            .where(*cohort(s))
            .order_by(I.created_at.desc(), I.id)
        )
    if kind == "detection-findings":
        return (
            select(
                F.finding_id,
                R.rule_id,
                F.title,
                F.first_seen,
                F.last_seen,
                F.severity,
                F.confidence,
                func.host(F.source_ip).label("source_ip"),
                F.username,
                F.event_count,
            )
            .join(R, F.detection_rule_id == R.id)
            .where(*window(F.last_seen, s))
            .order_by(F.last_seen.desc(), F.id)
        )
    if kind == "risk-assessments":
        return (
            select(
                Risk.assessment_id,
                F.finding_id,
                R.rule_id,
                Risk.risk_score,
                Risk.risk_level,
                Risk.score_version,
                Risk.calculated_at,
            )
            .select_from(F)
            .join(Risk, current_risk_join())
            .join(R, F.detection_rule_id == R.id)
            .where(*window(F.last_seen, s))
            .order_by(F.last_seen.desc(), F.id)
        )
    if kind == "threat-indicators":
        # Reports use the same current-policy/expiry semantics as the analytics UI.
        expected_policy = case(policy_hashes or {}, value=Intel.mode, else_="")
        fresh = and_(Intel.expires_at > s.as_of, Intel.policy_hash == expected_policy)
        return (
            select(
                Indicator.indicator,
                Indicator.indicator_type,
                Intel.mode,
                case((fresh, Intel.reputation_level), else_="UNKNOWN").label("reputation_level"),
                case((fresh, Intel.normalized_score)).label("normalized_score"),
                case(
                    (Intel.policy_hash != expected_policy, "incompatible"),
                    (Intel.expires_at <= s.as_of, "expired"),
                    else_="fresh",
                ).label("cache_status"),
                Intel.checked_at,
                Intel.expires_at,
            )
            .select_from(Intel)
            .join(Indicator, Indicator.id == Intel.indicator_id)
            .where(*window(Intel.checked_at, s))
            .order_by(Intel.checked_at.desc(), Intel.id)
        )
    raise ValueError("Unsupported projection")


class ReportingService:
    def __init__(self, session, settings):
        self.session, self.settings = session, settings

    def generate(self, kind, query):
        s = resolve_scope(query, self.settings)
        service = SecurityAnalyticsService(self.session, self.settings, scope=s)
        q = AnalyticsQuery(start=s.start, end=s.end)
        sections = {}
        with self.session.no_autoflush:
            if kind == "security-summary":
                for key, operation, options in [
                    ("overview", "overview", q),
                    ("incident_trend", "incidents", q),
                    ("event_trend", "events", None),
                    ("rules", "rules", q),
                    ("risk_histogram", "histogram", RiskQuery(start=s.start, end=s.end)),
                    ("intelligence", "intelligence", q),
                    ("backlog", "backlog", q),
                ]:
                    if options is None:
                        from app.schemas.analytics import EventTrendQuery

                        options = EventTrendQuery(start=s.start, end=s.end)
                    sections[key] = service.execute(operation, options).model_dump(mode="json")
                critical = (
                    export_statement("incidents", s).where(I.severity == "CRITICAL").limit(21)
                )
                preview = service.repository.rows(critical)
                sections["critical_incidents"] = {
                    "items": preview[:20],
                    "limit": 20,
                    "has_more": len(preview) > 20,
                }
                rows = []
                for section, body in sections.items():
                    for key, value in body.items():
                        if key not in {"scope", "definition"} and not isinstance(
                            value, (dict, list)
                        ):
                            rows.append({"section": section, "metric": key, "value": value})
                    for array in ("items", "data", "modes"):
                        for index, item in enumerate(body.get(array, [])):
                            identity = (
                                item.get("rule_id")
                                or item.get("incident_id")
                                or item.get("timestamp")
                                or item.get("label")
                                or item.get("mode")
                                or index
                            )
                            for key, value in item.items():
                                if not isinstance(value, (list, dict)):
                                    rows.append(
                                        {
                                            "section": section,
                                            "metric": f"{identity}.{key}",
                                            "value": value,
                                        }
                                    )
                selected = rows[query.offset : query.offset + query.limit + 1]
            elif kind == "analyst-workload":
                selected = service.repository.workload(s, 86400, query.limit, query.offset)["items"]
            elif kind == "detection-rules":
                values = service.execute("rules", q)
                selected = [r.model_dump(mode="json") for r in values.items][
                    query.offset : query.offset + query.limit + 1
                ]
            else:
                policies = None
                if kind == "threat-indicators":
                    policies = {
                        mode: ThreatIntelligenceService(
                            self.session, self.settings, mock=mode == "mock"
                        ).policy_hash()
                        for mode in ("mock", "live")
                    }
                selected = service.repository.rows(
                    export_statement(kind, s, policies).offset(query.offset).limit(query.limit + 1)
                )
        more = len(selected) > query.limit
        return ReportResponse(
            report_type=kind,
            generated_at=s.as_of,
            scope=s,
            definition="Bounded read-only projections, current states/scores and a shared "
            "UTC scope. Each SQL statement observes committed data; concurrent "
            "updates can occur between sections. No historical score "
            "reconstruction. CSV summary uses section/metric/value rows; JSON "
            "also includes bounded structured sections.",
            returned_rows=min(len(selected), query.limit),
            limit=query.limit,
            offset=query.offset,
            has_more=more,
            next_offset=query.offset + query.limit if more else None,
            columns=COLUMNS[kind],
            rows=selected[: query.limit],
            sections=sections,
        )
