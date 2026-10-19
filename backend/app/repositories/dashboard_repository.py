"""Read-only column projections and PostgreSQL aggregates. No event payload loading."""

from datetime import timedelta

from sqlalchemy import and_, case, func, literal, select, true, union

from app.core.enums import IncidentStatus, IndicatorType, SeverityLevel
from app.models import (
    DetectionFinding as Finding,
)
from app.models import (
    DetectionRule as Rule,
)
from app.models import (
    Incident,
    IncidentFinding,
    SystemMetric,
    User,
)
from app.models import (
    RiskAssessment as Risk,
)
from app.models import (
    SecurityEvent as Event,
)
from app.models import (
    ThreatIntelligence as Indicator,
)
from app.models import (
    ThreatIntelligenceResult as Intel,
)
from app.risk.config import SCORE_VERSION
from app.services.analytics_service import EPOCH

ACTIVE = (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)
ACTIVITY_TYPES = {
    "successful_logins": "LOGIN_SUCCESS",
    "failed_logins": "LOGIN_FAILED",
    "access_denials": "ACCESS_DENIED",
    "api_requests": "API_REQUEST",
    "sensitive_record_accesses": "SENSITIVE_RECORD_ACCESS",
    "privilege_changes": "PRIVILEGE_CHANGE",
}


def window(column, scope):
    return column >= scope.start, column < scope.end


def event_columns():
    return (
        Event.id,
        Event.ingestion_sequence,
        Event.event_id,
        Event.timestamp,
        Event.event_type,
        func.host(Event.source_ip).label("source_ip"),
        func.host(Event.destination_ip).label("destination_ip"),
        Event.username,
        Event.service,
        Event.status,
        Event.processed,
    )


def incident_pairs(scope, attribute):
    """Deduplicated (entity, incident) pairs including primary and linked identities."""
    i_value, f_value = getattr(Incident, attribute), getattr(Finding, attribute)
    if attribute == "source_ip":
        i_value, f_value = func.host(i_value), func.host(f_value)
    direct = select(i_value.label("entity"), Incident.id.label("incident_id")).where(
        *window(Incident.detected_at, scope), i_value.is_not(None), i_value != ""
    )
    linked = (
        select(f_value.label("entity"), Incident.id.label("incident_id"))
        .select_from(Incident)
        .join(IncidentFinding, IncidentFinding.incident_id == Incident.id)
        .join(Finding, Finding.id == IncidentFinding.detection_finding_id)
        .where(*window(Incident.detected_at, scope), f_value.is_not(None), f_value != "")
    )
    return union(direct, linked).cte(f"incident_{attribute}_pairs")


def finding_entities(scope, attribute):
    value = getattr(Finding, attribute)
    if attribute == "source_ip":
        value = func.host(value)
    return select(value.label("entity")).where(
        *window(Finding.last_seen, scope), value.is_not(None), value != ""
    )


def suspicious_entities(scope):
    pairs = incident_pairs(scope, "source_ip")
    return union(finding_entities(scope, "source_ip"), select(pairs.c.entity)).subquery()


def event_metrics(scope=None):
    values = [
        func.count().label("total_events"),
        func.count().filter(Event.processed.is_(False)).label("unprocessed_events"),
        func.max(Event.timestamp).label("latest_event_timestamp"),
    ]
    if scope:
        values.append(func.count().filter(*window(Event.timestamp, scope)).label("events_in_range"))
    return select(*values).select_from(Event)


def incident_metrics(scope):
    return select(
        func.count().label("total_incidents"),
        func.count().filter(Incident.status.in_(ACTIVE)).label("active_incidents"),
        func.count()
        .filter(Incident.severity == SeverityLevel.CRITICAL)
        .label("critical_incidents"),
        func.count().filter(Incident.risk_score >= 50).label("high_risk_incidents"),
        func.avg(Incident.risk_score).label("average_risk_score"),
    ).where(*window(Incident.detected_at, scope))


def overview_statement(scope):
    events = event_metrics(scope).cte("event_metrics")
    incidents = incident_metrics(scope).cte("incident_metrics")
    findings = (
        select(func.count().label("total_findings"))
        .select_from(Finding)
        .where(*window(Finding.last_seen, scope))
        .cte("finding_metrics")
    )
    return (
        select(
            *events.c,
            *incidents.c,
            *findings.c,
            select(func.count())
            .select_from(suspicious_entities(scope))
            .scalar_subquery()
            .label("suspicious_ips"),
        )
        .select_from(events)
        .join(incidents, true())
        .join(findings, true())
    )


def timeline_statement(scope, seconds):
    bucket = func.date_bin(timedelta(seconds=seconds), Event.timestamp, EPOCH)
    return (
        select(
            bucket.label("timestamp"),
            func.count().label("total"),
            func.count().filter(Event.event_type == "LOGIN_FAILED").label("login_failed"),
            func.count().filter(Event.event_type == "ACCESS_DENIED").label("access_denied"),
            func.count().filter(Event.event_type == "API_REQUEST").label("api_requests"),
        )
        .where(*window(Event.timestamp, scope))
        .group_by(bucket)
        .order_by(bucket)
    )


def incident_distribution_statement(scope, field):
    return (
        select(field, func.count().label("count"))
        .where(*window(Incident.detected_at, scope))
        .group_by(field)
    )


def risk_distribution_statement(scope):
    # The existing Phase 7 category boundaries, applied to the stored current case score.
    level = case(
        (Incident.risk_score < 25, "LOW"),
        (Incident.risk_score < 50, "MEDIUM"),
        (Incident.risk_score < 75, "HIGH"),
        else_="CRITICAL",
    )
    return (
        select(
            level.label("level"),
            func.count().label("count"),
            func.sum(Incident.risk_score).label("score_sum"),
        )
        .where(*window(Incident.detected_at, scope))
        .group_by(level)
    )


def top_ips_statement(scope, mode, policy_hash, limit):
    pairs = incident_pairs(scope, "source_ip")
    cases = (
        select(
            pairs.c.entity,
            func.count().label("incident_count"),
            func.max(Incident.risk_score).label("highest_risk_score"),
            func.max(Incident.last_seen).label("latest_incident_activity"),
        )
        .join(Incident, Incident.id == pairs.c.incident_id)
        .group_by(pairs.c.entity)
        .cte("ip_cases")
    )
    findings = (
        select(
            func.host(Finding.source_ip).label("entity"),
            func.count().label("finding_count"),
            func.max(Risk.risk_score).label("highest_finding_risk_score"),
            func.max(Finding.last_seen).label("latest_finding_activity"),
        )
        .select_from(Finding)
        .outerjoin(
            Risk, and_(Risk.detection_finding_id == Finding.id, Risk.score_version == SCORE_VERSION)
        )
        .where(*window(Finding.last_seen, scope), Finding.source_ip.is_not(None))
        .group_by(Finding.source_ip)
        .cte("ip_findings")
    )
    keys = union(select(cases.c.entity), select(findings.c.entity)).cte("ip_keys")
    status = case(
        (Intel.id.is_(None), "missing"),
        (Intel.policy_hash != policy_hash, "incompatible"),
        (Intel.expires_at <= scope.as_of, "expired"),
        else_="fresh",
    )
    fresh = and_(Intel.expires_at > scope.as_of, Intel.policy_hash == policy_hash)
    latest = func.greatest(cases.c.latest_incident_activity, findings.c.latest_finding_activity)
    incident_count = func.coalesce(cases.c.incident_count, 0)
    finding_count = func.coalesce(findings.c.finding_count, 0)
    return (
        select(
            keys.c.entity.label("ip"),
            incident_count.label("incident_count"),
            finding_count.label("finding_count"),
            cases.c.highest_risk_score,
            findings.c.highest_finding_risk_score,
            latest.label("latest_activity"),
            case((fresh, Intel.reputation_level), else_="UNKNOWN").label("reputation_level"),
            Intel.reputation_level.label("cached_reputation_level"),
            status.label("intelligence_status"),
            literal(mode).label("mode"),
            literal(mode == "mock").label("simulation"),
        )
        .select_from(keys)
        .outerjoin(cases, cases.c.entity == keys.c.entity)
        .outerjoin(findings, findings.c.entity == keys.c.entity)
        .outerjoin(
            Indicator,
            and_(
                Indicator.indicator == keys.c.entity, Indicator.indicator_type == IndicatorType.IP
            ),
        )
        .outerjoin(Intel, and_(Intel.indicator_id == Indicator.id, Intel.mode == mode))
        .order_by(
            cases.c.highest_risk_score.desc().nulls_last(),
            incident_count.desc(),
            finding_count.desc(),
            latest.desc(),
            keys.c.entity,
        )
        .limit(limit)
    )


def targeted_users_statement(scope, limit):
    events = (
        select(
            Event.username.label("entity"),
            func.count().filter(Event.event_type == "LOGIN_FAILED").label("failed_logins"),
            func.count().filter(Event.event_type == "ACCESS_DENIED").label("access_denials"),
        )
        .where(
            *window(Event.timestamp, scope),
            Event.username.is_not(None),
            Event.username != "",
            Event.event_type.in_(["LOGIN_FAILED", "ACCESS_DENIED"]),
        )
        .group_by(Event.username)
        .cte("account_events")
    )
    findings = (
        select(Finding.username.label("entity"), func.count().label("finding_count"))
        .where(
            *window(Finding.last_seen, scope), Finding.username.is_not(None), Finding.username != ""
        )
        .group_by(Finding.username)
        .cte("account_findings")
    )
    pairs = incident_pairs(scope, "username")
    incidents = (
        select(pairs.c.entity, func.count().label("incident_count"))
        .group_by(pairs.c.entity)
        .cte("account_cases")
    )
    keys = union(
        select(events.c.entity), select(findings.c.entity), select(incidents.c.entity)
    ).cte("account_keys")
    failures, denials = (
        func.coalesce(events.c.failed_logins, 0),
        func.coalesce(events.c.access_denials, 0),
    )
    finding_count, incident_count = (
        func.coalesce(findings.c.finding_count, 0),
        func.coalesce(incidents.c.incident_count, 0),
    )
    return (
        select(
            keys.c.entity.label("username"),
            failures.label("failed_logins"),
            denials.label("access_denials"),
            finding_count.label("finding_count"),
            incident_count.label("incident_count"),
        )
        .select_from(keys)
        .outerjoin(events, events.c.entity == keys.c.entity)
        .outerjoin(findings, findings.c.entity == keys.c.entity)
        .outerjoin(incidents, incidents.c.entity == keys.c.entity)
        .order_by(
            finding_count.desc(), incident_count.desc(), (failures + denials).desc(), keys.c.entity
        )
        .limit(limit)
    )


def effective_reputation(now, policy_hash):
    return case(
        (and_(Intel.expires_at > now, Intel.policy_hash == policy_hash), Intel.reputation_level),
        else_="UNKNOWN",
    )


class DashboardRepository:
    def __init__(self, session):
        self.session = session

    def rows(self, statement):
        return self.session.execute(statement).mappings().all()

    def overview(self, scope):
        return dict(self.session.execute(overview_statement(scope)).mappings().one())

    def timeline(self, scope, seconds):
        return self.rows(timeline_statement(scope, seconds))

    def event_types(self, scope):
        return self.rows(
            select(Event.event_type, func.count().label("count"))
            .where(*window(Event.timestamp, scope))
            .group_by(Event.event_type)
            .order_by(func.count().desc(), Event.event_type)
        )

    def distribution(self, scope, field):
        return dict(self.session.execute(incident_distribution_statement(scope, field)).all())

    def risk_distribution(self, scope):
        return self.rows(risk_distribution_statement(scope))

    def event_head(self):
        return self.session.scalar(select(func.coalesce(func.max(Event.ingestion_sequence), 0)))

    def recent_events(self, scope, limit):
        return self.rows(
            select(*event_columns())
            .where(*window(Event.timestamp, scope))
            .order_by(Event.timestamp.desc(), Event.id.desc())
            .limit(limit)
        )

    def event_updates(self, after, head, limit):
        return self.rows(
            select(*event_columns())
            .where(Event.ingestion_sequence > after, Event.ingestion_sequence <= head)
            .order_by(Event.ingestion_sequence)
            .limit(limit + 1)
        )

    def recent_incidents(self, scope, limit):
        rows = self.rows(
            select(
                Incident.incident_id,
                Incident.title,
                Incident.severity,
                Incident.risk_score,
                Incident.status,
                func.host(Incident.source_ip).label("source_ip"),
                Incident.username,
                Incident.detected_at,
                User.id.label("analyst_id"),
                User.username.label("analyst_username"),
                User.full_name.label("analyst_full_name"),
                User.role.label("analyst_role"),
                User.is_active.label("analyst_is_active"),
            )
            .outerjoin(User, Incident.assigned_analyst_id == User.id)
            .where(*window(Incident.detected_at, scope))
            .order_by(Incident.detected_at.desc(), Incident.id.desc())
            .limit(limit)
        )
        result = []
        for row in rows:  # At most 100 compact records, never ORM relationship loading.
            data = dict(row)
            analyst = {
                key: data.pop("analyst_" + key)
                for key in ("id", "username", "full_name", "role", "is_active")
            }
            data["assigned_analyst"] = analyst if analyst["id"] else None
            result.append(data)
        return result

    def top_ips(self, scope, mode, policy_hash, limit):
        return self.rows(top_ips_statement(scope, mode, policy_hash, limit))

    def targeted_users(self, scope, limit):
        return self.rows(targeted_users_statement(scope, limit))

    def rules(self, scope):
        return self.rows(
            select(
                Rule.rule_id,
                Rule.name,
                Rule.enabled,
                Rule.severity,
                func.count(Finding.id).label("finding_count"),
                func.max(Finding.last_seen).label("latest_finding_timestamp"),
            )
            .outerjoin(
                Finding,
                and_(Finding.detection_rule_id == Rule.id, *window(Finding.last_seen, scope)),
            )
            .group_by(Rule.id)
            .order_by(Rule.rule_id)
        )

    def threats(self, scope, mode, policy_hash):
        level = effective_reputation(scope.as_of, policy_hash)
        statement = select(
            func.count().label("cached_indicators"),
            func.count().filter(level == "MALICIOUS").label("malicious_indicators"),
            func.count().filter(level == "SUSPICIOUS").label("suspicious_indicators"),
            func.count()
            .filter(level == "NO_ADVERSE_SIGNALS")
            .label("no_adverse_signal_indicators"),
            func.count().filter(level == "UNKNOWN").label("unknown_indicators"),
            func.count().filter(Intel.expires_at <= scope.as_of).label("expired_indicators"),
            func.count().filter(Intel.policy_hash != policy_hash).label("incompatible_indicators"),
            func.max(Intel.checked_at).label("last_refresh"),
        ).where(Intel.mode == mode, *window(Intel.checked_at, scope))
        result = dict(self.session.execute(statement).mappings().one())
        result["cache_hits"] = int(
            self.session.scalar(
                select(func.coalesce(func.sum(SystemMetric.metric_value), 0)).where(
                    SystemMetric.metric_name == "threat_cache_hits",
                    SystemMetric.metric_metadata["mode"].astext == mode,
                    *window(SystemMetric.timestamp, scope),
                )
            )
        )
        return result

    def activity(self, scope):
        return dict(
            self.session.execute(
                select(
                    *[
                        func.count().filter(Event.event_type == event_type).label(name)
                        for name, event_type in ACTIVITY_TYPES.items()
                    ]
                ).where(*window(Event.timestamp, scope))
            )
            .mappings()
            .one()
        )

    def health(self):
        result = dict(self.session.execute(event_metrics()).mappings().one())
        metric = self.session.execute(
            select(SystemMetric.timestamp, SystemMetric.metric_value)
            .where(SystemMetric.metric_name == "detection_duration_ms")
            .order_by(SystemMetric.timestamp.desc(), SystemMetric.id.desc())
            .limit(1)
        ).first()
        result["last_processing_time"] = metric.timestamp if metric else None
        result["last_processing_duration_ms"] = float(metric.metric_value) if metric else None
        return result
