"""PostgreSQL aggregation for operational analytics; never loads raw payloads."""

from datetime import timedelta

from sqlalchemy import String, and_, case, cast, func, literal, select, true, union

from app.core.enums import IncidentStatus as Status
from app.core.enums import UserRole
from app.models import AIAnalysis, AuditLog, User
from app.models import DetectionFinding as F
from app.models import DetectionRule as R
from app.models import Incident as I
from app.models import IncidentFinding as IF
from app.models import RiskAssessment as Risk
from app.models import SecurityEvent as E
from app.models import SystemMetric as M
from app.repositories.dashboard_repository import ACTIVE, window
from app.risk.config import SCORE_VERSION
from app.services.analytics_service import EPOCH

CLOSED = (Status.RESOLVED, Status.FALSE_POSITIVE)
CATEGORY_RULES = {
    "Authentication Abuse": ["CS-001", "CS-002", "CS-003", "CS-004"],
    "Access Control": ["CS-009"],
    "Privilege Activity": ["CS-005"],
    "Network Activity": ["CS-006"],
    "API Abuse": ["CS-010"],
    "Sensitive Data Access": ["CS-007"],
    "Reputation-Based": ["CS-008"],
}


def cohort(s):
    return (*window(I.created_at, s), I.created_at <= s.as_of)


def bucket(column, seconds):
    return func.date_bin(timedelta(seconds=seconds), column, EPOCH)


def resolved_duration(s):
    return case(
        (
            and_(
                I.status == Status.RESOLVED, I.resolved_at >= I.created_at, I.resolved_at <= s.as_of
            ),
            func.extract("epoch", I.resolved_at - I.created_at),
        )
    )


def acknowledgements(s):
    # Canonical status event only: auxiliary RESOLVED/REOPENED audits must not double count.
    return (
        select(I.id.label("id"), func.min(AuditLog.timestamp).label("acknowledged_at"))
        .join(
            AuditLog,
            and_(AuditLog.entity_type == "incident", AuditLog.entity_id == cast(I.id, String)),
        )
        .where(
            *cohort(s),
            AuditLog.action == "INCIDENT_STATUS_CHANGED",
            AuditLog.new_value["status"].astext == "INVESTIGATING",
            AuditLog.new_value["automatic"].astext.is_distinct_from("true"),
            AuditLog.timestamp >= I.created_at,
            AuditLog.timestamp <= s.as_of,
        )
        .group_by(I.id)
        .cte("acknowledgements")
    )


def rule_case_pairs(s):
    direct = select(I.detection_rule_id.label("rule_pk"), I.id.label("incident_pk")).where(
        *cohort(s)
    )
    linked = (
        select(F.detection_rule_id, I.id)
        .select_from(I)
        .join(IF, IF.incident_id == I.id)
        .join(F, F.id == IF.detection_finding_id)
        .where(*cohort(s))
    )
    return union(direct, linked).cte("rule_cases")


def current_risk_join():
    return and_(Risk.detection_finding_id == F.id, Risk.score_version == SCORE_VERSION)


def finding_events(s=None):
    """Distinct evidence-event pairs, including primary events; no UUID casts of log input."""
    ids = (
        func.jsonb_array_elements_text(F.evidence_event_ids)
        .table_valued("event_id")
        .render_derived()
        .lateral("evidence_ids")
    )
    primary = select(F.id.label("finding_pk"), F.primary_event_id.label("event_pk"))
    linked = (
        select(F.id, E.id).select_from(F).join(ids, true()).join(E, E.event_id == ids.c.event_id)
    )
    if s:
        primary = primary.where(*window(F.last_seen, s))
        linked = linked.where(*window(F.last_seen, s))
    return union(primary, linked).cte()


class AnalyticsRepository:
    def __init__(self, session):
        self.session = session

    def rows(self, statement):
        return [dict(row) for row in self.session.execute(statement).mappings()]

    def one(self, statement):
        return dict(self.session.execute(statement).mappings().one())

    def overview(self, s):
        ack = acknowledgements(s)
        duration = resolved_duration(s)
        values = self.one(
            select(
                func.count(I.id).label("incidents_created"),
                func.count().filter(I.severity == "CRITICAL").label("critical_incidents"),
                func.count().filter(I.status == Status.RESOLVED).label("resolved_incidents"),
                func.count().filter(I.status == Status.FALSE_POSITIVE).label("false_positives"),
                func.avg(I.risk_score).label("average_risk_score"),
                func.percentile_cont(0.5).within_group(I.risk_score).label("median_risk_score"),
                func.count(ack.c.acknowledged_at).label("acknowledged_incidents"),
                func.avg(func.extract("epoch", ack.c.acknowledged_at - I.created_at)).label(
                    "mean_time_to_acknowledge_seconds"
                ),
                func.count(duration).label("measured_resolutions"),
                func.avg(duration).label("mean_time_to_resolve_seconds"),
                func.percentile_cont(0.9).within_group(duration).label("p90_resolution_seconds"),
            )
            .select_from(I)
            .outerjoin(ack, ack.c.id == I.id)
            .where(*cohort(s))
        )
        values["total_events"] = self.session.scalar(
            select(func.count()).select_from(E).where(*window(E.timestamp, s))
        )
        values["detection_findings"] = self.session.scalar(
            select(func.count()).select_from(F).where(*window(F.last_seen, s))
        )
        # Use the same deduplicated association source as entity analytics.
        from app.repositories.analytics_entities import entity_pairs

        for field, key in [
            ("source_ip", "unique_suspicious_ips"),
            ("username", "unique_targeted_users"),
        ]:
            pairs = entity_pairs(s, field, "finding")
            cases = entity_pairs(s, field, "incident")
            keys = union(select(pairs.c.entity), select(cases.c.entity)).subquery()
            values[key] = self.session.scalar(select(func.count()).select_from(keys))
        return values

    def event_trend(self, s, seconds, query):
        b = bucket(E.timestamp, seconds)
        clauses = list(window(E.timestamp, s))
        for key in ("event_type", "service", "status", "username"):
            if getattr(query, key) is not None:
                clauses.append(getattr(E, key) == getattr(query, key))
        if query.source_ip:
            from ipaddress import ip_address

            from app.core.errors import ServiceError

            try:
                address = str(ip_address(query.source_ip))
            except ValueError:
                raise ServiceError(422, "source_ip must be a valid IP address") from None
            clauses.append(E.source_ip == address)
        types = {
            "login_failed": "LOGIN_FAILED",
            "access_denied": "ACCESS_DENIED",
            "api_requests": "API_REQUEST",
            "sensitive_access": "SENSITIVE_RECORD_ACCESS",
            "privilege_changes": "PRIVILEGE_CHANGE",
        }
        return self.rows(
            select(
                b.label("timestamp"),
                func.count().label("total"),
                *[func.count().filter(E.event_type == v).label(k) for k, v in types.items()],
            )
            .where(*clauses)
            .group_by(b)
            .order_by(b)
        )

    def incident_trend(self, s, seconds):
        b = bucket(I.created_at, seconds)
        created = self.rows(
            select(
                b.label("timestamp"),
                func.count().label("created"),
                func.count().filter(I.severity == "CRITICAL").label("critical"),
            )
            .where(*cohort(s))
            .group_by(b)
        )
        b = bucket(AuditLog.timestamp, seconds)
        previous, current = AuditLog.old_value["status"].astext, AuditLog.new_value["status"].astext
        transitions = self.rows(
            select(
                b.label("timestamp"),
                func.count().filter(current == "RESOLVED").label("resolved"),
                func.count().filter(current == "FALSE_POSITIVE").label("false_positive"),
                func.count()
                .filter(previous.in_(["RESOLVED", "FALSE_POSITIVE"]), current == "INVESTIGATING")
                .label("reopened"),
            )
            .where(
                AuditLog.entity_type == "incident",
                AuditLog.action == "INCIDENT_STATUS_CHANGED",
                current != previous,
                *window(AuditLog.timestamp, s),
                AuditLog.timestamp <= s.as_of,
            )
            .group_by(b)
        )
        return created, transitions

    def rules(self, s):
        findings = (
            select(
                F.detection_rule_id.label("rule_pk"),
                func.count().label("findings"),
                func.avg(Risk.risk_score).label("average_risk"),
                func.max(F.last_seen).label("latest_detection"),
            )
            .select_from(F)
            .outerjoin(Risk, current_risk_join())
            .where(*window(F.last_seen, s))
            .group_by(F.detection_rule_id)
            .cte("rule_findings")
        )
        pairs = rule_case_pairs(s)
        cases = (
            select(
                pairs.c.rule_pk,
                func.count().label("incidents"),
                func.count().filter(I.severity == "CRITICAL").label("critical_incidents"),
                func.count().filter(I.status == Status.FALSE_POSITIVE).label("false_positives"),
                func.count().filter(I.status.in_(CLOSED)).label("closed_incidents"),
            )
            .join(I, I.id == pairs.c.incident_pk)
            .group_by(pairs.c.rule_pk)
            .cte("case_totals")
        )
        return self.rows(
            select(
                R.rule_id,
                R.name,
                R.enabled,
                *[func.coalesce(findings.c[k], 0).label(k) for k in ["findings"]],
                findings.c.average_risk,
                findings.c.latest_detection,
                *[
                    func.coalesce(cases.c[k], 0).label(k)
                    for k in [
                        "incidents",
                        "critical_incidents",
                        "false_positives",
                        "closed_incidents",
                    ]
                ],
            )
            .select_from(R)
            .outerjoin(findings, findings.c.rule_pk == R.id)
            .outerjoin(cases, cases.c.rule_pk == R.id)
            .order_by(R.rule_id)
        )

    def risk_population(self, s, population):
        if population == "incidents":
            return (
                select(I.risk_score.label("score"), I.created_at.label("time"))
                .where(*cohort(s))
                .cte("risk_population")
            )
        return (
            select(Risk.risk_score.label("score"), F.last_seen.label("time"))
            .select_from(F)
            .join(Risk, current_risk_join())
            .where(*window(F.last_seen, s))
            .cte("risk_population")
        )

    def risk_trend(self, s, seconds, population):
        p = self.risk_population(s, population)
        b = bucket(p.c.time, seconds)
        return self.rows(
            select(
                b.label("timestamp"),
                func.count().label("count"),
                func.avg(p.c.score).label("average_risk"),
                func.percentile_cont(0.5).within_group(p.c.score).label("median_risk"),
                func.max(p.c.score).label("maximum_risk"),
                func.count().filter(p.c.score >= 75).label("critical_count"),
            )
            .group_by(b)
            .order_by(b)
        )

    def histogram(self, s, population):
        p = self.risk_population(s, population)
        band = func.least(func.floor(p.c.score / literal(10.0)), 9)
        return dict(self.session.execute(select(band, func.count()).group_by(band)).all())

    def backlog(self, s):
        age = func.extract("epoch", s.as_of - I.created_at)
        conditions = (*cohort(s), I.status.in_(ACTIVE))
        result = self.one(
            select(
                func.count().filter(I.status == Status.OPEN).label("open_count"),
                func.count().filter(I.status == Status.INVESTIGATING).label("investigating_count"),
                func.count().filter(I.severity == "CRITICAL").label("critical_unresolved"),
                func.avg(age).label("average_age_seconds"),
            ).where(*conditions)
        )
        oldest = self.rows(
            select(I.incident_id, I.created_at, age.label("age_seconds"))
            .where(*conditions)
            .order_by(I.created_at, I.id)
            .limit(1)
        )
        result["oldest"] = oldest[0] if oldest else None
        band = case(
            (age < 3600, "<1 hour"),
            (age < 14400, "1–4 hours"),
            (age < 86400, "4–24 hours"),
            (age <= 259200, "1–3 days"),
            else_=">3 days",
        )
        bands = dict(
            self.session.execute(select(band, func.count()).where(*conditions).group_by(band)).all()
        )
        result["age_distribution"] = [
            {"label": k, "count": bands.get(k, 0)}
            for k in ["<1 hour", "1–4 hours", "4–24 hours", "1–3 days", ">3 days"]
        ]
        return result

    def workload(self, s, seconds, limit=100, offset=0):
        eligible = and_(User.is_active.is_(True), User.role.in_([UserRole.ADMIN, UserRole.ANALYST]))
        items = self.rows(
            select(
                cast(User.id, String).label("analyst_id"),
                User.username,
                func.count(I.id).label("assigned"),
                func.count(I.id).filter(I.status == Status.OPEN).label("open"),
                func.count(I.id).filter(I.status == Status.INVESTIGATING).label("investigating"),
                func.count(I.id).filter(I.status == Status.RESOLVED).label("resolved"),
                func.avg(resolved_duration(s)).label("average_resolution_seconds"),
            )
            .select_from(User)
            .outerjoin(I, and_(I.assigned_analyst_id == User.id, *cohort(s)))
            .where(eligible)
            .group_by(User.id)
            .order_by(User.username)
            .offset(offset)
            .limit(limit + 1)
        )
        counts = self.one(
            select(
                func.count().filter(I.assigned_analyst_id.is_(None)).label("unassigned"),
                func.count()
                .filter(I.assigned_analyst_id.is_not(None), ~eligible)
                .label("assigned_to_ineligible"),
            )
            .select_from(I)
            .outerjoin(User, User.id == I.assigned_analyst_id)
            .where(*cohort(s))
        )
        b = bucket(AuditLog.timestamp, seconds)
        activity = self.rows(
            select(
                b.label("timestamp"),
                func.count().filter(AuditLog.action == "INCIDENT_ASSIGNED").label("assignments"),
                func.count().filter(AuditLog.action == "INCIDENT_COMMENT_ADDED").label("comments"),
                func.count()
                .filter(AuditLog.action == "INCIDENT_STATUS_CHANGED")
                .label("status_transitions"),
                func.count()
                .filter(
                    AuditLog.action == "INCIDENT_STATUS_CHANGED",
                    AuditLog.new_value["status"].astext == "RESOLVED",
                )
                .label("resolutions"),
            )
            .where(
                AuditLog.entity_type == "incident",
                AuditLog.user_id.is_not(None),
                *window(AuditLog.timestamp, s),
            )
            .group_by(b)
        )
        return dict(items=items, activity=activity, **counts)

    def categories(self, s):
        category = case(
            *[(R.rule_id.in_(codes), name) for name, codes in CATEGORY_RULES.items()], else_="Other"
        )
        findings = self.rows(
            select(category.label("category"), func.count().label("findings"))
            .select_from(F)
            .join(R, F.detection_rule_id == R.id)
            .where(*window(F.last_seen, s))
            .group_by(category)
        )
        pairs = rule_case_pairs(s)
        cases = self.rows(
            select(
                category.label("category"),
                func.count(func.distinct(pairs.c.incident_pk)).label("incidents"),
            )
            .select_from(pairs)
            .join(R, R.id == pairs.c.rule_pk)
            .group_by(category)
        )
        return findings, cases

    def geography(self, s):
        fe = finding_events(s)
        countries = (
            select(E.country, F.id.label("finding_pk"))
            .select_from(fe)
            .join(E, E.id == fe.c.event_pk)
            .join(F, F.id == fe.c.finding_pk)
            .where(
                E.country.is_not(None),
                func.length(func.trim(E.country)) > 0,
                func.lower(func.trim(E.country)).not_in(["unknown", "n/a", "none"]),
            )
            .distinct()
            .cte("observed_countries")
        )
        # Incident counts use the same finding-linked geography, with creation-time incident scope.
        return self.rows(
            select(
                countries.c.country,
                func.count(func.distinct(countries.c.finding_pk)).label("finding_count"),
                func.count(func.distinct(I.id)).label("incident_count"),
            )
            .select_from(countries)
            .outerjoin(IF, IF.detection_finding_id == countries.c.finding_pk)
            .outerjoin(I, and_(I.id == IF.incident_id, *cohort(s)))
            .group_by(countries.c.country)
            .order_by(func.count(func.distinct(countries.c.finding_pk)).desc(), countries.c.country)
            .limit(31)
        )

    def metric(self, s, name, mode=None, average=False):
        stmt = select(
            func.avg(M.metric_value) if average else func.coalesce(func.sum(M.metric_value), 0)
        ).where(M.metric_name == name, *window(M.timestamp, s))
        if mode:
            stmt = stmt.where(M.metric_metadata["mode"].astext == mode)
        return self.session.scalar(stmt)

    def ai_usage(self, s):
        result = self.one(
            select(
                func.count().label("analyses_generated"),
                func.count()
                .filter(AIAnalysis.analysis_mode == "FALLBACK")
                .label("fallback_analyses"),
                func.count().filter(AIAnalysis.analysis_mode == "AI").label("provider_analyses"),
            ).where(*window(AIAnalysis.generated_at, s))
        )
        result.update(
            analysis_failures=int(self.metric(s, "ai_analysis_failures")),
            cache_hits=int(self.metric(s, "ai_analysis_cache_hits")),
            average_response_ms=self.metric(s, "ai_analysis_duration_ms", average=True),
        )
        return result


def status_history_statement(s, seconds):
    """State at bucket end for audited creation-cohort cases; SQL window ranking, no N+1."""
    from sqlalchemy import union_all

    from app.services.analytics_service import bucket_start

    created_audit = (
        select(AuditLog.id)
        .where(
            AuditLog.entity_type == "incident",
            AuditLog.entity_id == cast(I.id, String),
            AuditLog.action == "INCIDENT_CREATED",
        )
        .exists()
    )
    tracked = select(I.id, I.created_at).where(*cohort(s), created_audit).cte("tracked_cases")
    initial = select(
        tracked.c.id.label("incident_pk"),
        tracked.c.created_at.label("time"),
        literal("OPEN").label("status"),
        literal(0).label("priority"),
        literal("").label("tie"),
    )
    changes = (
        select(
            tracked.c.id,
            AuditLog.timestamp,
            AuditLog.new_value["status"].astext,
            literal(1),
            cast(AuditLog.id, String),
        )
        .select_from(tracked)
        .join(
            AuditLog,
            and_(
                AuditLog.entity_type == "incident", AuditLog.entity_id == cast(tracked.c.id, String)
            ),
        )
    )
    changes = changes.where(
        AuditLog.action == "INCIDENT_STATUS_CHANGED",
        AuditLog.new_value["status"].astext.in_(
            ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
        ),
        AuditLog.timestamp >= tracked.c.created_at,
        AuditLog.timestamp <= s.as_of,
    )
    states = union_all(initial, changes).cte("recorded_states")
    times = (
        func.generate_series(
            bucket_start(s.start, seconds),
            s.end - timedelta(microseconds=1),
            timedelta(seconds=seconds),
        )
        .table_valued("timestamp")
        .render_derived()
    )
    times = select(times.c.timestamp).cte("status_buckets")
    cutoff = func.least(times.c.timestamp + timedelta(seconds=seconds), s.end, s.as_of)
    ranked = select(
        times.c.timestamp,
        states.c.status,
        func.row_number()
        .over(
            partition_by=(times.c.timestamp, states.c.incident_pk),
            order_by=(states.c.time.desc(), states.c.priority.desc(), states.c.tie.desc()),
        )
        .label("position"),
    )
    ranked = ranked.select_from(times).join(states, states.c.time < cutoff).cte("ranked_states")
    statement = (
        select(
            ranked.c.timestamp,
            *[
                func.count().filter(ranked.c.status == key.upper()).label(key)
                for key in ("open", "investigating", "resolved", "false_positive")
            ],
        )
        .where(ranked.c.position == 1)
        .group_by(ranked.c.timestamp)
    )
    coverage = select(
        select(func.count()).select_from(tracked).scalar_subquery().label("tracked_cases"),
        (
            select(func.count()).select_from(I).where(*cohort(s)).scalar_subquery()
            - select(func.count()).select_from(tracked).scalar_subquery()
        ).label("excluded_cases"),
    )
    return statement, coverage
