"""Deduplicated entity associations; preaggregate each fact table before joining."""

from sqlalchemy import and_, func, select, union

from app.models import DetectionFinding as F
from app.models import DetectionRule as R
from app.models import Incident as I
from app.models import IncidentEvidence as IE
from app.models import IncidentFinding as IF
from app.models import RiskAssessment as Risk
from app.models import SecurityEvent as E
from app.models import ThreatIntelligence as Indicator
from app.models import ThreatIntelligenceResult as Intel
from app.repositories.analytics_repository import cohort, current_risk_join, finding_events
from app.repositories.dashboard_repository import effective_reputation, window


def value(model, kind):
    column = getattr(model, kind)
    return func.host(column) if kind == "source_ip" else column


def entity_pairs(s, kind, population):
    statements = []
    if population == "finding":
        fe = finding_events(s)
        statements.append(
            select(value(E, kind).label("entity"), fe.c.finding_pk.label("pk"))
            .select_from(fe)
            .join(E, E.id == fe.c.event_pk)
        )
        if kind in {"source_ip", "username"}:
            statements.append(
                select(value(F, kind).label("entity"), F.id.label("pk")).where(
                    *window(F.last_seen, s)
                )
            )
    else:
        statements.append(
            select(value(E, kind).label("entity"), I.id.label("pk"))
            .select_from(I)
            .join(IE, IE.incident_id == I.id)
            .join(E, E.id == IE.security_event_id)
            .where(*cohort(s))
        )
        if kind in {"source_ip", "username"}:
            statements.extend(
                [
                    select(value(I, kind).label("entity"), I.id.label("pk")).where(*cohort(s)),
                    select(value(F, kind).label("entity"), I.id.label("pk"))
                    .select_from(I)
                    .join(IF, IF.incident_id == I.id)
                    .join(F, F.id == IF.detection_finding_id)
                    .where(*cohort(s)),
                ]
            )
    pairs = (
        union(*statements).subquery()
        if len(statements) > 1
        else statements[0].distinct().subquery()
    )
    return (
        select(pairs.c.entity, pairs.c.pk)
        .where(pairs.c.entity.is_not(None), pairs.c.entity != "")
        .cte(population + "_entity_pairs")
    )


def entity_statement(s, kind, limit, recurring_only, mode, policy_hash):
    fp, ip = entity_pairs(s, kind, "finding"), entity_pairs(s, kind, "incident")
    findings = (
        select(
            fp.c.entity,
            func.count().label("finding_count"),
            func.max(Risk.risk_score).label("highest_finding_risk"),
            func.min(F.first_seen).label("finding_first"),
            func.max(F.last_seen).label("finding_last"),
            func.array_agg(func.distinct(R.rule_id)).label("detection_rules"),
        )
        .join(F, F.id == fp.c.pk)
        .join(R, R.id == F.detection_rule_id)
        .outerjoin(Risk, current_risk_join())
        .group_by(fp.c.entity)
        .cte("entity_findings")
    )
    incidents = (
        select(
            ip.c.entity,
            func.count().label("incident_count"),
            func.avg(I.risk_score).label("average_risk"),
            func.max(I.risk_score).label("highest_case_risk"),
            func.count().filter(I.severity == "CRITICAL").label("critical_incidents"),
            func.min(I.first_seen).label("incident_first"),
            func.max(I.last_seen).label("incident_last"),
        )
        .join(I, I.id == ip.c.pk)
        .group_by(ip.c.entity)
        .cte("entity_cases")
    )
    ev = value(E, kind)
    events = (
        select(
            ev.label("entity"),
            func.count().label("event_count"),
            func.count().filter(E.event_type == "LOGIN_FAILED").label("failed_logins"),
            func.count().filter(E.event_type == "ACCESS_DENIED").label("access_denials"),
        )
        .where(*window(E.timestamp, s), ev.is_not(None), ev != "")
        .group_by(ev)
        .cte("entity_events")
    )
    fe = finding_events(s)
    suspicious = (
        select(ev.label("entity"), func.count(func.distinct(E.id)).label("suspicious_event_count"))
        .select_from(fe)
        .join(E, E.id == fe.c.event_pk)
        .where(*window(E.timestamp, s), ev.is_not(None), ev != "")
        .group_by(ev)
        .cte("entity_suspicious_events")
    )
    keys = [select(findings.c.entity), select(incidents.c.entity)]
    if kind in {"service", "device"}:
        keys.append(select(events.c.entity))
    keys = union(*keys).cte("entity_keys")
    count = func.coalesce(incidents.c.incident_count, 0)
    highest = func.greatest(incidents.c.highest_case_risk, findings.c.highest_finding_risk)
    stmt = (
        select(
            keys.c.entity,
            count.label("incident_count"),
            incidents.c.average_risk,
            highest.label("highest_risk"),
            func.coalesce(incidents.c.critical_incidents, 0).label("critical_incidents"),
            func.coalesce(findings.c.finding_count, 0).label("finding_count"),
            findings.c.detection_rules,
            *[
                func.coalesce(events.c[k], 0).label(k)
                for k in ["event_count", "failed_logins", "access_denials"]
            ],
            func.coalesce(suspicious.c.suspicious_event_count, 0).label("suspicious_event_count"),
            func.least(findings.c.finding_first, incidents.c.incident_first).label("first_seen"),
            func.greatest(findings.c.finding_last, incidents.c.incident_last).label(
                "latest_activity"
            ),
        )
        .select_from(keys)
        .outerjoin(findings, findings.c.entity == keys.c.entity)
        .outerjoin(incidents, incidents.c.entity == keys.c.entity)
        .outerjoin(events, events.c.entity == keys.c.entity)
        .outerjoin(suspicious, suspicious.c.entity == keys.c.entity)
    )
    if kind == "source_ip":
        stmt = stmt.outerjoin(
            Indicator, and_(Indicator.indicator == keys.c.entity, Indicator.indicator_type == "IP")
        )
        stmt = stmt.outerjoin(Intel, and_(Intel.indicator_id == Indicator.id, Intel.mode == mode))
        stmt = stmt.add_columns(
            effective_reputation(s.as_of, policy_hash).label("reputation"),
            Intel.mode.label("intelligence_mode"),
        )
    if recurring_only:
        stmt = stmt.where(count >= 2)
    return stmt.order_by(
        highest.desc().nulls_last(),
        count.desc(),
        func.coalesce(findings.c.finding_count, 0).desc(),
        keys.c.entity,
    ).limit(limit + 1)
