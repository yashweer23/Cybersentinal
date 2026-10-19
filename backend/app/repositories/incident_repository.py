"""Bounded PostgreSQL queries; services own transactions and audit snapshots."""

from datetime import timedelta

from sqlalchemy import String, and_, case, cast, func, literal, or_, select, tuple_, union_all
from sqlalchemy.dialects.postgresql import JSONB, insert
from sqlalchemy.orm import selectinload

from app.core.enums import IncidentStatus, SeverityLevel, UserRole
from app.core.errors import ServiceError
from app.incidents.correlation import ACTIVE, Case, Context
from app.models import (
    AuditLog,
    DetectionFinding,
    DetectionRule,
    Incident,
    IncidentComment,
    IncidentEvidence,
    IncidentFinding,
    IncidentProcessing,
    RiskAssessment,
    SecurityEvent,
    User,
)
from app.risk.config import SCORE_VERSION
from app.schemas.incident import (
    AnalystPage,
    AnalystReference,
    CommentPage,
    EvidenceReference,
    FindingPage,
    IncidentEvent,
    IncidentEventPage,
    IncidentListResponse,
    IncidentNote,
    IncidentStats,
    IncidentSummary,
    LinkedFinding,
    TimelineEntry,
    TimelinePage,
)
from app.schemas.risk import assessment_response


def acquire_lock(session):
    return session.scalar(select(func.pg_try_advisory_xact_lock(1129530451, 8)))


def context_revision(session):
    return session.scalar(select(func.max(Incident.updated_at)))


def pending_query(options, policy, cutoff, revision):
    state = IncidentProcessing
    changed_context = and_(
        state.outcome == "DEFERRED", state.context_updated_at.is_distinct_from(revision)
    )
    query = (
        select(RiskAssessment)
        .join(DetectionFinding, DetectionFinding.id == RiskAssessment.detection_finding_id)
        .outerjoin(state, state.detection_finding_id == DetectionFinding.id)
        .where(
            RiskAssessment.score_version == SCORE_VERSION,
            RiskAssessment.calculated_at <= cutoff,
            DetectionFinding.created_at <= cutoff,
            or_(
                state.detection_finding_id.is_(None),
                state.risk_input_hash != RiskAssessment.input_hash,
                state.policy_hash != policy.fingerprint,
                changed_context,
            ),
        )
    )
    if options.finding:
        query = query.where(DetectionFinding.finding_id == options.finding)
    return query


def fetch_batch(session, options, policy, cutoff, revision, size, cursor=None, excluded=()):
    priority = case((RiskAssessment.risk_score >= policy.minimum_risk, 0), else_=1)
    query = pending_query(options, policy, cutoff, revision)
    if excluded:
        query = query.where(DetectionFinding.id.not_in(excluded))
    if cursor:
        query = query.where(
            tuple_(priority, DetectionFinding.first_seen, DetectionFinding.id) > tuple_(*cursor)
        )
    return list(
        session.scalars(
            query.order_by(priority, DetectionFinding.first_seen, DetectionFinding.id).limit(size)
        )
    )


def pending_count(session, options, policy, cutoff, revision):
    return session.scalar(
        select(func.count()).select_from(
            pending_query(options, policy, cutoff, revision).subquery()
        )
    )


def evidence_events(session, assessments):
    ids = set()
    for assessment in assessments:
        values = assessment.finding.evidence_event_ids
        if isinstance(values, list) and len(values) <= 200:
            ids.update(x for x in values if isinstance(x, str) and len(x) <= 128)
    ids, found = sorted(ids), {}
    for offset in range(0, len(ids), 5000):
        for row in session.execute(
            select(SecurityEvent.id, SecurityEvent.event_id, SecurityEvent.device).where(
                SecurityEvent.event_id.in_(ids[offset : offset + 5000])
            )
        ):
            found[row.event_id] = row
    return found


def linked_incident(session, finding_id):
    return session.scalar(
        select(Incident)
        .join(IncidentFinding)
        .where(IncidentFinding.detection_finding_id == finding_id)
    )


def candidates(session, incoming, policy, limit):
    identity = []
    if incoming.username:
        identity.append(DetectionFinding.username == incoming.username)
    if incoming.source_ip:
        identity.append(DetectionFinding.source_ip == incoming.source_ip)
    if not identity:
        return {}
    window = timedelta(minutes=policy.window_minutes)
    statuses = list(ACTIVE) + ([IncidentStatus.RESOLVED] if policy.reopen_minutes else [])
    rows = session.execute(
        select(
            Incident,
            DetectionFinding.finding_id,
            DetectionFinding.username,
            DetectionFinding.source_ip,
            DetectionFinding.first_seen,
            DetectionFinding.last_seen,
            DetectionFinding.created_at,
            DetectionRule.rule_id,
            SecurityEvent.device,
        )
        .join(IncidentFinding, IncidentFinding.incident_id == Incident.id)
        .join(DetectionFinding, DetectionFinding.id == IncidentFinding.detection_finding_id)
        .join(DetectionRule, DetectionRule.id == DetectionFinding.detection_rule_id)
        .join(SecurityEvent, SecurityEvent.id == DetectionFinding.primary_event_id)
        .where(
            Incident.status.in_(statuses),
            Incident.first_seen >= incoming.last_seen - window,
            Incident.last_seen <= incoming.first_seen + window,
            or_(*identity),
        )
        .order_by(Incident.created_at, Incident.id, DetectionFinding.id)
        .limit(limit + 1)
    ).all()
    if len(rows) > limit:
        raise ServiceError(422, "Incident correlation candidate limit exceeded; narrow the run")
    result = {}
    for row in rows:
        candidate = result.setdefault(row.Incident.id, Case.from_row(row.Incident))
        device = row.device
        if not device or device.lower() in {"unknown", "n/a", "none"}:
            device = None
        candidate.members.append(
            Context(
                row.finding_id,
                row.username,
                str(row.source_ip) if row.source_ip else None,
                device,
                row.rule_id,
                row.first_seen,
                row.last_seen,
                row.created_at,
            )
        )
    return result


def save_link(session, incident, finding, events, reason, correlation):
    session.add(
        IncidentFinding(
            incident_id=incident.id,
            detection_finding_id=finding.id,
            relationship_reason=reason,
            correlation_data=correlation,
        )
    )
    session.flush()
    values = [
        {
            "incident_id": incident.id,
            "security_event_id": event.id,
            "detection_finding_id": finding.id,
            "evidence_type": "DETECTION_EVENT",
            "description": "Retained event referenced by a linked detection finding.",
            "evidence_data": {"reference_only": True},
        }
        for event in events
    ]
    if values:
        session.execute(
            insert(IncidentEvidence)
            .values(values)
            .on_conflict_do_nothing(
                index_elements=["incident_id", "security_event_id", "evidence_type"]
            )
        )


def refresh_incident(session, incident):
    total, first, last, confidence, score = session.execute(
        select(
            func.count(),
            func.min(DetectionFinding.first_seen),
            func.max(DetectionFinding.last_seen),
            func.max(DetectionFinding.confidence),
            func.max(RiskAssessment.risk_score),
        )
        .select_from(IncidentFinding)
        .join(DetectionFinding, DetectionFinding.id == IncidentFinding.detection_finding_id)
        .join(RiskAssessment, RiskAssessment.detection_finding_id == DetectionFinding.id)
        .where(
            IncidentFinding.incident_id == incident.id,
            RiskAssessment.score_version == SCORE_VERSION,
        )
    ).one()
    from app.risk.components import risk_level

    if not total:
        raise ServiceError(422, "Linked findings have no current risk assessment")
    incident.first_seen, incident.last_seen = first, last
    incident.confidence, incident.risk_score = confidence, score
    incident.severity = risk_level(score)
    incident.risk_score_version = SCORE_VERSION
    incident.risk_updated_at = session.scalar(select(func.clock_timestamp()))
    incident.description = (
        f"{total} scored detection finding(s) observed between {first.isoformat()} "
        f"and {last.isoformat()}. Incident risk is the highest linked {SCORE_VERSION} "
        "assessment. Review the linked evidence to establish cause and impact."
    )
    session.flush()
    session.refresh(incident)


def save_states(session, values):
    if not values:
        return
    statement = insert(IncidentProcessing).values(values)
    session.execute(
        statement.on_conflict_do_update(
            index_elements=["detection_finding_id"],
            set_={
                key: getattr(statement.excluded, key)
                for key in values[0]
                if key != "detection_finding_id"
            },
        )
    )


def get_incident(session, identifier, lock=False):
    query = (
        select(Incident)
        .options(selectinload(Incident.assigned_analyst))
        .where(Incident.incident_id == identifier)
        .execution_options(populate_existing=True)
    )
    if lock:
        query = query.with_for_update()
    row = session.scalar(query)
    if row is None:
        raise ServiceError(404, "Incident not found")
    return row


def summary(row):
    data = {
        key: getattr(row, key) for key in IncidentSummary.model_fields if key != "assigned_analyst"
    }
    data["assigned_analyst"] = (
        AnalystReference.model_validate(row.assigned_analyst) if row.assigned_analyst else None
    )
    return IncidentSummary(**data)


def eligible_analysts(session, filters):
    clauses = [User.is_active.is_(True), User.role.in_([UserRole.ADMIN, UserRole.ANALYST])]
    if filters.q:
        clauses.append(
            or_(
                User.username.icontains(filters.q, autoescape=True),
                User.full_name.icontains(filters.q, autoescape=True),
            )
        )
    total = session.scalar(select(func.count()).select_from(User).where(*clauses))
    rows = session.scalars(
        select(User)
        .where(*clauses)
        .order_by(User.username, User.id)
        .offset(filters.offset)
        .limit(filters.limit)
    )
    return AnalystPage(
        items=[AnalystReference.model_validate(row) for row in rows],
        total=total,
        limit=filters.limit,
        offset=filters.offset,
    )


def leading_assessment(session, incident):
    """Same maximum policy as case processing; return stored components, never rescore."""
    if not incident.risk_score_version:
        return None
    row = session.scalar(
        select(RiskAssessment)
        .join(
            IncidentFinding,
            IncidentFinding.detection_finding_id == RiskAssessment.detection_finding_id,
        )
        .where(
            IncidentFinding.incident_id == incident.id,
            RiskAssessment.score_version == incident.risk_score_version,
        )
        .order_by(RiskAssessment.risk_score.desc(), RiskAssessment.assessment_id)
        .limit(1)
    )
    return assessment_response(row) if row else None


def list_incidents(session, filters):
    clauses = []
    for key in ("status", "severity"):
        if getattr(filters, key) is not None:
            clauses.append(getattr(Incident, key) == getattr(filters, key))
    if filters.assigned_analyst is not None:
        clauses.append(Incident.assigned_analyst_id == filters.assigned_analyst)
    if filters.minimum_risk is not None:
        clauses.append(Incident.risk_score >= filters.minimum_risk)
    if filters.maximum_risk is not None:
        clauses.append(Incident.risk_score <= filters.maximum_risk)
    if filters.start_time:
        clauses.append(Incident.last_seen >= filters.start_time)
    if filters.end_time:
        clauses.append(Incident.first_seen <= filters.end_time)
    # Identity/rule filters search linked findings as well as the case's original primary context.
    for key in ("username", "source_ip", "rule_id"):
        value = getattr(filters, key)
        if value is None:
            continue
        column = DetectionRule.rule_id if key == "rule_id" else getattr(DetectionFinding, key)
        linked = (
            select(IncidentFinding.id)
            .join(DetectionFinding)
            .join(DetectionRule)
            .where(IncidentFinding.incident_id == Incident.id, column == value)
            .exists()
        )
        primary = (
            Incident.detection_rule.has(DetectionRule.rule_id == value)
            if key == "rule_id"
            else getattr(Incident, key) == value
        )
        clauses.append(or_(primary, linked))
    total = session.scalar(select(func.count()).select_from(Incident).where(*clauses))
    rank = case(
        {
            level: index
            for index, level in enumerate(
                [
                    SeverityLevel.CRITICAL,
                    SeverityLevel.HIGH,
                    SeverityLevel.MEDIUM,
                    SeverityLevel.LOW,
                ]
            )
        },
        value=Incident.severity,
    )
    rows = session.scalars(
        select(Incident)
        .options(selectinload(Incident.assigned_analyst))
        .where(*clauses)
        .order_by(rank, Incident.risk_score.desc(), Incident.created_at.desc(), Incident.id)
        .offset(filters.offset)
        .limit(filters.limit)
    )
    return IncidentListResponse(
        items=[summary(row) for row in rows],
        total=total,
        limit=filters.limit,
        offset=filters.offset,
    )


def finding_page(session, incident, page):
    query = (
        select(IncidentFinding, DetectionFinding, RiskAssessment)
        .join(DetectionFinding, DetectionFinding.id == IncidentFinding.detection_finding_id)
        .outerjoin(
            RiskAssessment,
            and_(
                RiskAssessment.detection_finding_id == DetectionFinding.id,
                RiskAssessment.score_version == SCORE_VERSION,
            ),
        )
        .where(IncidentFinding.incident_id == incident.id)
    )
    total = session.scalar(
        select(func.count())
        .select_from(IncidentFinding)
        .where(IncidentFinding.incident_id == incident.id)
    )
    items = []
    for link, finding, risk in session.execute(
        query.order_by(DetectionFinding.first_seen, DetectionFinding.id)
        .offset(page.offset)
        .limit(page.limit)
    ):
        items.append(
            LinkedFinding(
                finding_id=finding.finding_id,
                rule_id=finding.rule.rule_id,
                rule_name=finding.rule.name,
                title=finding.title,
                severity=finding.severity,
                confidence=finding.confidence,
                event_count=finding.event_count,
                risk_score=risk.risk_score if risk else None,
                risk_level=risk.risk_level if risk else None,
                score_version=risk.score_version if risk else None,
                assessment_id=risk.assessment_id if risk else None,
                source_ip=finding.source_ip,
                username=finding.username,
                first_seen=finding.first_seen,
                last_seen=finding.last_seen,
                added_at=link.added_at,
                relationship_reason=link.relationship_reason,
                correlation_data=link.correlation_data,
            )
        )
    return FindingPage(items=items, total=total, limit=page.limit, offset=page.offset)


def event_condition(incident):
    return (
        select(IncidentEvidence.id)
        .where(
            IncidentEvidence.incident_id == incident.id,
            IncidentEvidence.security_event_id == SecurityEvent.id,
        )
        .exists()
    )


def event_page(session, incident, page):
    clauses = [event_condition(incident)]
    for field in ("event_type", "source_ip", "username", "service", "status"):
        value = getattr(page, field, None)
        if value is not None:
            clauses.append(getattr(SecurityEvent, field) == value)
    query = select(*(getattr(SecurityEvent, key) for key in IncidentEvent.model_fields)).where(
        *clauses
    )
    total = session.scalar(select(func.count()).select_from(SecurityEvent).where(*clauses))
    rows = session.execute(
        query.order_by(SecurityEvent.timestamp, SecurityEvent.id)
        .offset(page.offset)
        .limit(page.limit)
    ).mappings()
    return IncidentEventPage(
        items=[IncidentEvent(**row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


def evidence_page(session, incident, limit=50):
    total = session.scalar(
        select(func.count())
        .select_from(IncidentEvidence)
        .where(IncidentEvidence.incident_id == incident.id)
    )
    rows = session.execute(
        select(
            IncidentEvidence.id,
            IncidentEvidence.security_event_id,
            SecurityEvent.event_id,
            IncidentEvidence.detection_finding_id,
            IncidentEvidence.evidence_type,
            IncidentEvidence.description,
        )
        .join(SecurityEvent)
        .where(IncidentEvidence.incident_id == incident.id)
        .order_by(SecurityEvent.timestamp, IncidentEvidence.id)
        .limit(limit)
    ).mappings()
    return [EvidenceReference(**row) for row in rows], total


def note_response(note):
    return IncidentNote(
        id=note.id,
        created_at=note.created_at,
        updated_at=note.updated_at,
        comment=note.comment,
        author=AnalystReference.model_validate(note.user) if note.user else None,
    )


def get_comment(session, identifier):
    return note_response(
        session.scalar(
            select(IncidentComment)
            .options(selectinload(IncidentComment.user))
            .where(IncidentComment.id == identifier)
        )
    )


def comment_page(session, incident, page):
    clause = IncidentComment.incident_id == incident.id
    total = session.scalar(select(func.count()).select_from(IncidentComment).where(clause))
    rows = session.scalars(
        select(IncidentComment)
        .options(selectinload(IncidentComment.user))
        .where(clause)
        .order_by(IncidentComment.created_at, IncidentComment.id)
        .offset(page.offset)
        .limit(page.limit)
    )
    return CommentPage(
        items=[note_response(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


def timeline_page(session, incident, page):
    """Union in SQL before sorting/pagination; no full evidence history in Python memory."""

    def fields(timestamp, kind, title, reference, actor=None, details=None):
        return (
            timestamp.label("timestamp"),
            literal(kind).label("type"),
            title.label("title"),
            cast(reference, String).label("reference_id"),
            cast(actor, String).label("actor_id")
            if actor is not None
            else cast(literal(None), String).label("actor_id"),
            (details if details is not None else literal({}, type_=JSONB)).label("details"),
        )

    events = select(
        *fields(
            SecurityEvent.timestamp,
            "SECURITY_EVENT",
            SecurityEvent.event_type,
            SecurityEvent.event_id,
            details=func.jsonb_build_object(
                "source_ip", func.host(SecurityEvent.source_ip), "username", SecurityEvent.username
            ),
        )
    ).where(event_condition(incident))
    findings = (
        select(
            *fields(
                DetectionFinding.created_at,
                "DETECTION",
                DetectionFinding.title,
                DetectionFinding.finding_id,
            )
        )
        .join(IncidentFinding)
        .where(IncidentFinding.incident_id == incident.id)
    )
    risks = (
        select(
            *fields(
                RiskAssessment.calculated_at,
                "RISK_ASSESSMENT",
                literal("Risk score ") + cast(RiskAssessment.risk_score, String),
                RiskAssessment.assessment_id,
            )
        )
        .join(
            IncidentFinding,
            IncidentFinding.detection_finding_id == RiskAssessment.detection_finding_id,
        )
        .where(
            IncidentFinding.incident_id == incident.id,
            RiskAssessment.score_version == SCORE_VERSION,
        )
    )
    comments = select(
        *fields(
            IncidentComment.created_at,
            "COMMENT",
            literal("Analyst note added"),
            IncidentComment.id,
            IncidentComment.user_id,
        )
    ).where(IncidentComment.incident_id == incident.id)
    audits = select(
        *fields(
            AuditLog.timestamp,
            "AUDIT",
            AuditLog.action,
            AuditLog.id,
            AuditLog.user_id,
            details=func.jsonb_build_object(
                "previous_status",
                AuditLog.old_value["status"].as_string(),
                "status",
                AuditLog.new_value["status"].as_string(),
                "resolution_summary",
                AuditLog.new_value["resolution_summary"].as_string(),
                "reason",
                AuditLog.new_value["reason"].as_string(),
                "analyst_id",
                AuditLog.new_value["analyst_id"].as_string(),
            ),
        )
    ).where(
        or_(
            and_(
                AuditLog.entity_type == "incident",
                AuditLog.entity_id == str(incident.id),
                AuditLog.action != "INCIDENT_COMMENT_ADDED",
            ),
            and_(
                AuditLog.entity_type == "threat_enrichment",
                AuditLog.entity_id == incident.incident_id,
                AuditLog.action == "INCIDENT_ENRICHMENT_TRIGGERED",
            ),
        )
    )
    combined = union_all(events, findings, risks, comments, audits).subquery()
    total = session.scalar(select(func.count()).select_from(combined))
    order = [combined.c.timestamp, combined.c.type, combined.c.reference_id]
    if getattr(page, "order", "asc") == "desc":
        order = [column.desc() for column in order]
    rows = session.execute(
        select(combined, User.username.label("actor_username"))
        .outerjoin(User, cast(User.id, String) == combined.c.actor_id)
        .order_by(*order)
        .offset(page.offset)
        .limit(page.limit)
    ).mappings()
    return TimelinePage(
        items=[TimelineEntry(**row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


def stats(session):
    total, avg, unassigned = session.execute(
        select(
            func.count(),
            func.avg(Incident.risk_score),
            func.count().filter(Incident.assigned_analyst_id.is_(None)),
        )
    ).one()
    states = {state: 0 for state in IncidentStatus}
    states.update(
        dict(session.execute(select(Incident.status, func.count()).group_by(Incident.status)).all())
    )
    levels = {level.value: 0 for level in SeverityLevel}
    levels.update(
        {
            level.value: count
            for level, count in session.execute(
                select(Incident.severity, func.count()).group_by(Incident.severity)
            )
        }
    )
    return IncidentStats(
        total=total,
        open=states[IncidentStatus.OPEN],
        investigating=states[IncidentStatus.INVESTIGATING],
        resolved=states[IncidentStatus.RESOLVED],
        false_positive=states[IncidentStatus.FALSE_POSITIVE],
        by_severity=levels,
        average_risk_score=round(float(avg or 0), 2),
        unassigned_incidents=unassigned,
    )
