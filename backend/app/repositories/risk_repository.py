"""Bounded finding/evidence queries and version-scoped risk persistence."""

from datetime import timedelta

from sqlalchemy import case, func, literal, literal_column, select, tuple_
from sqlalchemy.dialects.postgresql import JSONB, insert

from app.core.enums import SeverityLevel
from app.core.errors import ServiceError
from app.models import DetectionFinding, DetectionRule, SecurityEvent
from app.models.risk_assessment import RiskAssessment
from app.risk.config import SCORE_VERSION
from app.schemas.risk import RiskStats


def acquire_lock(session):
    return session.scalar(select(func.pg_try_advisory_xact_lock(1129530451, 7)))


def finding_clauses(options, cutoff):
    clauses = [DetectionFinding.created_at <= cutoff]
    if options.finding:
        clauses.append(DetectionFinding.finding_id == options.finding)
    if options.rule:
        clauses.append(DetectionRule.rule_id == options.rule)
    return clauses


def has_score():
    return (
        select(RiskAssessment.id)
        .where(
            RiskAssessment.detection_finding_id == DetectionFinding.id,
            RiskAssessment.score_version == SCORE_VERSION,
        )
        .exists()
    )


def count_findings(session, options, cutoff, *, scored):
    return session.scalar(
        select(func.count())
        .select_from(DetectionFinding)
        .join(DetectionRule)
        .where(*finding_clauses(options, cutoff), has_score() == scored)
    )


def fetch_batch(session, options, cutoff, size, cursor=None):
    query = select(DetectionFinding).join(DetectionRule).where(*finding_clauses(options, cutoff))
    if not options.rescore:
        query = query.where(~has_score())
    if cursor:
        query = query.where(
            tuple_(DetectionFinding.created_at, DetectionFinding.id) > tuple_(*cursor)
        )
    # The advisory lock serializes risk batches; avoids locking the nullable joined rule load.
    return list(
        session.scalars(
            query.order_by(DetectionFinding.created_at, DetectionFinding.id).limit(size)
        )
    )


def event_projection():
    """Project only scoring fields; never load large unrelated JSON log payloads."""
    data = SecurityEvent.raw_data
    fields = [literal_column("'sensitive'"), data["sensitive"] == literal(True, JSONB)]
    for key in ("endpoint", "resource", "path"):
        # These keys are fixed source literals, never caller-supplied SQL identifiers.
        fields.extend(
            [
                literal_column("'" + key + "'"),
                case(
                    (func.jsonb_typeof(data[key]) == "string", func.left(data[key].astext, 255)),
                    else_=None,
                ),
            ]
        )
    return select(
        SecurityEvent.id,
        SecurityEvent.event_id,
        SecurityEvent.timestamp,
        SecurityEvent.source_ip,
        SecurityEvent.destination_ip,
        SecurityEvent.username,
        SecurityEvent.event_type,
        SecurityEvent.service,
        SecurityEvent.destination_port,
        SecurityEvent.status,
        func.jsonb_build_object(*fields).label("raw_data"),
    )


def evidence_context(session, findings, config, limit, cutoff):
    identifiers = set()
    for finding in findings:
        ids = finding.evidence_event_ids
        if isinstance(ids, list) and len(ids) <= 200:
            identifiers.update(x for x in ids if isinstance(x, str) and len(x) <= 128)
    events = {}
    identifiers = sorted(identifiers)
    for offset in range(0, len(identifiers), 5000):
        for row in session.execute(
            event_projection().where(
                SecurityEvent.event_id.in_(identifiers[offset : offset + 5000])
            )
        ):
            events[row.event_id] = row
    auth = [f for f in findings if f.rule.rule_id in {"CS-001", "CS-002"}]
    pairs = set()
    for finding in auth:
        users = (
            {
                events[key].username
                for key in finding.evidence_event_ids
                if isinstance(key, str) and key in events
            }
            if isinstance(finding.evidence_event_ids, list)
            and len(finding.evidence_event_ids) <= 200
            else set()
        )
        if finding.username:
            users.add(finding.username)
        listed = (
            finding.evidence_data.get("usernames", [])
            if isinstance(finding.evidence_data, dict)
            else []
        )
        if isinstance(listed, list) and len(listed) <= 200:
            users.update(x for x in listed if isinstance(x, str) and len(x) <= 255)
        if finding.source_ip:
            pairs.update((str(finding.source_ip), user) for user in users if user)
    successes = []
    if pairs:
        # One bounded context query per chunk, never one per evidence event.
        pairs = sorted(pairs)
        for offset in range(0, len(pairs), 2000):
            rows = list(
                session.execute(
                    event_projection()
                    .where(
                        SecurityEvent.event_type == "LOGIN_SUCCESS",
                        SecurityEvent.status.in_(["success", "successful", "allowed"]),
                        SecurityEvent.created_at <= cutoff,
                        SecurityEvent.timestamp >= min(f.last_seen for f in auth),
                        SecurityEvent.timestamp
                        <= max(f.last_seen for f in auth)
                        + timedelta(seconds=config.success_lookahead_seconds),
                        tuple_(SecurityEvent.source_ip, SecurityEvent.username).in_(
                            pairs[offset : offset + 2000]
                        ),
                    )
                    .order_by(SecurityEvent.timestamp, SecurityEvent.id)
                    .limit(limit + 1)
                )
            )
            successes.extend(rows)
            if len(successes) > limit:
                raise ServiceError(
                    422, "Risk authentication context limit exceeded; reduce batch size"
                )
    return events, successes


def existing_assessments(session, findings):
    return {
        row.detection_finding_id: row
        for row in session.scalars(
            select(RiskAssessment).where(
                RiskAssessment.detection_finding_id.in_([f.id for f in findings]),
                RiskAssessment.score_version == SCORE_VERSION,
            )
        )
    }


def persist(session, values, *, rescore):
    if not values:
        return
    query = insert(RiskAssessment).values(values)
    if rescore:
        immutable = {"id", "assessment_id", "created_at", "detection_finding_id", "score_version"}
        query = query.on_conflict_do_update(
            constraint="uq_risk_finding_version",
            set_={key: getattr(query.excluded, key) for key in values[0] if key not in immutable},
        )
    else:
        query = query.on_conflict_do_nothing(constraint="uq_risk_finding_version")
    # Rows are serialized by the transaction lock. RETURNING verifies reported writes.
    return len(session.scalars(query.returning(RiskAssessment.id)).all())


def list_assessments(session, filters):
    clauses = [RiskAssessment.score_version == filters.score_version]
    for key in ("risk_level",):
        if getattr(filters, key) is not None:
            clauses.append(getattr(RiskAssessment, key) == getattr(filters, key))
    for key in ("source_ip", "username", "finding_id"):
        if getattr(filters, key) is not None:
            clauses.append(getattr(DetectionFinding, key) == getattr(filters, key))
    if filters.rule_id:
        clauses.append(DetectionRule.rule_id == filters.rule_id)
    if filters.minimum_score is not None:
        clauses.append(RiskAssessment.risk_score >= filters.minimum_score)
    if filters.maximum_score is not None:
        clauses.append(RiskAssessment.risk_score <= filters.maximum_score)
    if filters.start_time:
        clauses.append(RiskAssessment.calculated_at >= filters.start_time)
    if filters.end_time:
        clauses.append(RiskAssessment.calculated_at <= filters.end_time)
    query = select(RiskAssessment).join(DetectionFinding).join(DetectionRule).where(*clauses)
    total = session.scalar(
        select(func.count())
        .select_from(RiskAssessment)
        .join(DetectionFinding)
        .join(DetectionRule)
        .where(*clauses)
    )
    return list(
        session.scalars(
            query.order_by(
                RiskAssessment.risk_score.desc(),
                RiskAssessment.calculated_at.desc(),
                RiskAssessment.id,
            )
            .offset(filters.offset)
            .limit(filters.limit)
        )
    ), total


def stats(session, version=SCORE_VERSION):
    count, average, highest = session.execute(
        select(
            func.count(), func.avg(RiskAssessment.risk_score), func.max(RiskAssessment.risk_score)
        ).where(RiskAssessment.score_version == version)
    ).one()
    levels = {x.value: 0 for x in SeverityLevel}
    levels.update(
        {
            level.value: total
            for level, total in session.execute(
                select(RiskAssessment.risk_level, func.count())
                .where(RiskAssessment.score_version == version)
                .group_by(RiskAssessment.risk_level)
            )
        }
    )
    return RiskStats(
        score_version=version,
        total_assessments=count,
        average_score=round(float(average or 0), 2),
        highest_score=highest or 0,
        by_level=levels,
    )
