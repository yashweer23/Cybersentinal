"""Bounded SQL queries. A transaction-level advisory lock serializes chronological runs."""

from sqlalchemy import func, select, tuple_, update
from sqlalchemy.dialects.postgresql import insert

from app.core.enums import SeverityLevel
from app.core.errors import ServiceError
from app.models import DetectionFinding, DetectionRule, SecurityEvent
from app.schemas.detection import DetectionStats


def acquire_lock(session):
    # Also taken by rule updates. Automatically released on commit/rollback/disconnect.
    return session.scalar(select(func.pg_try_advisory_xact_lock(1129530451, 6)))


def pending_count(session):
    return session.scalar(
        select(func.count()).select_from(SecurityEvent).where(SecurityEvent.processed.is_(False))
    )


def fetch_batch(session, size, cutoff, cursor=None, replay=False, claim=True):
    query = select(SecurityEvent).where(SecurityEvent.created_at <= cutoff)
    if not replay:
        query = query.where(SecurityEvent.processed.is_(False))
    if cursor:
        query = query.where(tuple_(SecurityEvent.timestamp, SecurityEvent.id) > tuple_(*cursor))
    query = query.order_by(SecurityEvent.timestamp, SecurityEvent.id).limit(size)
    if claim:
        query = query.with_for_update(skip_locked=True)
    return list(session.scalars(query))


def get_events_in_window(session, start, end, *, event_types=None, entities=None, limit=50000):
    query = select(SecurityEvent).where(
        SecurityEvent.timestamp >= start, SecurityEvent.timestamp <= end
    )
    if event_types is not None:
        query = query.where(SecurityEvent.event_type.in_(event_types))
    for column, values in (entities or {}).items():
        query = query.where(getattr(SecurityEvent, column).in_(values))
    rows = list(
        session.scalars(query.order_by(SecurityEvent.timestamp, SecurityEvent.id).limit(limit + 1))
    )
    if len(rows) > limit:
        raise ServiceError(
            422, "Detection context exceeds its limit; reduce batch size or tune the context limit"
        )
    return rows


def load_context(session, rule, config, batch, limit, *, recheck_processed=True):
    relevant = [event for event in batch if rule.applicable(event, config)]
    if not relevant:
        return [], set()
    columns = (config.group_by,) if rule.rule_id == "CS-010" else rule.entity_columns
    entities = {key: list({getattr(event, key) for event in relevant}) for key in columns}
    start, end = min(e.timestamp for e in relevant), max(e.timestamp for e in relevant)
    rows = get_events_in_window(
        session,
        start - rule.lookback(config),
        end + rule.lookahead(config) if recheck_processed else end,
        event_types=rule.event_types(config),
        entities=entities,
        limit=limit,
    )
    selected = {e.id for e in relevant}
    # Revisit processed anchors affected by a newly arrived earlier event.
    candidates = {
        e.id
        for e in rows
        if e.id in selected or (recheck_processed and e.processed and e.timestamp >= start)
    }
    return rows, candidates


def persist_findings(session, values):
    if not values:
        return 0
    # Verify bounded references once per batch rather than querying once per finding/event.
    identifiers = sorted({item for row in values for item in row["evidence_event_ids"]})
    for offset in range(0, len(identifiers), 5000):
        wanted = set(identifiers[offset : offset + 5000])
        actual = set(
            session.scalars(
                select(SecurityEvent.event_id).where(SecurityEvent.event_id.in_(wanted))
            )
        )
        if wanted != actual:
            raise ValueError("Finding evidence references missing security events")
    return len(
        session.scalars(
            insert(DetectionFinding)
            .values(values)
            .on_conflict_do_nothing(index_elements=[DetectionFinding.fingerprint])
            .returning(DetectionFinding.id)
        ).all()
    )


def mark_processed(session, batch):
    session.execute(
        update(SecurityEvent)
        .where(SecurityEvent.id.in_([e.id for e in batch]))
        .values(processed=True)
    )


def get_finding(session, finding_id):
    return session.scalar(select(DetectionFinding).where(DetectionFinding.finding_id == finding_id))


def list_findings(session, filters):
    clauses = []
    for key in ("severity", "source_ip", "username"):
        value = getattr(filters, key)
        if value is not None:
            clauses.append(getattr(DetectionFinding, key) == value)
    if filters.rule_id:
        clauses.append(DetectionRule.rule_id == filters.rule_id)
    if filters.start_time:
        clauses.append(DetectionFinding.last_seen >= filters.start_time)
    if filters.end_time:
        clauses.append(DetectionFinding.last_seen <= filters.end_time)
    query = select(DetectionFinding).join(DetectionRule).where(*clauses)
    total = session.scalar(
        select(func.count()).select_from(DetectionFinding).join(DetectionRule).where(*clauses)
    )
    rows = session.scalars(
        query.order_by(DetectionFinding.last_seen.desc(), DetectionFinding.id)
        .limit(filters.limit)
        .offset(filters.offset)
    ).all()
    return rows, total


def detection_stats(session):
    rows = session.execute(
        select(DetectionRule.rule_id, DetectionFinding.severity, func.count())
        .join(DetectionFinding, DetectionFinding.detection_rule_id == DetectionRule.id)
        .group_by(DetectionRule.rule_id, DetectionFinding.severity)
    )
    by_rule, severity, total = {}, {value.value: 0 for value in SeverityLevel}, 0
    for rule_id, level, count in rows:
        by_rule[rule_id] = by_rule.get(rule_id, 0) + count
        severity[level.value] += count
        total += count
    return DetectionStats(
        total_findings=total,
        by_rule=by_rule,
        by_severity=severity,
        unprocessed_events=pending_count(session),
    )
