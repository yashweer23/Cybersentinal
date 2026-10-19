"""Parameterized PostgreSQL access. The ingestion service owns commit/rollback."""

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import SecurityEvent
from app.schemas.event_ingestion import EventQuery, EventStatsResponse
from app.schemas.security_event import SecurityEventCreate


def insert_batch(session: Session, events: list[SecurityEventCreate]) -> dict:
    if not events:
        return {}
    # First valid occurrence wins. Never overwrite an existing event or processed flag.
    unique = {}
    for event in events:
        unique.setdefault(event.event_id, event)
    values = [dict(event.model_dump(), processed=False) for event in unique.values()]
    statement = (
        insert(SecurityEvent)
        .values(values)
        .on_conflict_do_nothing(index_elements=[SecurityEvent.event_id])
        .returning(SecurityEvent.event_id, SecurityEvent.id)
    )
    return dict(session.execute(statement).all())


def get_event(session: Session, event_id: str) -> SecurityEvent | None:
    return session.scalar(select(SecurityEvent).where(SecurityEvent.event_id == event_id))


def list_events(session: Session, filters: EventQuery):
    clauses = []
    for key in (
        "event_type",
        "username",
        "source_ip",
        "destination_ip",
        "service",
        "status",
        "processed",
    ):
        value = getattr(filters, key)
        if value is not None:
            clauses.append(getattr(SecurityEvent, key) == value)
    if filters.start_time is not None:
        clauses.append(SecurityEvent.timestamp >= filters.start_time)
    if filters.end_time is not None:
        clauses.append(SecurityEvent.timestamp <= filters.end_time)
    total = session.scalar(select(func.count()).select_from(SecurityEvent).where(*clauses))
    columns = {
        "timestamp": SecurityEvent.timestamp,
        "created_at": SecurityEvent.created_at,
        "event_id": SecurityEvent.event_id,
    }
    column = columns[filters.sort_by]
    order = column.desc() if filters.sort_order == "desc" else column.asc()
    items = session.scalars(
        select(SecurityEvent)
        .where(*clauses)
        .order_by(order, SecurityEvent.id)
        .limit(filters.limit)
        .offset(filters.offset)
    ).all()
    return items, total


def event_stats(session: Session) -> EventStatsResponse:
    rows = session.execute(
        select(
            SecurityEvent.event_type,
            SecurityEvent.processed,
            func.count(),
            func.max(SecurityEvent.timestamp),
        ).group_by(SecurityEvent.event_type, SecurityEvent.processed)
    ).all()
    types, total, processed, latest = {}, 0, 0, None
    for event_type, done, count, timestamp in rows:
        types[event_type] = types.get(event_type, 0) + count
        total += count
        processed += count if done else 0
        latest = timestamp if latest is None or timestamp > latest else latest
    return EventStatsResponse(
        total_events=total,
        processed_events=processed,
        unprocessed_events=total - processed,
        latest_event_timestamp=latest,
        event_types=dict(sorted(types.items())),
    )
