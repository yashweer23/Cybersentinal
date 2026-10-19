"""Time semantics and zero filling; event aggregation remains in PostgreSQL."""

from datetime import UTC, datetime, timedelta

from app.core.errors import ServiceError
from app.schemas.dashboard import DashboardScope, TimelinePoint

PRESETS = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000, "90d": 7776000}
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def resolve_scope(query, settings, *, now=None):
    now = now or datetime.now(UTC)
    preset = None if query.start is not None else query.range or "24h"
    try:
        start = (
            query.start.astimezone(UTC) if query.start else now - timedelta(seconds=PRESETS[preset])
        )
        end = query.end.astimezone(UTC) if query.end else now
    except (OverflowError, ValueError):
        raise ServiceError(422, "Timestamps cannot be represented in UTC") from None
    if not timedelta(0) < end - start <= timedelta(days=settings.dashboard_max_range_days):
        raise ServiceError(
            422, f"Time range must be positive and at most {settings.dashboard_max_range_days} days"
        )
    return DashboardScope(start=start, end=end, preset=preset, as_of=now)


def timeline_interval(scope):
    seconds = (scope.end - scope.start).total_seconds()
    if seconds <= 3600:
        return "minute", 60
    if seconds <= 21600:
        return "15_minutes", 900
    if seconds <= 86400:
        return "hour", 3600
    return "day", 86400


def bucket_start(time, seconds):
    # UTC epoch arithmetic, consistent with PostgreSQL date_bin's origin.
    return EPOCH + ((time - EPOCH) // timedelta(seconds=seconds)) * timedelta(seconds=seconds)


def fill_timeline(scope, seconds, rows):
    points = {row["timestamp"].astimezone(UTC): row for row in rows}
    result, current = [], bucket_start(scope.start, seconds)
    while current < scope.end:
        result.append(TimelinePoint(**points.get(current, {"timestamp": current})))
        current += timedelta(seconds=seconds)
    return result


def average(value):
    return round(float(value), 2) if value is not None else None
