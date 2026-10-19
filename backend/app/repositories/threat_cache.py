from datetime import datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.enums import IndicatorType
from app.core.validation import normalize_indicator
from app.models import ThreatIntelligence
from app.schemas.common import utc_now
from app.schemas.threat_intelligence import ThreatIntelligenceCreate


def get_cached_indicator(
    session: Session,
    indicator: str,
    kind: IndicatorType,
    *,
    at: datetime | None = None,
) -> ThreatIntelligence | None:
    return session.scalar(
        select(ThreatIntelligence).where(
            ThreatIntelligence.indicator_type == kind,
            ThreatIntelligence.indicator == normalize_indicator(indicator, kind),
            ThreatIntelligence.expires_at > (at or utc_now()),
        )
    )


def store_cached_indicator(
    session: Session,
    entry: ThreatIntelligenceCreate,
) -> ThreatIntelligence:
    """Upsert one cache identity, retaining its UUID and first observation.

    The caller owns the transaction. Older responses cannot overwrite newer ones.
    No threat-intelligence provider is called here.
    """
    statement = insert(ThreatIntelligence).values(**entry.model_dump())
    replacements = {
        field: getattr(statement.excluded, field)
        for field in type(entry).model_fields
        if field not in {"indicator", "indicator_type", "first_seen"}
    }
    statement = statement.on_conflict_do_update(
        constraint="uq_threat_intelligence_type_indicator",
        set_=replacements,
        where=statement.excluded.last_checked >= ThreatIntelligence.last_checked,
    )
    session.execute(statement)
    return session.scalars(
        select(ThreatIntelligence)
        .where(
            ThreatIntelligence.indicator == entry.indicator,
            ThreatIntelligence.indicator_type == entry.indicator_type,
        )
        .execution_options(populate_existing=True)
    ).one()
