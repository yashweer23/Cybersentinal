from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
    event,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import IndicatorType
from app.core.validation import normalize_indicator
from app.database import Base
from app.models.common import INDICATOR_TYPE, JSON_OBJECT, UUIDPrimaryKey


class ThreatIntelligence(UUIDPrimaryKey, Base):
    __tablename__ = "threat_intelligence"
    __table_args__ = (
        UniqueConstraint(
            "indicator_type", "indicator", name="uq_threat_intelligence_type_indicator"
        ),
        CheckConstraint("abuse_score BETWEEN 0 AND 100", name="abuse_score_range"),
        CheckConstraint("confidence_score BETWEEN 0 AND 100", name="confidence_score_range"),
        CheckConstraint("reports >= 0", name="reports_nonnegative"),
        CheckConstraint("expires_at > last_checked", name="cache_expiry"),
        CheckConstraint("first_seen <= last_checked", name="seen_before_checked"),
        CheckConstraint("jsonb_typeof(source) = 'array'", name="source_array"),
        CheckConstraint("jsonb_typeof(raw_response) = 'object'", name="raw_response_object"),
        CheckConstraint(
            "CASE WHEN indicator_type = 'IP' THEN indicator = host(indicator::inet) "
            "ELSE indicator = lower(btrim(indicator)) AND right(indicator, 1) <> '.' END",
            name="indicator_canonical",
        ),
    )

    indicator: Mapped[str] = mapped_column(String(253), index=True)
    indicator_type: Mapped[IndicatorType] = mapped_column(INDICATOR_TYPE)
    malicious: Mapped[bool | None] = mapped_column(Boolean, server_default=text("false"))
    abuse_score: Mapped[int | None] = mapped_column(Integer, server_default=text("0"))
    confidence_score: Mapped[Decimal | None] = mapped_column(
        Numeric(5, 2), server_default=text("0")
    )
    reports: Mapped[int | None] = mapped_column(Integer, server_default=text("0"))
    country: Mapped[str | None] = mapped_column(String(100))
    isp: Mapped[str | None] = mapped_column(String(255))
    source: Mapped[list[str]] = mapped_column(
        JSON_OBJECT,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    raw_response: Mapped[dict[str, Any]] = mapped_column(
        JSON_OBJECT,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_checked: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


@event.listens_for(ThreatIntelligence, "before_insert")
@event.listens_for(ThreatIntelligence, "before_update")
def canonicalize_indicator(mapper, connection, target: ThreatIntelligence) -> None:
    target.indicator = normalize_indicator(target.indicator, IndicatorType(target.indicator_type))
