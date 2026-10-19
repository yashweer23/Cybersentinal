"""One current provider bundle per indicator and mode; no unbounded response history."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.common import JSON_OBJECT, UUIDPrimaryKey


class ThreatIntelligenceResult(UUIDPrimaryKey, Base):
    __tablename__ = "threat_intelligence_results"
    __table_args__ = (
        UniqueConstraint("indicator_id", "mode"),
        CheckConstraint("mode IN ('mock','live')", name="mode_valid"),
        CheckConstraint(
            "reputation_level IN ('MALICIOUS','SUSPICIOUS','NO_ADVERSE_SIGNALS','UNKNOWN')",
            name="reputation_valid",
        ),
        CheckConstraint("normalized_score BETWEEN 0 AND 100", name="score_range"),
        CheckConstraint("jsonb_typeof(payload) = 'object'", name="payload_object"),
        CheckConstraint("policy_hash ~ '^[0-9a-f]{64}$'", name="policy_hash_format"),
    )
    indicator_id: Mapped[UUID] = mapped_column(
        ForeignKey("threat_intelligence.id", ondelete="CASCADE")
    )
    mode: Mapped[str] = mapped_column(String(8))
    reputation_level: Mapped[str] = mapped_column(String(24))
    normalized_score: Mapped[int | None] = mapped_column(Integer)
    malicious: Mapped[bool | None] = mapped_column(Boolean)
    policy_hash: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_OBJECT)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class ThreatProviderState(Base):
    __tablename__ = "threat_provider_state"
    provider: Mapped[str] = mapped_column(String(64), primary_key=True)
    credential_hash: Mapped[str] = mapped_column(String(64))
    next_allowed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str] = mapped_column(String(32))
