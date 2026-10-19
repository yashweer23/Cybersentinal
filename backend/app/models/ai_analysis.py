"""Append-only analysis history, independent of authoritative incident fields."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.common import JSON_OBJECT, UUIDPrimaryKey


class AIAnalysis(UUIDPrimaryKey, Base):
    __tablename__ = "ai_analyses"
    __table_args__ = (
        Index("ix_ai_analyses_incident_generated", "incident_id", "generated_at"),
        Index("ix_ai_analyses_cache", "incident_id", "context_hash", "config_hash"),
        CheckConstraint("analysis_mode IN ('AI','FALLBACK')", name="mode_valid"),
        CheckConstraint("context_hash ~ '^[0-9a-f]{64}$'", name="context_hash_format"),
        CheckConstraint("config_hash ~ '^[0-9a-f]{64}$'", name="config_hash_format"),
        CheckConstraint("jsonb_typeof(response) = 'object'", name="response_object"),
    )
    analysis_id: Mapped[str] = mapped_column(String(64), unique=True)
    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id", ondelete="RESTRICT"))
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str | None] = mapped_column(String(100))
    analysis_mode: Mapped[str] = mapped_column(String(16))
    context_version: Mapped[str] = mapped_column(String(16))
    context_hash: Mapped[str] = mapped_column(String(64))
    config_hash: Mapped[str] = mapped_column(String(64))
    response: Mapped[dict[str, Any]] = mapped_column(JSON_OBJECT)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.clock_timestamp()
    )
    generated_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
