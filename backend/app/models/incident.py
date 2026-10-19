from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import IncidentStatus, SeverityLevel
from app.database import Base
from app.models.common import (
    INCIDENT_STATUS,
    JSON_OBJECT,
    SEVERITY_LEVEL,
    IPAddress,
    UpdatedAt,
    UUIDPrimaryKey,
)

if TYPE_CHECKING:
    from app.models.detection_rule import DetectionRule
    from app.models.incident_comment import IncidentComment
    from app.models.incident_evidence import IncidentEvidence
    from app.models.incident_finding import IncidentFinding
    from app.models.user import User


class Incident(UUIDPrimaryKey, UpdatedAt, Base):
    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_created_at", "created_at"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score_range"),
        CheckConstraint("confidence BETWEEN 0 AND 100", name="confidence_range"),
        CheckConstraint("last_seen >= first_seen", name="ordered_window"),
        CheckConstraint(
            "resolved_at IS NULL OR resolved_at >= detected_at", name="resolution_time"
        ),
        CheckConstraint(
            "ai_analysis IS NULL OR jsonb_typeof(ai_analysis) = 'object'",
            name="ai_analysis_object",
        ),
        CheckConstraint(
            "jsonb_typeof(recommended_actions) = 'array'",
            name="recommended_actions_array",
        ),
    )

    incident_id: Mapped[str] = mapped_column(String(64), unique=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    detection_rule_id: Mapped[UUID] = mapped_column(
        ForeignKey("detection_rules.id", ondelete="RESTRICT"),
        index=True,
    )
    source_ip: Mapped[IPAddress | None] = mapped_column(INET, index=True)
    username: Mapped[str | None] = mapped_column(String(255), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    severity: Mapped[SeverityLevel] = mapped_column(SEVERITY_LEVEL, index=True)
    confidence: Mapped[Decimal] = mapped_column(Numeric(5, 2))
    status: Mapped[IncidentStatus] = mapped_column(
        INCIDENT_STATUS,
        server_default=text("'OPEN'"),
        index=True,
    )
    assigned_analyst_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
    )
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    # Defaults preserve existing ORM callers; migration backfills existing rows.
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda ctx: ctx.get_current_parameters()["detected_at"]
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda ctx: ctx.get_current_parameters()["detected_at"]
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolution_summary: Mapped[str | None] = mapped_column(Text)
    risk_score_version: Mapped[str | None] = mapped_column(String(32))
    risk_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ai_analysis: Mapped[dict[str, Any] | None] = mapped_column(JSON_OBJECT)
    recommended_actions: Mapped[list[str]] = mapped_column(
        JSON_OBJECT,
        default=list,
        server_default=text("'[]'::jsonb"),
    )

    detection_rule: Mapped[DetectionRule] = relationship(back_populates="incidents")
    assigned_analyst: Mapped[User | None] = relationship(back_populates="assigned_incidents")
    evidence: Mapped[list[IncidentEvidence]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    comments: Mapped[list[IncidentComment]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    finding_links: Mapped[list[IncidentFinding]] = relationship(
        back_populates="incident", passive_deletes="all"
    )
