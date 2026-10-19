from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.common import JSON_OBJECT, CreatedAt, UUIDPrimaryKey

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.security_event import SecurityEvent


class IncidentEvidence(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "incident_evidence"
    __table_args__ = (
        UniqueConstraint("incident_id", "security_event_id", "evidence_type"),
        CheckConstraint("jsonb_typeof(evidence_data) = 'object'", name="evidence_data_object"),
    )

    incident_id: Mapped[UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"),
        index=True,
    )
    security_event_id: Mapped[UUID] = mapped_column(
        ForeignKey("security_events.id", ondelete="RESTRICT"),
        index=True,
    )
    detection_finding_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("detection_findings.id", ondelete="RESTRICT"), index=True
    )
    evidence_type: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text)
    evidence_data: Mapped[dict[str, Any]] = mapped_column(
        JSON_OBJECT,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    incident: Mapped[Incident] = relationship(back_populates="evidence")
    security_event: Mapped[SecurityEvent] = relationship(back_populates="evidence")
