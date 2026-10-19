"""A finding belongs to one case; its original evidence remains immutable."""

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.common import JSON_OBJECT, UUIDPrimaryKey

if TYPE_CHECKING:
    from app.models.detection_finding import DetectionFinding
    from app.models.incident import Incident


class IncidentFinding(UUIDPrimaryKey, Base):
    __tablename__ = "incident_findings"
    __table_args__ = (
        UniqueConstraint("incident_id", "detection_finding_id"),
        UniqueConstraint("detection_finding_id"),
        CheckConstraint("length(btrim(relationship_reason)) > 0", name="reason_nonempty"),
        CheckConstraint("jsonb_typeof(correlation_data) = 'object'", name="correlation_object"),
    )
    incident_id: Mapped[UUID] = mapped_column(ForeignKey("incidents.id", ondelete="RESTRICT"))
    detection_finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("detection_findings.id", ondelete="RESTRICT")
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.clock_timestamp()
    )
    relationship_reason: Mapped[str] = mapped_column(Text)
    correlation_data: Mapped[dict[str, Any]] = mapped_column(JSON_OBJECT)
    incident: Mapped["Incident"] = relationship(back_populates="finding_links")
    finding: Mapped["DetectionFinding"] = relationship()
