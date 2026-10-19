"""Incident evaluation state is independent of event and finding evidence."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class IncidentProcessing(Base):
    __tablename__ = "incident_processing"
    __table_args__ = (
        CheckConstraint("risk_input_hash ~ '^[0-9a-f]{64}$'", name="risk_hash_format"),
        CheckConstraint("policy_hash ~ '^[0-9a-f]{64}$'", name="policy_hash_format"),
        CheckConstraint("outcome IN ('LINKED', 'DEFERRED')", name="outcome_valid"),
    )
    detection_finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("detection_findings.id", ondelete="RESTRICT"), primary_key=True
    )
    risk_input_hash: Mapped[str] = mapped_column(String(64))
    policy_hash: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(16))
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    context_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
