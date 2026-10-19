"""Immutable rule matches, distinct from future incident cases."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import SeverityLevel
from app.database import Base
from app.models.common import JSON_OBJECT, SEVERITY_LEVEL, CreatedAt, IPAddress, UUIDPrimaryKey
from app.models.detection_rule import DetectionRule


class DetectionFinding(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "detection_findings"
    __table_args__ = (
        CheckConstraint("confidence BETWEEN 0 AND 100", name="confidence_range"),
        CheckConstraint("event_count > 0", name="positive_event_count"),
        CheckConstraint("last_seen >= first_seen", name="ordered_window"),
        CheckConstraint("fingerprint ~ '^[0-9a-f]{64}$'", name="fingerprint_format"),
        CheckConstraint("jsonb_typeof(evidence_event_ids) = 'array'", name="evidence_array"),
        CheckConstraint("jsonb_typeof(evidence_data) = 'object'", name="evidence_object"),
        Index("ix_detection_findings_rule_seen", "detection_rule_id", "last_seen"),
        Index("ix_detection_findings_last_seen", "last_seen"),
        Index("ix_detection_findings_severity", "severity"),
        Index("ix_detection_findings_source_ip", "source_ip"),
        Index("ix_detection_findings_username", "username"),
    )
    finding_id: Mapped[str] = mapped_column(String(64), unique=True)
    detection_rule_id: Mapped[UUID] = mapped_column(
        ForeignKey("detection_rules.id", ondelete="RESTRICT")
    )
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[SeverityLevel] = mapped_column(SEVERITY_LEVEL)
    confidence: Mapped[int] = mapped_column(Integer)
    source_ip: Mapped[IPAddress | None] = mapped_column(INET)
    username: Mapped[str | None] = mapped_column(String(255))
    primary_event_id: Mapped[UUID] = mapped_column(
        ForeignKey("security_events.id", ondelete="RESTRICT")
    )
    evidence_event_ids: Mapped[list[str]] = mapped_column(JSON_OBJECT)
    evidence_data: Mapped[dict[str, Any]] = mapped_column(JSON_OBJECT)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(Integer)
    entity_key: Mapped[str] = mapped_column(String(640))
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    rule: Mapped[DetectionRule] = relationship(lazy="joined")
