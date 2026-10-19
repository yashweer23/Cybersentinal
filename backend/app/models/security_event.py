from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    FetchedValue,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.common import JSON_OBJECT, CreatedAt, IPAddress, UUIDPrimaryKey

if TYPE_CHECKING:
    from app.models.incident_evidence import IncidentEvidence


class SecurityEvent(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_pending_order", "processed", "timestamp", "id"),
        Index("ix_security_events_type_time", "event_type", "timestamp"),
        Index("ix_security_events_source_time", "source_ip", "timestamp"),
        Index("ix_security_events_user_time", "username", "timestamp"),
        CheckConstraint("source_port BETWEEN 0 AND 65535", name="source_port_range"),
        CheckConstraint("destination_port BETWEEN 0 AND 65535", name="destination_port_range"),
        CheckConstraint("jsonb_typeof(raw_data) = 'object'", name="raw_data_object"),
        CheckConstraint("ingestion_sequence > 0", name="ingestion_sequence_positive"),
    )

    event_id: Mapped[str] = mapped_column(String(128), unique=True)
    # Migration-owned trigger allocates in serialized writer order; UUID remains the PK.
    ingestion_sequence: Mapped[int] = mapped_column(
        BigInteger, unique=True, server_default=FetchedValue()
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[IPAddress] = mapped_column(INET, index=True)
    destination_ip: Mapped[IPAddress | None] = mapped_column(INET)
    # Logged account names describe monitored systems, not necessarily our analyst accounts.
    username: Mapped[str | None] = mapped_column(String(255), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    service: Mapped[str | None] = mapped_column(String(100))
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    country: Mapped[str | None] = mapped_column(String(100))
    device: Mapped[str | None] = mapped_column(String(255))
    user_agent: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(64))
    raw_data: Mapped[dict[str, Any]] = mapped_column(
        JSON_OBJECT,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    processed: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), index=True)

    evidence: Mapped[list[IncidentEvidence]] = relationship(
        back_populates="security_event",
        passive_deletes="all",
    )
