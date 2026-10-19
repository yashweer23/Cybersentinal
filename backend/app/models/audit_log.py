from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.common import JSON_OBJECT, IPAddress, UUIDPrimaryKey

if TYPE_CHECKING:
    from app.models.user import User


class AuditLog(UUIDPrimaryKey, Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_entity", "entity_type", "entity_id"),)

    user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
    )
    action: Mapped[str] = mapped_column(String(100))
    entity_type: Mapped[str] = mapped_column(String(100))
    # No polymorphic FK: audit records survive deletion of the described object.
    entity_id: Mapped[str] = mapped_column(String(128))
    old_value: Mapped[dict[str, Any] | None] = mapped_column(JSON_OBJECT)
    new_value: Mapped[dict[str, Any] | None] = mapped_column(JSON_OBJECT)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )
    ip_address: Mapped[IPAddress | None] = mapped_column(INET)
    user: Mapped[User | None] = relationship(back_populates="audit_logs")
