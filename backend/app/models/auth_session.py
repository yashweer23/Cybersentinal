from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.common import CreatedAt, UUIDPrimaryKey

if TYPE_CHECKING:
    from app.models.user import User


class AuthSession(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "auth_sessions"
    __table_args__ = (
        CheckConstraint("refresh_token_hash ~ '^[0-9a-f]{64}$'", name="token_hash_format"),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
    )

    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    refresh_token_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    user: Mapped[User] = relationship(back_populates="auth_sessions")
