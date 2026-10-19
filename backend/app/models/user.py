from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, DateTime, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.core.enums import UserRole
from app.core.validation import normalize_email, normalize_username
from app.database import Base
from app.models.common import USER_ROLE, UpdatedAt, UUIDPrimaryKey

if TYPE_CHECKING:
    from app.models.audit_log import AuditLog
    from app.models.auth_session import AuthSession
    from app.models.incident import Incident
    from app.models.incident_comment import IncidentComment


class User(UUIDPrimaryKey, UpdatedAt, Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("username = lower(btrim(username))", name="username_normalized"),
        CheckConstraint("email = lower(btrim(email))", name="email_normalized"),
        CheckConstraint("length(username) BETWEEN 3 AND 64", name="username_length"),
        CheckConstraint("length(hashed_password) >= 20", name="password_hash_length"),
    )

    username: Mapped[str] = mapped_column(String(64), unique=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str | None] = mapped_column(String(150))
    role: Mapped[UserRole] = mapped_column(USER_ROLE, server_default=text("'VIEWER'"))
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    assigned_incidents: Mapped[list[Incident]] = relationship(
        back_populates="assigned_analyst",
        passive_deletes=True,
    )
    comments: Mapped[list[IncidentComment]] = relationship(
        back_populates="user",
        passive_deletes=True,
    )
    audit_logs: Mapped[list[AuditLog]] = relationship(
        back_populates="user",
        passive_deletes=True,
    )
    auth_sessions: Mapped[list[AuthSession]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @validates("username")
    def validate_username(self, key: str, value: str) -> str:
        return normalize_username(value)

    @validates("email")
    def validate_email(self, key: str, value: str) -> str:
        return normalize_email(value)
