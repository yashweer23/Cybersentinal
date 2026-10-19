from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.common import UpdatedAt, UUIDPrimaryKey

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.user import User


class IncidentComment(UUIDPrimaryKey, UpdatedAt, Base):
    __tablename__ = "incident_comments"
    __table_args__ = (CheckConstraint("length(btrim(comment)) > 0", name="comment_nonempty"),)
    incident_id: Mapped[UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"),
        index=True,
    )
    user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
    )
    comment: Mapped[str] = mapped_column(Text)
    incident: Mapped[Incident] = relationship(back_populates="comments")
    user: Mapped[User | None] = relationship(back_populates="comments")
