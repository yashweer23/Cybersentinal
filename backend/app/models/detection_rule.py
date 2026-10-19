from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, CheckConstraint, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import SeverityLevel
from app.database import Base
from app.models.common import JSON_OBJECT, SEVERITY_LEVEL, UpdatedAt, UUIDPrimaryKey

if TYPE_CHECKING:
    from app.models.incident import Incident


class DetectionRule(UUIDPrimaryKey, UpdatedAt, Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        CheckConstraint("jsonb_typeof(configuration) = 'object'", name="configuration_object"),
    )

    rule_id: Mapped[str] = mapped_column(String(32), unique=True)
    name: Mapped[str] = mapped_column(String(150))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[SeverityLevel] = mapped_column(SEVERITY_LEVEL)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    configuration: Mapped[dict[str, Any]] = mapped_column(
        JSON_OBJECT,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    incidents: Mapped[list[Incident]] = relationship(
        back_populates="detection_rule",
        passive_deletes="all",
    )
