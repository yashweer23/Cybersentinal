from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID, uuid4

from sqlalchemy import DateTime, FetchedValue, func, text
from sqlalchemy.dialects.postgresql import ENUM, JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import IncidentStatus, IndicatorType, SeverityLevel, UserRole

IPAddress = IPv4Address | IPv6Address

# The migration explicitly creates each native type once and drops it on downgrade.
USER_ROLE = ENUM(UserRole, name="user_role", create_type=False, validate_strings=True)
INCIDENT_STATUS = ENUM(
    IncidentStatus,
    name="incident_status",
    create_type=False,
    validate_strings=True,
)
SEVERITY_LEVEL = ENUM(
    SeverityLevel,
    name="severity_level",
    create_type=False,
    validate_strings=True,
)
INDICATOR_TYPE = ENUM(
    IndicatorType,
    name="indicator_type",
    create_type=False,
    validate_strings=True,
)
JSON_OBJECT = JSONB(none_as_null=True)


class UUIDPrimaryKey:
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )


class CreatedAt:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class UpdatedAt(CreatedAt):
    # Migration-owned triggers update this field for ORM and direct SQL writes alike.
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        server_onupdate=FetchedValue(),
    )
