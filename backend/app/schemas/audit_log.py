from typing import Any
from uuid import UUID

from pydantic import AwareDatetime, Field, IPvAnyAddress

from app.schemas.common import Schema, utc_now


class AuditLogCreate(Schema):
    user_id: UUID | None = None
    action: str = Field(min_length=1, max_length=100)
    entity_type: str = Field(min_length=1, max_length=100)
    entity_id: str = Field(min_length=1, max_length=128)
    old_value: dict[str, Any] | None = None
    new_value: dict[str, Any] | None = None
    timestamp: AwareDatetime = Field(default_factory=utc_now)
    ip_address: IPvAnyAddress | None = None


class AuditLogResponse(AuditLogCreate):
    id: UUID
