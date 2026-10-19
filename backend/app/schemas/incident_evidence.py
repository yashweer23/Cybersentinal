from typing import Any
from uuid import UUID

from pydantic import Field

from app.schemas.common import CreatedResponse, Schema


class IncidentEvidenceCreate(Schema):
    incident_id: UUID
    security_event_id: UUID
    evidence_type: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=10000)
    evidence_data: dict[str, Any] = Field(default_factory=dict)


class IncidentEvidenceResponse(IncidentEvidenceCreate, CreatedResponse):
    pass
