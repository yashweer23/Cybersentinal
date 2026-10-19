from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

Port = Annotated[int, Field(ge=0, le=65535)]
Score = Annotated[int, Field(ge=0, le=100)]
Confidence = Annotated[float, Field(ge=0, le=100, allow_inf_nan=False)]


def utc_now() -> datetime:
    return datetime.now(UTC)


class Schema(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid", hide_input_in_errors=True)


class CreatedResponse(Schema):
    id: UUID
    created_at: AwareDatetime


class UpdatedResponse(CreatedResponse):
    updated_at: AwareDatetime
