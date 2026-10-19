from uuid import UUID

from pydantic import Field, field_validator

from app.schemas.common import Schema, UpdatedResponse


class IncidentCommentCreate(Schema):
    incident_id: UUID
    user_id: UUID | None = None
    comment: str = Field(min_length=1, max_length=10000)

    @field_validator("comment")
    @classmethod
    def nonblank_comment(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("comment must not be blank")
        return value


class IncidentCommentResponse(IncidentCommentCreate, UpdatedResponse):
    pass
