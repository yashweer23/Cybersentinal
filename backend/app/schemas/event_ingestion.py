from typing import Any, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    Field,
    IPvAnyAddress,
    computed_field,
    field_validator,
    model_validator,
)

from app.core import event_validation as normalization
from app.schemas.common import Schema
from app.schemas.security_event import SecurityEventResponse


class EventIngestResponse(Schema):
    status: Literal["accepted", "duplicate"]
    event_id: str
    database_id: UUID
    duplicate: bool


class IngestionError(Schema):
    index: int = Field(ge=1, description="One-based input record index")
    line: int | None = Field(default=None, description="Physical JSONL line number, when available")
    code: Literal["invalid_event", "invalid_json", "record_too_large", "database_error"]
    message: str


class BatchIngestRequest(Schema):
    # Validate elements in the service so one bad event cannot reject its valid neighbors.
    events: list[Any] = Field(
        min_length=1,
        max_length=1000,
        description="Items follow SecurityEventCreate; invalid items are reported individually.",
        json_schema_extra={"items": {"$ref": "#/components/schemas/SecurityEventCreate"}},
    )


class BatchIngestResponse(Schema):
    received: int = 0
    inserted: int = 0
    duplicates: int = 0
    invalid: int = 0
    failed: int = 0
    errors: list[IngestionError] = Field(default_factory=list)
    errors_omitted: int = 0
    duration_ms: float = 0
    complete: bool = True

    @computed_field
    @property
    def valid(self) -> int:
        return self.received - self.invalid


class EventQuery(Schema):
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0, le=1000000)
    sort_by: Literal["timestamp", "created_at", "event_id"] = "timestamp"
    sort_order: Literal["asc", "desc"] = "desc"
    event_type: str | None = Field(
        default=None, max_length=64, pattern=normalization.EVENT_TYPE_PATTERN
    )
    username: str | None = Field(default=None, max_length=255)
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    service: str | None = Field(default=None, max_length=100)
    status: str | None = Field(default=None, max_length=64)
    processed: bool | None = None
    start_time: AwareDatetime | None = None
    end_time: AwareDatetime | None = None

    _trim = field_validator("username", "service", "source_ip", "destination_ip", mode="before")(
        normalization.clean_text
    )
    _type = field_validator("event_type", mode="before")(normalization.event_type)
    _status = field_validator("status", mode="before")(normalization.status)
    _host_ip = field_validator("source_ip", "destination_ip", mode="before")(normalization.host_ip)
    _time = field_validator("start_time", "end_time", mode="before")(normalization.timestamp_input)

    @model_validator(mode="after")
    def ordered_window(self):
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValueError("start_time must not be after end_time")
        return self


class EventListResponse(Schema):
    items: list[SecurityEventResponse]
    total: int
    limit: int
    offset: int


class EventStatsResponse(Schema):
    total_events: int
    processed_events: int
    unprocessed_events: int
    latest_event_timestamp: AwareDatetime | None
    event_types: dict[str, int]
