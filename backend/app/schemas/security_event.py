from typing import Any

from pydantic import AwareDatetime, Field, IPvAnyAddress, field_validator

from app.core import event_validation as normalization
from app.schemas.common import CreatedResponse, Port, Schema


class SecurityEventCreate(Schema):
    # Supplied by the upstream producer, providing a stable deduplication key.
    event_id: str = Field(min_length=1, max_length=128)
    timestamp: AwareDatetime
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress | None = None
    username: str | None = Field(default=None, max_length=255)
    event_type: str = Field(min_length=1, max_length=64, pattern=normalization.EVENT_TYPE_PATTERN)
    service: str | None = Field(default=None, max_length=100)
    source_port: Port | None = None
    destination_port: Port | None = None
    country: str | None = Field(default=None, max_length=100)
    device: str | None = Field(default=None, max_length=255)
    user_agent: str | None = Field(default=None, max_length=4096)
    status: str = Field(min_length=1, max_length=64)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    _trim = field_validator(
        "event_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "username",
        "service",
        "country",
        "device",
        "user_agent",
        mode="before",
    )(normalization.clean_text)
    _type = field_validator("event_type", mode="before")(normalization.event_type)
    _status = field_validator("status", mode="before")(normalization.status)
    _id = field_validator("event_id")(normalization.event_id)
    _utc = field_validator("timestamp")(normalization.utc_timestamp)
    _raw = field_validator("raw_data")(normalization.validate_json_object)

    _host_ip = field_validator("source_ip", "destination_ip", mode="before")(normalization.host_ip)

    @field_validator("source_port", "destination_port", mode="before")
    @classmethod
    def reject_boolean_port(cls, value):
        if isinstance(value, bool):
            raise ValueError("Ports must be integers between 0 and 65535")
        return value

    _timestamp_input = field_validator("timestamp", mode="before")(normalization.timestamp_input)


class SecurityEventResponse(SecurityEventCreate, CreatedResponse):
    processed: bool
