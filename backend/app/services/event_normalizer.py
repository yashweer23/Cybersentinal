"""Normalize through the shared schema and produce bounded, input-free diagnostics."""

from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from app.schemas.security_event import SecurityEventCreate


@dataclass(frozen=True)
class InputRecord:
    index: int
    value: Any = None
    line: int | None = None
    error: str | None = None
    code: str = "invalid_json"


class InvalidEvent(ValueError):
    def __init__(self, message: str, code: str = "invalid_event"):
        super().__init__(message)
        self.code = code


def normalize_event(value: Any, max_bytes: int) -> SecurityEventCreate:
    if isinstance(value, SecurityEventCreate):
        value = value.model_dump()
    try:
        event = SecurityEventCreate.model_validate(value)
    except ValidationError as exc:
        # Only schema-known field names and fixed validation messages; no input or context.
        descriptions = []
        for error in exc.errors(include_input=False, include_context=False, include_url=False)[:3]:
            first = error["loc"][0] if error["loc"] else "event"
            field = first if first in SecurityEventCreate.model_fields else "event"
            descriptions.append(f"{field}: {error['msg']}")
        raise InvalidEvent("; ".join(descriptions)) from None
    if len(event.model_dump_json().encode("utf-8")) > max_bytes:
        raise InvalidEvent("Event exceeds the configured byte limit", "record_too_large")
    return event
