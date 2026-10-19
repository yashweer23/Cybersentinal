"""Canonical event fields shared by ingestion schemas and query filters."""

import json
import re
from datetime import UTC, datetime

EVENT_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
EVENT_TYPE_PATTERN = r"^[A-Z][A-Z0-9_]{0,63}$"


def clean_text(value):
    if isinstance(value, str):
        if "\x00" in value:
            raise ValueError("NUL characters are not supported")
        try:
            value.encode("utf-8")
        except UnicodeError:
            raise ValueError("Text must contain valid Unicode") from None
        return value.strip()
    return value


def event_type(value):
    value = clean_text(value)
    return value.upper() if isinstance(value, str) else value


def status(value):
    value = clean_text(value)
    return value.lower() if isinstance(value, str) else value


def event_id(value: str) -> str:
    if not re.fullmatch(EVENT_ID_PATTERN, value):
        raise ValueError(
            "Use an event ID with letters, digits, dots, colons, underscores or hyphens"
        )
    return value


def utc_timestamp(value: datetime) -> datetime:
    return value.astimezone(UTC)


def timestamp_input(value):
    value = clean_text(value)
    if isinstance(value, (int, float, bool)) or (
        isinstance(value, str) and not re.match(r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:", value)
    ):
        raise ValueError("Use an ISO-8601 timestamp with a timezone")
    return value


def host_ip(value):
    if isinstance(value, (int, float, bool)) or (value is not None and "%" in str(value)):
        raise ValueError("Use an IPv4 or IPv6 host address without a scope ID")
    return clean_text(value)


def strict_json(value):
    def constant(_):
        raise ValueError("Non-finite JSON numbers are not supported")

    def object_pairs(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("Duplicate JSON object keys are not supported")
            result[key] = item
        return result

    result = json.loads(value, parse_constant=constant, object_pairs_hook=object_pairs)
    pending = [(result, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 64:
            raise ValueError("JSON document nesting must not exceed 64 levels")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return result


def validate_json_object(value: dict) -> dict:
    """Reject values PostgreSQL JSONB cannot store without altering the supplied object."""

    def walk(item, depth=0):
        if depth > 32:
            raise ValueError("raw_data nesting must not exceed 32 levels")
        if isinstance(item, dict):
            for key, nested in item.items():
                if not isinstance(key, str):
                    raise ValueError("raw_data keys must be strings")
                walk(key, depth + 1)
                walk(nested, depth + 1)
        elif isinstance(item, list):
            for nested in item:
                walk(nested, depth + 1)
        elif isinstance(item, str):
            clean_text(item)  # Validate Unicode/NUL, but do not trim raw values.
        elif isinstance(item, int) and not isinstance(item, bool) and item.bit_length() > 4096:
            raise ValueError("raw_data integer is too large")

    walk(value)
    try:
        json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise ValueError("raw_data must contain finite, JSON-serializable values") from None
    return value
