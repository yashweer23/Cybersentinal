"""Input normalization shared by schemas and ORM writes. No network requests."""

import re
from ipaddress import ip_address

from app.core.enums import IndicatorType


def normalize_username(value: str) -> str:
    value = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,63}", value):
        raise ValueError("Username must be 3–64 letters, numbers, underscores, dots or hyphens")
    return value


def normalize_domain(value: str) -> str:
    # A terminal DNS dot is equivalent to the same fully qualified domain without it.
    value = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    labels = value.split(".")
    if (
        len(value) > 253
        or len(labels) < 2
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
    ):
        raise ValueError("Expected a domain name, without a URL scheme, path or port")
    try:
        ip_address(value)
    except ValueError:
        return value
    raise ValueError("Use indicator_type IP for an IP address")


def normalize_email(value: str) -> str:
    # Deliberately supports the requested .local demo addresses; no deliverability lookup.
    value = value.strip().lower()
    if value.count("@") != 1 or len(value) > 254:
        raise ValueError("Expected an email address")
    local, domain = value.rsplit("@", 1)
    if (
        not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}", local)
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
    ):
        raise ValueError("Invalid email local part")
    return f"{local}@{normalize_domain(domain)}"


def normalize_indicator(value: str, kind: IndicatorType) -> str:
    if kind == IndicatorType.IP:
        return str(ip_address(value.strip()))
    return normalize_domain(value)


def validate_password(value: str) -> str:
    # bcrypt accepts at most 72 UTF-8 bytes. Reject rather than truncate.
    if len(value) < 12 or len(value.encode("utf-8")) > 72 or "\x00" in value:
        raise ValueError("Password must be at least 12 characters and at most 72 UTF-8 bytes")
    return value
