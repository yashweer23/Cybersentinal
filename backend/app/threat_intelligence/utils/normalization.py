from datetime import UTC, datetime
from ipaddress import ip_address


def integer(value, *, low=0, high=2147483647):
    return value if type(value) is int and low <= value <= high else None


def string(value, limit=255):
    return value[:limit] if isinstance(value, str) else None


def timestamp(value):
    try:
        if type(value) in {int, float}:
            return datetime.fromtimestamp(value, UTC)
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.astimezone(UTC) if parsed.tzinfo else None
    except (ValueError, OverflowError, OSError):
        pass
    return None


def same_ip(value, target):
    try:
        return str(ip_address(value)) == target
    except (ValueError, TypeError):
        return False


def tags(values):
    if not isinstance(values, list):
        return []
    return sorted({value[:100] for value in values[:100] if isinstance(value, str)})


def redact(value, secrets=(), depth=0):
    """Preserve bounded provider JSON, omitting credential fields and known key values."""
    if depth > 30:
        return "[depth limit]"
    if isinstance(value, dict):
        return {
            redact(str(k), secrets): redact(v, secrets, depth + 1)
            for k, v in value.items()
            if not any(
                word in str(k).lower().replace("-", "_")
                for word in ("api_key", "apikey", "authorization", "password", "secret", "token")
            )
        }
    if isinstance(value, list):
        return [redact(v, secrets, depth + 1) for v in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[redacted]")
    return value
