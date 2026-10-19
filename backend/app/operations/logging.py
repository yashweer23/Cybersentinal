"""Structured operational records, with minimized request and exception details."""

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime

from pydantic import SecretStr

request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
SAFE_EXTRA = {
    "method",
    "route",
    "status",
    "duration_ms",
    "error_type",
    "environment",
    "database",
    "threat_intelligence",
    "ai_analyst",
}


class SafeJsonFormatter(logging.Formatter):
    def __init__(self, secrets=()):
        super().__init__()
        self.secrets = tuple(value for value in secrets if value)

    def redact(self, value):
        value = str(value)
        value = re.sub(
            r"(?i)postgres(?:ql)?(?:\+psycopg)?://[^\s\"'<>]+",
            "[REDACTED_DATABASE_URL]",
            value,
        )
        for secret in self.secrets:
            value = value.replace(secret, "[REDACTED]")
        value = re.sub(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]", value)
        return re.sub(
            r"(?i)\b(password|api[_-]?key|jwt[_-]?secret|access_token|refresh_token)\s*[:=]\s*[^\s,;]+",
            r"\1=[REDACTED]",
            value,
        )

    def format(self, record):
        data = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": self.redact(record.getMessage()),
            "request_id": request_id.get(),
        }
        for name in SAFE_EXTRA:
            if hasattr(record, name):
                value = getattr(record, name)
                data[name] = self.redact(value) if isinstance(value, str) else value
        if record.exc_info:
            # Exception messages/traceback locals may contain SQL parameters or provider payloads.
            data["error_type"] = record.exc_info[0].__name__
        return json.dumps(data, ensure_ascii=True, default=str)


def configure_logging(settings):
    secrets = [
        value.get_secret_value()
        for value in vars(settings).values()
        if isinstance(value, SecretStr)
    ]
    secrets.append(settings.database_url.password)
    root = logging.getLogger()
    handler = next((h for h in root.handlers if getattr(h, "cybersentinel_handler", False)), None)
    if handler is None:
        handler = logging.StreamHandler(sys.stdout)
        handler.cybersentinel_handler = True
        # Keep test instrumentation, but remove default console handlers that duplicate raw logs.
        for existing in list(root.handlers):
            if type(existing) is logging.StreamHandler:
                root.removeHandler(existing)
        root.addHandler(handler)
    handler.setFormatter(SafeJsonFormatter(secrets))
    root.setLevel(settings.log_level)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
    for name in ("httpx", "httpcore", "sqlalchemy.engine"):
        logging.getLogger(name).setLevel(logging.WARNING)
