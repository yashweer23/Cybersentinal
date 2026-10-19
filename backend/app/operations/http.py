"""ASGI request correlation and safe final error handling, without body inspection."""

import logging
import re
from time import perf_counter
from uuid import UUID, uuid4

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse

from app.operations.logging import request_id

logger = logging.getLogger("cybersentinel.http")


class CanonicalHTTPSMiddleware:
    """An explicitly configured HTTPS gateway terminates TLS before the private API.

    Only the scheme is canonicalized. Host validation remains independent; no
    client-supplied Forwarded/X-Forwarded-* value changes identity or scheme.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope["scheme"] = "https"
        return await self.app(scope, receive, send)


def correlation_id(value):
    if value and re.fullmatch(
        r"[a-fA-F0-9]{32}|[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", value
    ):
        return UUID(value).hex
    return uuid4().hex


class OperationalHTTPMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        identifier = correlation_id(Headers(scope=scope).get("x-request-id"))
        scope.setdefault("state", {})["request_id"] = identifier
        token = request_id.set(identifier)
        started, status, sent = perf_counter(), 500, False

        async def safe_send(message):
            nonlocal status, sent
            if message["type"] == "http.response.start":
                sent = True
                status = message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = identifier
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "no-referrer"
                headers["X-Frame-Options"] = "DENY"
                if status >= 400:
                    headers["Cache-Control"] = "no-store"
            await send(message)

        try:
            await self.app(scope, receive, safe_send)
        except Exception as exc:
            logger.error("Unhandled request error", extra={"error_type": type(exc).__name__})
            if sent:
                raise
            await JSONResponse(
                status_code=500,
                content={
                    "detail": "An unexpected error occurred; use the request ID when reporting it"
                },
            )(scope, receive, safe_send)
        finally:
            route = getattr(scope.get("route"), "path", "<unmatched>")
            logger.info(
                "Request completed",
                extra={
                    "method": scope["method"],
                    "route": route,
                    "status": status,
                    "duration_ms": round((perf_counter() - started) * 1000, 3),
                },
            )
            request_id.reset(token)
