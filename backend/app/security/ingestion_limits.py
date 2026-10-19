"""Bound event API bodies before JSON decoding, including chunked requests."""

from starlette.responses import JSONResponse

from app.core.event_validation import strict_json


class IngestionBodyLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        paths = {"/api/events/ingest", "/api/events/ingest/batch"}
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or scope.get("path", "").rstrip("/") not in paths
        ):
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        if headers.get(b"content-encoding", b"identity").lower() != b"identity":
            return await JSONResponse(
                {"detail": "Compressed event request bodies are not supported"}, status_code=415
            )(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_bytes:
                return await JSONResponse(
                    {"detail": "Event request exceeds the configured byte limit"}, status_code=413
                )(scope, receive, send)
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False
        content_type = headers.get(b"content-type", b"").split(b";", 1)[0].lower()
        if content_type != b"application/json":
            return await JSONResponse(
                {"detail": "Use Content-Type: application/json"}, status_code=415
            )(scope, receive, send)
        try:
            strict_json(body.decode("utf-8-sig"))
        except (ValueError, UnicodeError, RecursionError):
            return await JSONResponse(
                {"detail": "Request must contain valid UTF-8 JSON without duplicate keys"},
                status_code=422,
            )(scope, receive, send)

        async def buffered_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, buffered_receive, send)
