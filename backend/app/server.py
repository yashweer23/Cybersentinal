"""Container entrypoint: validated settings, one worker, no reload, bounded shutdown."""

import json
import sys

from pydantic import ValidationError
from pydantic_settings import SettingsError

from app.config import get_settings
from app.operations.logging import configure_logging


def main():
    try:
        settings = get_settings()
    except (ValidationError, SettingsError) as exc:
        fields = (
            sorted({str(e["loc"][0]) for e in exc.errors() if e["loc"]})
            if isinstance(exc, ValidationError)
            else []
        )
        print(
            json.dumps(
                {
                    "level": "ERROR",
                    "message": "Invalid configuration; check .env and the operations guide",
                    "fields": fields,
                }
            ),
            file=sys.stderr,
        )
        return 1
    configure_logging(settings)
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.server_host,
        port=settings.server_port,
        workers=settings.server_workers,
        reload=False,
        log_config=None,
        log_level=settings.log_level.lower(),
        access_log=False,
        server_header=False,
        proxy_headers=settings.proxy_headers_enabled,
        forwarded_allow_ips=",".join(settings.forwarded_allow_ips),
        timeout_keep_alive=5,
        timeout_graceful_shutdown=settings.server_graceful_timeout_seconds,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
