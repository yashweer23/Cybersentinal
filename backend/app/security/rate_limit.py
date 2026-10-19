"""Bounded, process-local development limiter. Use a shared limiter before scaling."""

import math
import time
from collections import deque
from threading import Lock

from fastapi import HTTPException, Request


class AuthRateLimiter:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.attempts = {}
        self.lock = Lock()

    def check(self, key: tuple[str, str], limit: int) -> None:
        now = self.clock()
        with self.lock:
            if key not in self.attempts and len(self.attempts) >= 10000:
                self.attempts = {k: q for k, q in self.attempts.items() if q[-1] > now - 60}
                if len(self.attempts) >= 10000:
                    raise HTTPException(
                        429, "Too many requests; try again shortly", headers={"Retry-After": "60"}
                    )
            queue = self.attempts.setdefault(key, deque())
            while queue and queue[0] <= now - 60:
                queue.popleft()
            if len(queue) >= limit:
                retry = max(1, math.ceil(queue[0] + 60 - now))
                raise HTTPException(
                    429, "Too many requests; try again shortly", headers={"Retry-After": str(retry)}
                )
            queue.append(now)


def limit_auth_requests(request: Request) -> None:
    settings = request.app.state.settings
    if not settings.auth_rate_limit_enabled:
        return
    endpoint = request.url.path.rsplit("/", 1)[-1]
    limits = {
        "login": settings.auth_login_limit,
        "register": settings.auth_register_limit,
        "refresh": settings.auth_refresh_limit,
    }
    if endpoint in limits:
        peer = request.client.host if request.client else "unknown"
        request.app.state.auth_limiter.check((endpoint, peer), limits[endpoint])
