from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class ServiceCheck(BaseModel):
    status: Literal[
        "running", "connected", "disconnected", "READY", "FALLBACK", "DISABLED", "CONFIGURED"
    ]
    message: str
    latency_ms: float | None = None


class HealthResponse(BaseModel):
    status: Literal["healthy", "degraded"]
    app: str = "CyberSentinel"
    version: str = "0.15.0"
    phase: int = 15
    environment: str
    timestamp: datetime
    services: dict[str, ServiceCheck]
    planned_modules: list[str]


class ReadinessResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    database: Literal["connected", "unavailable"]
    migrations: Literal["current", "pending", "unavailable"]
    message: str
