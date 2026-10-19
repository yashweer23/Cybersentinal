import logging
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from time import perf_counter
from typing import Annotated

from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from app.ai.service import ai_status
from app.database import get_engine
from app.schemas.health import HealthResponse, ReadinessResponse, ServiceCheck

router = APIRouter(prefix="/api/system", tags=["System"])
logger = logging.getLogger(__name__)


@router.get("/live")
def liveness() -> dict[str, str]:
    """Process liveness. Does not assert database readiness."""
    return {"status": "alive"}


@lru_cache
def migration_heads():
    configuration = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    return set(ScriptDirectory.from_config(configuration).get_heads())


@router.get(
    "/ready", response_model=ReadinessResponse, responses={503: {"model": ReadinessResponse}}
)
def readiness(response: Response, engine: Annotated[Engine, Depends(get_engine)]):
    """Database and migration readiness. No optional provider or analytics calls."""
    response.headers["Cache-Control"] = "no-store"
    connected = False
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1")).scalar_one()
            connected = True
            versions = set(
                connection.execute(text("SELECT version_num FROM alembic_version")).scalars()
            )
        if versions == migration_heads():
            return ReadinessResponse(
                status="ready",
                database="connected",
                migrations="current",
                message="Database and Alembic revision are ready",
            )
    except SQLAlchemyError as exc:
        logger.warning("Readiness unavailable (%s)", type(exc).__name__)
    response.status_code = 503
    return ReadinessResponse(
        status="not_ready",
        database="connected" if connected else "unavailable",
        migrations="pending" if connected else "unavailable",
        message="Apply Alembic migrations" if connected else "Database temporarily unavailable",
    )


@router.get("/health", response_model=HealthResponse, responses={503: {"model": HealthResponse}})
def health(
    request: Request,
    response: Response,
    engine: Annotated[Engine, Depends(get_engine)],
) -> HealthResponse:
    """Readiness: HTTP 200 only after a real PostgreSQL SELECT 1 succeeds."""
    start = perf_counter()
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1")).scalar_one()
        db = ServiceCheck(
            status="connected",
            message="PostgreSQL query succeeded",
            latency_ms=round((perf_counter() - start) * 1000, 2),
        )
        healthy = True
    except SQLAlchemyError as exc:
        # Avoid serializing exceptions: connection errors can contain credentials/hostnames.
        logger.warning("Database readiness check failed (%s)", type(exc).__name__)
        db = ServiceCheck(status="disconnected", message="Database unavailable; check backend logs")
        healthy = False
        response.status_code = 503
    response.headers["Cache-Control"] = "no-store"
    analyst = ai_status(request.app.state.settings)
    return HealthResponse(
        status="healthy" if healthy else "degraded",
        environment=request.app.state.settings.app_env,
        timestamp=datetime.now(UTC),
        services={
            "api": ServiceCheck(status="running", message="FastAPI is responding"),
            "database": db,
            "ai_analyst": ServiceCheck(status=analyst.status, message=analyst.note),
        },
        planned_modules=[],
    )
