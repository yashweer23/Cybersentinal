"""Temporary read-only inspection routes, mounted only in development/test."""

import logging
from pathlib import Path
from typing import Annotated

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from fastapi import APIRouter, Depends, Response
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import Base, get_db
from app.schemas.database import DatabaseStatus

router = APIRouter(prefix="/api", tags=["Database development checks"])
logger = logging.getLogger(__name__)


def expected_revision() -> str:
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    return ScriptDirectory.from_config(config).get_current_head()


@router.get(
    "/database/status", response_model=DatabaseStatus, responses={503: {"model": DatabaseStatus}}
)
def database_status(
    response: Response,
    session: Annotated[Session, Depends(get_db)],
) -> DatabaseStatus:
    response.headers["Cache-Control"] = "no-store"
    head = expected_revision()
    connected = False
    try:
        session.execute(text("SELECT 1")).scalar_one()
        connected = True
        connection = session.connection()
        tables = set(inspect(connection).get_table_names())
        missing = sorted(set(Base.metadata.tables) - tables)
        revision = MigrationContext.configure(connection).get_current_revision()
        ready = not missing and revision == head
        if not ready:
            response.status_code = 503
        return DatabaseStatus(
            status="healthy" if ready else "degraded",
            connected=True,
            schema_ready=ready,
            migration_revision=revision,
            expected_revision=head,
            missing_tables=missing,
        )
    except SQLAlchemyError as exc:
        logger.warning("Database inspection failed (%s)", type(exc).__name__)
        response.status_code = 503
        return DatabaseStatus(status="degraded", connected=connected, expected_revision=head)
