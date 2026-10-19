from typing import Literal

from pydantic import Field

from app.schemas.common import Schema


class DatabaseStatus(Schema):
    status: Literal["healthy", "degraded"]
    database: Literal["postgresql"] = "postgresql"
    connected: bool
    schema_ready: bool = False
    migration_revision: str | None = None
    expected_revision: str
    missing_tables: list[str] = Field(default_factory=list)
