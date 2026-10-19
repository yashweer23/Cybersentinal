"""Guarded, single-release Alembic migration and read-only schema verification.

Run from backend: python -m scripts.cloud_release [--migrate]
Never seeds users/data, changes roles, downgrades, or prints database credentials.
"""

import argparse
import json
import os
from pathlib import Path

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Enum, inspect, text

from alembic import command
from app import models  # noqa: F401 -- register the existing metadata
from app.config import get_settings
from app.database import Base, build_engine
from app.operations.logging import configure_logging


def migration_config(connection):
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    config.attributes["connection"] = connection
    return config


def verify_schema(connection):
    """Verify the migration head and required structural objects, without altering data."""
    config = migration_config(connection)
    current = set(MigrationContext.configure(connection).get_current_heads())
    expected = set(ScriptDirectory.from_config(config).get_heads())
    if current != expected:
        raise RuntimeError("Database migrations are not current")
    inspector = inspect(connection)
    schema = connection.scalar(text("SELECT current_schema()"))
    actual_tables = set(inspector.get_table_names(schema=schema))
    required = set(Base.metadata.tables)
    if not required <= actual_tables:
        raise RuntimeError("Required database tables are missing")
    enum_types = {row["name"]: row["labels"] for row in inspector.get_enums(schema=schema)}
    indexes = foreign_keys = 0
    for table in Base.metadata.sorted_tables:
        columns = {row["name"] for row in inspector.get_columns(table.name, schema=schema)}
        if not set(table.columns.keys()) <= columns:
            raise RuntimeError(f"Missing columns on {table.name}")
        actual_indexes = {
            tuple(row["column_names"]) for row in inspector.get_indexes(table.name, schema=schema)
        }
        for index in table.indexes:
            if tuple(column.name for column in index.columns) not in actual_indexes:
                raise RuntimeError(f"Missing index on {table.name}")
            indexes += 1
        actual_foreign_keys = {
            (
                tuple(row["constrained_columns"]),
                row["referred_table"],
                tuple(row["referred_columns"]),
            )
            for row in inspector.get_foreign_keys(table.name, schema=schema)
        }
        for constraint in table.foreign_key_constraints:
            key = (
                tuple(element.parent.name for element in constraint.elements),
                next(iter(constraint.elements)).column.table.name,
                tuple(element.column.name for element in constraint.elements),
            )
            if key not in actual_foreign_keys:
                raise RuntimeError(f"Missing foreign key on {table.name}")
            foreign_keys += 1
        for column in table.columns:
            if isinstance(column.type, Enum) and column.type.native_enum:
                if enum_types.get(column.type.name) != column.type.enums:
                    raise RuntimeError(f"Missing or incompatible enum on {table.name}")
    return {
        "status": "verified",
        "alembic_heads": sorted(current),
        "tables": len(required),
        "indexes": indexes,
        "foreign_keys": foreign_keys,
        "enums": len(enum_types),
    }


def release(connection, *, expected_database: str, migrate: bool):
    """Caller owns one transaction on a direct PostgreSQL connection."""
    if (
        not expected_database
        or connection.scalar(text("SELECT current_database()")) != expected_database
    ):
        raise RuntimeError("Target database does not match EXPECTED_DATABASE_NAME")
    if migrate:
        # Direct session connection; never a transaction-mode pooler. Another deployment
        # fails immediately instead of competing for migration ownership.
        if not connection.scalar(text("SELECT pg_try_advisory_xact_lock(7318, 18)")):
            raise RuntimeError("Another release owns the migration lock")
        command.upgrade(migration_config(connection), "head")
    return verify_schema(connection)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--migrate", action="store_true", help="Apply Alembic migrations before verification"
    )
    args = parser.parse_args(argv)
    engine = None
    try:
        settings = get_settings()
        if settings.app_env != "production":
            raise RuntimeError("Cloud release requires APP_ENV=production")
        expected = os.environ.get("EXPECTED_DATABASE_NAME", "")
        if not expected or expected != settings.database_url.database:
            raise RuntimeError("Configure EXPECTED_DATABASE_NAME for this deployment")
        configure_logging(settings)
        engine = build_engine(settings)
        with engine.begin() as connection:
            result = release(connection, expected_database=expected, migrate=args.migrate)
        print(json.dumps(result))
        return 0
    except Exception as exc:
        # Never emit driver/parser exception messages or credential-bearing input.
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "message": "Cloud release failed; check environment, target and schema",
                }
            )
        )
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
