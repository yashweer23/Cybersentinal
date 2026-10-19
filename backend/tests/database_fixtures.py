"""Never migrate public or delete existing tables: each run owns a random schema."""

import os
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from alembic import command


def migration_config(connection) -> Config:
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    config.attributes["connection"] = connection
    return config


@contextmanager
def isolated_schema(url, **engine_options):
    """A second guard beyond a separate test DB: every DDL operation stays in this schema."""
    schema = f"cs_test_{uuid4().hex}"
    admin = create_engine(url, hide_parameters=True, poolclass=NullPool)
    engine = None
    created = False
    try:
        with admin.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        created = True
        engine = create_engine(
            url, hide_parameters=True, **{"poolclass": NullPool, **engine_options}
        )

        @event.listens_for(engine, "connect")
        def set_search_path(dbapi_connection, connection_record):
            # Set outside a transaction so per-test rollback cannot undo isolation.
            old_autocommit = dbapi_connection.autocommit
            dbapi_connection.autocommit = True
            try:
                with dbapi_connection.cursor() as cursor:
                    cursor.execute(f'SET search_path TO "{schema}", pg_catalog')
            finally:
                dbapi_connection.autocommit = old_autocommit

        with engine.connect() as connection:
            assert connection.scalar(text("SELECT current_schema()")) == schema
        yield engine
    finally:
        if engine is not None:
            engine.dispose()
        if created:
            with admin.begin() as connection:
                connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.fixture(scope="session")
def database_url():
    value = os.environ.get("TEST_DATABASE_URL")
    if not value:
        pytest.skip("Use python -m scripts.run_database_tests for PostgreSQL integration tests")
    url = make_url(value)
    if url.drivername != "postgresql+psycopg":
        pytest.fail("Integration tests require PostgreSQL with psycopg, not SQLite")
    return url


@pytest.fixture(scope="session")
def database_engine(database_url):
    with isolated_schema(database_url) as engine:
        with engine.begin() as connection:
            command.upgrade(migration_config(connection), "head")
        yield engine


@pytest.fixture
def db(database_engine):
    with database_engine.connect() as connection:
        transaction = connection.begin()
        session = Session(bind=connection, join_transaction_mode="create_savepoint")
        try:
            yield session
        finally:
            session.close()
            if transaction.is_active:
                transaction.rollback()
