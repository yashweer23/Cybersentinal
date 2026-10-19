"""Create an isolated PostgreSQL database, run all tests, and drop only that new database."""

import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool

from app.config import get_settings


def main() -> int:
    settings = get_settings()
    if settings.app_env not in {"development", "test"}:
        print("Run database tests only in development or test environments.")
        return 1
    name = f"cybersentinel_test_{uuid4().hex}"
    url = settings.database_url
    admin = create_engine(
        url,
        isolation_level="AUTOCOMMIT",
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={"connect_timeout": 5},
    )
    created = False
    result = 1
    try:
        with admin.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{name}"'))
        created = True
        print(f"Created isolated test database: {name}", flush=True)
        env = os.environ.copy()
        env["TEST_DATABASE_URL"] = url.set(database=name).render_as_string(hide_password=False)
        env["APP_ENV"] = "test"
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", *sys.argv[1:]],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            check=False,
        )
        result = completed.returncode
    except SQLAlchemyError as exc:
        print(f"Test DB setup failed ({type(exc).__name__}). The dev role needs CREATEDB.")
    finally:
        if created:
            try:
                with admin.connect() as connection:
                    # Generated locally, never accepted from an argument or environment variable.
                    connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
                print(f"Removed isolated test database: {name}")
            except SQLAlchemyError as exc:
                print(
                    f"Cleanup failed ({type(exc).__name__}); remove test database {name} manually."
                )
                result = 1
        admin.dispose()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
