"""Development only. Passwords come from masked prompts or DEMO_*_PASSWORD env vars."""

import sys
from collections.abc import Mapping
from getpass import getpass

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import PROJECT_ROOT, Settings, get_settings
from app.core.enums import UserRole
from app.database import build_engine
from app.models import User
from app.security.passwords import hash_password

DEMO_USERS = (
    ("admin", "admin@cybersentinel.local", "Demo Administrator", UserRole.ADMIN),
    ("analyst", "analyst@cybersentinel.local", "Demo Analyst", UserRole.ANALYST),
    ("viewer", "viewer@cybersentinel.local", "Demo Viewer", UserRole.VIEWER),
)


class DemoPasswords(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8-sig",
        env_prefix="DEMO_",
        extra="ignore",
        hide_input_in_errors=True,
    )
    admin_password: SecretStr | None = None
    analyst_password: SecretStr | None = None
    viewer_password: SecretStr | None = None


def check_development(settings: Settings) -> None:
    if settings.app_env != "development":
        raise ValueError("Demo user creation is permitted only with APP_ENV=development")


def missing_demo_users(session: Session) -> list[tuple]:
    missing = []
    for username, email, name, role in DEMO_USERS:
        existing = session.scalars(
            select(User).where(
                or_(User.username == username, User.email == email),
            )
        ).all()
        if not existing:
            missing.append((username, email, name, role))
        elif len(existing) != 1 or existing[0].username != username or existing[0].email != email:
            raise ValueError(f"An existing account conflicts with demo username {username}")
    return missing


def seed_demo_users(
    session: Session,
    settings: Settings,
    passwords: Mapping[str, str],
) -> int:
    check_development(settings)
    inserted = 0
    for username, email, name, role in missing_demo_users(session):
        password = passwords.get(username)
        if password is None:
            raise ValueError(f"A password must be supplied for {username}")
        statement = (
            insert(User)
            .values(
                username=username,
                email=email,
                full_name=name,
                role=role,
                hashed_password=hash_password(password),
            )
            .on_conflict_do_nothing()
            .returning(User.id)
        )
        inserted += session.scalar(statement) is not None
    # Detect a conflicting concurrent insert without changing any existing account.
    missing_demo_users(session)
    return inserted


def main() -> int:
    settings = get_settings()
    try:
        check_development(settings)
    except ValueError as exc:
        print(str(exc))
        return 1
    engine = build_engine(settings)
    try:
        configured = DemoPasswords()
        with Session(engine) as session, session.begin():
            passwords = {}
            for username, _, _, _ in missing_demo_users(session):
                supplied = getattr(configured, f"{username}_password")
                if supplied is not None:
                    passwords[username] = supplied.get_secret_value()
                elif sys.stdin.isatty():
                    passwords[username] = getpass(f"Password for {username} (12+ characters): ")
                    if passwords[username] != getpass("Confirm password: "):
                        raise ValueError("Passwords do not match")
                else:
                    raise ValueError(
                        f"Use an interactive terminal or set DEMO_{username.upper()}_PASSWORD"
                    )
            inserted = seed_demo_users(session, settings, passwords)
        print(f"Demo users: inserted={inserted}, already present={3 - inserted}")
        print("Existing passwords and roles were preserved. Sign in using your username.")
        return 0
    except ValueError as exc:
        print(str(exc))
        return 1
    except SQLAlchemyError as exc:
        print(
            f"User seed failed ({type(exc).__name__}). Check the DB and run alembic upgrade head."
        )
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
