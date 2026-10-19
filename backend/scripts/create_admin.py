"""Operator CLI: python -m scripts.create_admin. No password command-line argument."""

import argparse
import sys
from getpass import getpass

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.errors import ServiceError
from app.database import build_engine
from app.schemas.auth import UserRegister
from app.schemas.user import UserIdentity
from app.services.user_service import bootstrap_admin, find_bootstrap_admin


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an admin without public role escalation")
    parser.add_argument("--username")
    parser.add_argument("--email")
    parser.add_argument("--full-name")
    args = parser.parse_args()
    if (not args.username or not args.email) and not sys.stdin.isatty():
        print("Use an interactive terminal, or supply --username and --email.")
        return 1
    try:
        identity = UserIdentity(
            username=args.username or input("Admin username: "),
            email=args.email or input("Admin email: "),
            full_name=args.full_name,
        )
    except ValidationError:
        print("Invalid username/email. Use a 3–64 character username and a valid email address.")
        return 1
    engine = build_engine(get_settings())
    try:
        with Session(engine) as session:
            if find_bootstrap_admin(session, identity.username, identity.email):
                print("This active administrator already exists. Password and role preserved.")
                return 0
            if not sys.stdin.isatty():
                print(
                    "A new administrator requires an interactive terminal "
                    "for masked password input."
                )
                return 1
            password = getpass("Admin password (12+ characters, at most 72 UTF-8 bytes): ")
            if password != getpass("Confirm password: "):
                print("Passwords do not match.")
                return 1
            payload = UserRegister(**identity.model_dump(), password=password)
            user, created = bootstrap_admin(session, payload)
            print(f"Administrator {'created' if created else 'already exists'}: {user.username}")
        return 0
    except ServiceError as exc:
        print(exc.detail)
        return 1
    except ValidationError:
        print("Password must be at least 12 characters and at most 72 UTF-8 bytes, with no NUL.")
        return 1
    except SQLAlchemyError as exc:
        print(f"Admin setup failed ({type(exc).__name__}). Check connectivity and migrations.")
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
