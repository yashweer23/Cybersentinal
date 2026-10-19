"""bcrypt helpers shared by registration, login, and the existing seed scripts."""

import secrets

import bcrypt

from app.core.validation import validate_password


def hash_password(password: str) -> str:
    validate_password(password)
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        encoded = plain_password.encode("utf-8")
        if not encoded or len(encoded) > 72 or b"\x00" in encoded:
            return False
        return bcrypt.checkpw(encoded, hashed_password.encode("ascii"))
    except (ValueError, UnicodeError):
        return False


# Unknown accounts still execute bcrypt verification to reduce enumeration via timing.
# Generated at process start, never a usable account credential.
DUMMY_HASH = hash_password(secrets.token_urlsafe(32))
