"""Signed token creation and strict validation, independent of HTTP/database code."""

from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID, uuid4

import jwt as pyjwt

from app.config import Settings
from app.core.enums import UserRole


class InvalidToken(ValueError):
    pass


def _create_token(
    user_id: UUID,
    session_id: UUID,
    role: UserRole,
    settings: Settings,
    token_type: Literal["access", "refresh"],
    expires_at: datetime,
) -> str:
    now = datetime.now(UTC)
    return pyjwt.encode(
        {
            "sub": str(user_id),
            "sid": str(session_id),
            "role": role.value,
            "jti": str(uuid4()),
            "token_type": token_type,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
        },
        settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def create_access_token(
    user_id: UUID,
    session_id: UUID,
    role: UserRole,
    settings: Settings,
    *,
    expires_at: datetime | None = None,
) -> str:
    expiry = expires_at or datetime.now(UTC) + timedelta(
        minutes=settings.jwt_access_token_expire_minutes,
    )
    return _create_token(user_id, session_id, role, settings, "access", expiry)


def create_refresh_token(
    user_id: UUID,
    session_id: UUID,
    role: UserRole,
    settings: Settings,
    *,
    expires_at: datetime | None = None,
) -> str:
    expiry = expires_at or datetime.now(UTC) + timedelta(
        days=settings.jwt_refresh_token_expire_days
    )
    return _create_token(user_id, session_id, role, settings, "refresh", expiry)


def _decode_token(token: str, settings: Settings, kind: str) -> dict:
    try:
        if len(token) > 4096:
            raise InvalidToken("Invalid or expired token")
        claims = pyjwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={
                "require": ["sub", "sid", "role", "jti", "token_type", "iat", "exp", "iss", "aud"]
            },
        )
        if claims["token_type"] != kind:
            raise InvalidToken("Invalid or expired token")
        for field in ("sub", "sid", "jti"):
            UUID(claims[field])
        UserRole(claims["role"])
        if type(claims["exp"]) is not int or type(claims["iat"]) is not int:
            raise InvalidToken("Invalid or expired token")
        if claims["exp"] <= claims["iat"]:
            raise InvalidToken("Invalid or expired token")
        return claims
    except (pyjwt.InvalidTokenError, ValueError, TypeError, AttributeError) as exc:
        raise InvalidToken("Invalid or expired token") from exc


def decode_access_token(token: str, settings: Settings) -> dict:
    return _decode_token(token, settings, "access")


def decode_refresh_token(token: str, settings: Settings) -> dict:
    return _decode_token(token, settings, "refresh")
