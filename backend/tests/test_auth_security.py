from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.config import Settings
from app.core.enums import UserRole
from app.security.jwt import (
    InvalidToken,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
)
from app.security.passwords import verify_password
from app.security.rate_limit import AuthRateLimiter


@pytest.fixture
def settings():
    return Settings(_env_file=None)


def test_jwt_creation_and_separation(settings):
    uid, sid = uuid4(), uuid4()
    access = create_access_token(uid, sid, UserRole.ANALYST, settings)
    refresh = create_refresh_token(uid, sid, UserRole.ANALYST, settings)
    claims = decode_access_token(access, settings)
    assert claims["sub"] == str(uid) and claims["sid"] == str(sid)
    assert claims["role"] == "ANALYST" and claims["exp"] - claims["iat"] == 1800
    assert decode_refresh_token(refresh, settings)["token_type"] == "refresh"
    with pytest.raises(InvalidToken):
        decode_refresh_token(access, settings)
    with pytest.raises(InvalidToken):
        decode_access_token(refresh, settings)


@pytest.mark.parametrize(
    "field,value",
    [
        ("sub", "not-a-uuid"),
        ("sid", 123),
        ("jti", "bad"),
        ("role", "ROOT"),
        ("exp", "9999999999"),
        ("iat", True),
        ("iss", "other"),
        ("aud", "other"),
        ("token_type", "refresh"),
    ],
)
def test_signed_but_invalid_claims_rejected(settings, field, value):
    original = create_access_token(uuid4(), uuid4(), UserRole.VIEWER, settings)
    claims = decode_access_token(original, settings)
    claims[field] = value
    token = jwt.encode(claims, settings.jwt_secret_key.get_secret_value(), algorithm="HS256")
    with pytest.raises(InvalidToken):
        decode_access_token(token, settings)


@pytest.mark.parametrize(
    "field", ["sub", "sid", "jti", "role", "exp", "iat", "iss", "aud", "token_type"]
)
def test_required_claims(settings, field):
    claims = decode_access_token(
        create_access_token(uuid4(), uuid4(), UserRole.VIEWER, settings), settings
    )
    del claims[field]
    token = jwt.encode(claims, settings.jwt_secret_key.get_secret_value(), algorithm="HS256")
    with pytest.raises(InvalidToken):
        decode_access_token(token, settings)


def test_expiry_tampering_and_algorithm_allowlist(settings):
    expired = create_access_token(
        uuid4(),
        uuid4(),
        UserRole.VIEWER,
        settings,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    valid = create_access_token(uuid4(), uuid4(), UserRole.VIEWER, settings)
    claims = decode_access_token(valid, settings)
    wrong_key = jwt.encode(claims, "another-key-at-least-thirty-two-bytes-long", algorithm="HS256")
    wrong_algorithm = jwt.encode(
        claims, settings.jwt_secret_key.get_secret_value(), algorithm="HS384"
    )
    unsigned = jwt.encode(claims, "", algorithm="none")
    for token in (expired, wrong_key, wrong_algorithm, unsigned, "malformed", "a" * 5000):
        with pytest.raises(InvalidToken):
            decode_access_token(token, settings)


def test_bad_password_hash_and_overlong_password_are_safe():
    assert verify_password("password", "bad-hash") is False
    assert verify_password("a" * 73, "bad-hash") is False
    assert verify_password("bad\x00password", "bad-hash") is False


def test_weak_jwt_configuration_fails_closed():
    for secret in ("short", "CHANGE_ME_" + "x" * 40):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, jwt_secret_key=secret)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, jwt_algorithm="none")


def test_limiter_sliding_window_and_independent_endpoints():
    now = [0.0]
    limiter = AuthRateLimiter(clock=lambda: now[0])
    limiter.check(("login", "peer"), 1)
    with pytest.raises(HTTPException) as blocked:
        limiter.check(("login", "peer"), 1)
    assert blocked.value.status_code == 429
    limiter.check(("register", "peer"), 1)
    now[0] = 61
    limiter.check(("login", "peer"), 1)
