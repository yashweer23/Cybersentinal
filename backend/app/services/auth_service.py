from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from hmac import compare_digest
from uuid import UUID, uuid4

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.enums import UserRole
from app.core.errors import ServiceError
from app.models import AuthSession, User
from app.schemas.auth import TokenResponse, UserLogin, UserRegister
from app.schemas.user import UserResponse
from app.security.jwt import (
    InvalidToken,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
)
from app.security.passwords import DUMMY_HASH, hash_password, verify_password
from app.services.audit_service import record_audit, record_login_audit


@dataclass
class TokenBundle:
    response: TokenResponse
    refresh_token: str
    refresh_expires_at: datetime


def token_digest(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def _issue_tokens(user: User, login_session: AuthSession, settings: Settings) -> TokenBundle:
    now = datetime.now(UTC)
    access_expiry = min(
        login_session.expires_at,
        now
        + timedelta(
            minutes=settings.jwt_access_token_expire_minutes,
        ),
    )
    refresh = create_refresh_token(
        user.id, login_session.id, user.role, settings, expires_at=login_session.expires_at
    )
    login_session.refresh_token_hash = token_digest(refresh)
    login_session.last_used_at = now
    return TokenBundle(
        response=TokenResponse(
            access_token=create_access_token(
                user.id, login_session.id, user.role, settings, expires_at=access_expiry
            ),
            expires_in=max(0, int(access_expiry.timestamp()) - int(now.timestamp())),
            user=UserResponse.model_validate(user),
        ),
        refresh_token=refresh,
        refresh_expires_at=login_session.expires_at,
    )


def register_user(session: Session, payload: UserRegister, ip: str | None) -> User:
    if session.scalar(
        select(User.id).where(or_(User.username == payload.username, User.email == payload.email))
    ):
        raise ServiceError(409, "Username or email is already in use")
    user = User(
        **payload.model_dump(),
        hashed_password=hash_password(payload.password.get_secret_value()),
        role=UserRole.VIEWER,
    )
    try:
        session.add(user)
        session.flush()
    except IntegrityError:
        session.rollback()
        raise ServiceError(409, "Username or email is already in use") from None
    record_audit(
        session,
        "USER_REGISTERED",
        actor_id=user.id,
        entity_id=str(user.id),
        new_value={"username": user.username, "role": user.role.value},
        ip_address=ip,
    )
    session.commit()
    return user


def login(session: Session, payload: UserLogin, settings: Settings, ip: str | None) -> TokenBundle:
    # Serialize session creation with account deactivation so reactivation cannot
    # revive a session that slipped past a concurrent revoke-all operation.
    user = session.scalar(select(User).where(User.username == payload.username).with_for_update())
    verified = verify_password(
        payload.password.get_secret_value(), user.hashed_password if user else DUMMY_HASH
    )
    if not verified or user is None or not user.is_active:
        record_login_audit(
            session,
            "LOGIN_FAILED",
            actor_id=None,
            entity_id=str(user.id) if user else "unknown",
            new_value={"username": payload.username},
            ip_address=ip,
        )
        session.commit()
        raise ServiceError(401, "Invalid username or password")
    now = datetime.now(UTC)
    user.last_login = now
    login_session = AuthSession(
        id=uuid4(),
        user_id=user.id,
        created_at=now,
        expires_at=now + timedelta(days=settings.jwt_refresh_token_expire_days),
    )
    # Flush the user first so response timestamps reflect the database update trigger.
    session.flush()
    bundle = _issue_tokens(user, login_session, settings)
    session.add(login_session)
    session.flush()
    record_login_audit(
        session, "LOGIN_SUCCESS", actor_id=user.id, entity_id=str(user.id), ip_address=ip
    )
    session.commit()
    return bundle


def refresh(session: Session, token: str | None, settings: Settings, ip: str | None) -> TokenBundle:
    if not token:
        raise ServiceError(401, "Refresh session is invalid or expired")
    try:
        claims = decode_refresh_token(token, settings)
    except InvalidToken:
        raise ServiceError(401, "Refresh session is invalid or expired") from None
    login_session = session.scalar(
        select(AuthSession)
        .where(
            AuthSession.id == UUID(claims["sid"]),
            AuthSession.user_id == UUID(claims["sub"]),
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    now = datetime.now(UTC)
    if login_session is None or login_session.revoked_at or login_session.expires_at <= now:
        raise ServiceError(401, "Refresh session is invalid or expired")
    if not compare_digest(token_digest(token), login_session.refresh_token_hash):
        # A validly signed, superseded refresh token indicates replay. End this session.
        login_session.revoked_at = now
        record_login_audit(
            session,
            "REFRESH_REPLAY_REJECTED",
            actor_id=None,
            entity_id=str(login_session.user_id),
            ip_address=ip,
        )
        session.commit()
        raise ServiceError(401, "Refresh session is invalid or expired")
    user = session.get(User, login_session.user_id, populate_existing=True)
    if user is None or not user.is_active:
        raise ServiceError(401, "Refresh session is invalid or expired")
    bundle = _issue_tokens(user, login_session, settings)
    session.commit()
    return bundle


def logout(
    session: Session,
    settings: Settings,
    *,
    refresh_token: str | None,
    access_token: str | None,
    ip: str | None,
) -> None:
    identities = set()
    for token, decode in (
        (refresh_token, decode_refresh_token),
        (access_token, decode_access_token),
    ):
        if not token:
            continue
        try:
            claims = decode(token, settings)
            identities.add((UUID(claims["sid"]), UUID(claims["sub"])))
        except InvalidToken:
            continue
    for session_id, user_id in identities:
        row = session.scalar(
            select(AuthSession)
            .where(
                AuthSession.id == session_id,
                AuthSession.user_id == user_id,
            )
            .with_for_update()
        )
        if row is not None and row.revoked_at is None:
            row.revoked_at = datetime.now(UTC)
            record_login_audit(
                session, "LOGOUT", actor_id=user_id, entity_id=str(user_id), ip_address=ip
            )
    session.commit()
