from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import UserRole
from app.database import get_db
from app.models import AuthSession, User
from app.security.jwt import InvalidToken, decode_access_token

bearer = HTTPBearer(auto_error=False, scheme_name="BearerAuth", description="Paste the access JWT.")


def get_current_user(
    request: Request,
    session: Annotated[Session, Depends(get_db)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> User:
    unauthorized = HTTPException(
        401, "Authentication required", headers={"WWW-Authenticate": "Bearer"}
    )
    if credentials is None:
        raise unauthorized
    try:
        claims = decode_access_token(credentials.credentials, request.app.state.settings)
    except InvalidToken:
        raise unauthorized from None
    row = session.execute(
        select(User, AuthSession)
        .join(AuthSession)
        .where(
            User.id == UUID(claims["sub"]),
            AuthSession.id == UUID(claims["sid"]),
            User.is_active.is_(True),
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > datetime.now(UTC),
        )
        .execution_options(populate_existing=True)
    ).first()
    if row is None:
        raise unauthorized
    request.state.auth_session_id = row.AuthSession.id
    return row.User


def require_roles(*roles: UserRole):
    def authorize(user: Annotated[User, Depends(get_current_user)]) -> User:
        if user.role not in roles:
            raise HTTPException(403, "Your role does not permit this action")
        return user

    return authorize


def require_browser_guard(
    request: Request,
    guard: Annotated[str | None, Header(alias="X-CSRF-Guard", examples=["1"])] = None,
) -> None:
    """Custom-header + explicit Origin validation for endpoints that set/use cookies."""
    origin = request.headers.get("origin")
    if guard != "1" or (
        origin and origin not in request.app.state.settings.trusted_browser_origins
    ):
        raise HTTPException(403, "Request origin or CSRF guard is invalid")
    # Non-browser clients may omit Origin but must supply the custom header.
    if not origin and request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(403, "Cross-site authentication requests are not allowed")


def client_ip(request: Request) -> str | None:
    try:
        return str(ip_address(request.client.host)) if request.client else None
    except ValueError:
        return None
