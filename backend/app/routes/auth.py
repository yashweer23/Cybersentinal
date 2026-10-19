from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas.auth import RefreshTokenRequest, TokenResponse, UserLogin, UserRegister
from app.schemas.user import UserResponse
from app.security.dependencies import client_ip, get_current_user, require_browser_guard
from app.security.rate_limit import limit_auth_requests
from app.services import auth_service

REFRESH_COOKIE = "cs_refresh"
COOKIE_PATH = "/api/auth"
router = APIRouter(prefix="/api/auth", tags=["Authentication"])
SessionDep = Annotated[Session, Depends(get_db)]
guarded = [Depends(limit_auth_requests), Depends(require_browser_guard)]


def set_refresh_cookie(response: Response, request: Request, bundle: auth_service.TokenBundle):
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=bundle.refresh_token,
        httponly=True,
        secure=request.app.state.settings.cookie_secure,
        samesite="strict",
        path=COOKIE_PATH,
        max_age=max(0, int((bundle.refresh_expires_at - datetime.now(UTC)).total_seconds())),
    )


@router.post("/register", response_model=UserResponse, status_code=201, dependencies=guarded)
def register(payload: UserRegister, request: Request, session: SessionDep) -> User:
    """Create a VIEWER. Role selection is rejected; login is a separate operation."""
    return auth_service.register_user(session, payload, client_ip(request))


@router.post("/login", response_model=TokenResponse, dependencies=guarded)
def login(payload: UserLogin, request: Request, response: Response, session: SessionDep):
    """JSON username/password login. Refresh JWT is set only as an HTTP-only cookie."""
    bundle = auth_service.login(session, payload, request.app.state.settings, client_ip(request))
    set_refresh_cookie(response, request, bundle)
    return bundle.response


@router.get("/me", response_model=UserResponse)
def me(user: Annotated[User, Depends(get_current_user)]) -> User:
    return user


@router.post("/refresh", response_model=TokenResponse, dependencies=guarded)
def refresh(
    request: Request,
    response: Response,
    session: SessionDep,
    payload: RefreshTokenRequest | None = None,
):
    """Rotate the HTTP-only refresh cookie and return a new access JWT."""
    bundle = auth_service.refresh(
        session, request.cookies.get(REFRESH_COOKIE), request.app.state.settings, client_ip(request)
    )
    set_refresh_cookie(response, request, bundle)
    return bundle.response


@router.post("/logout", status_code=204, dependencies=[Depends(require_browser_guard)])
def logout(request: Request, session: SessionDep) -> Response:
    """Revoke the current session(s) and clear the refresh cookie. Idempotent."""
    authorization = request.headers.get("authorization", "")
    access = authorization[7:] if authorization.lower().startswith("bearer ") else None
    auth_service.logout(
        session,
        request.app.state.settings,
        refresh_token=request.cookies.get(REFRESH_COOKIE),
        access_token=access,
        ip=client_ip(request),
    )
    response = Response(status_code=204)
    response.delete_cookie(
        REFRESH_COOKIE,
        path=COOKIE_PATH,
        httponly=True,
        secure=request.app.state.settings.cookie_secure,
        samesite="strict",
    )
    return response
