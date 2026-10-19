"""Small development-only checks for the three access levels."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.enums import UserRole
from app.models import User
from app.security.dependencies import get_current_user, require_roles

router = APIRouter(prefix="/api/test", tags=["Development role checks"])


def result(user: User) -> dict[str, str]:
    return {"status": "allowed", "username": user.username, "role": user.role.value}


@router.get("/authenticated")
def authenticated(user: Annotated[User, Depends(get_current_user)]):
    return result(user)


@router.get("/analyst")
def analyst(user: Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]):
    return result(user)


@router.get("/admin")
def admin(user: Annotated[User, Depends(require_roles(UserRole.ADMIN))]):
    return result(user)
