from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.enums import UserRole
from app.database import get_db
from app.models import User
from app.schemas.auth import RoleUpdate, UserPage, UserStatusUpdate
from app.schemas.user import UserResponse
from app.security.dependencies import client_ip, require_roles
from app.services import user_service

router = APIRouter(prefix="/api/users", tags=["User administration"])
SessionDep = Annotated[Session, Depends(get_db)]
AdminDep = Annotated[User, Depends(require_roles(UserRole.ADMIN))]


@router.get("", response_model=UserPage)
def list_users(
    admin: AdminDep,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    q: Annotated[str | None, Query(max_length=100)] = None,
) -> UserPage:
    query = select(User)
    if q:
        query = query.where(
            or_(
                User.username.icontains(q, autoescape=True),
                User.email.icontains(q, autoescape=True),
            )
        )
    total = session.scalar(select(func.count()).select_from(query.subquery()))
    users = session.scalars(
        query.order_by(User.username, User.id).offset(offset).limit(limit)
    ).all()
    return UserPage(
        items=[UserResponse.model_validate(user) for user in users],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: UUID, admin: AdminDep, session: SessionDep):
    return user_service.get_user(session, user_id)


@router.patch("/{user_id}/role", response_model=UserResponse)
def set_role(
    user_id: UUID, payload: RoleUpdate, request: Request, admin: AdminDep, session: SessionDep
):
    return user_service.change_user(
        session, admin, user_id, role=payload.role, ip=client_ip(request)
    )


@router.patch("/{user_id}/status", response_model=UserResponse)
def set_status(
    user_id: UUID, payload: UserStatusUpdate, request: Request, admin: AdminDep, session: SessionDep
):
    return user_service.change_user(
        session, admin, user_id, is_active=payload.is_active, ip=client_ip(request)
    )
