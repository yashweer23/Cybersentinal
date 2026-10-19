from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, or_, select, text, update
from sqlalchemy.orm import Session

from app.core.enums import UserRole
from app.core.errors import ServiceError
from app.models import AuthSession, User
from app.schemas.auth import UserRegister
from app.security.passwords import hash_password
from app.services.audit_service import record_audit


def lock_admin_changes(session: Session) -> None:
    # One transaction-scoped PostgreSQL lock serializes admin membership changes.
    # It prevents concurrent requests from each removing a different "last" admin.
    session.execute(text("SELECT pg_advisory_xact_lock(74132903)"))


def get_user(session: Session, user_id: UUID) -> User:
    user = session.get(User, user_id, populate_existing=True)
    if user is None:
        raise ServiceError(404, "User not found")
    return user


def change_user(
    session: Session,
    actor: User,
    user_id: UUID,
    *,
    role: UserRole | None = None,
    is_active: bool | None = None,
    ip: str | None = None,
) -> User:
    lock_admin_changes(session)
    actor = get_user(session, actor.id)
    if not actor.is_active or actor.role != UserRole.ADMIN:
        raise ServiceError(403, "Your role does not permit this action")
    target = get_user(session, user_id)
    new_role = target.role if role is None else role
    new_active = target.is_active if is_active is None else is_active
    if (
        target.role == UserRole.ADMIN
        and target.is_active
        and (new_role != UserRole.ADMIN or not new_active)
    ):
        count = session.scalar(
            select(func.count())
            .select_from(User)
            .where(
                User.role == UserRole.ADMIN,
                User.is_active.is_(True),
            )
        )
        if count <= 1:
            raise ServiceError(409, "At least one active administrator must remain")
    old = {"role": target.role.value, "is_active": target.is_active}
    new = {"role": new_role.value, "is_active": new_active}
    if old == new:
        return target
    target.role, target.is_active = new_role, new_active
    if not new_active:
        session.execute(
            update(AuthSession)
            .where(
                AuthSession.user_id == target.id,
                AuthSession.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(UTC))
        )
    action = (
        "USER_ROLE_CHANGED"
        if role is not None
        else ("USER_ACTIVATED" if new_active else "USER_DEACTIVATED")
    )
    record_audit(
        session,
        action,
        actor_id=actor.id,
        entity_id=str(target.id),
        old_value=old,
        new_value=new,
        ip_address=ip,
    )
    session.commit()
    return target


def find_bootstrap_admin(session: Session, username: str, email: str) -> User | None:
    existing = session.scalars(
        select(User).where(or_(User.username == username, User.email == email))
    ).all()
    if existing:
        if (
            len(existing) == 1
            and existing[0].username == username
            and existing[0].email == email
            and existing[0].role == UserRole.ADMIN
            and existing[0].is_active
        ):
            return existing[0]
        raise ServiceError(409, "An existing account conflicts; no role or password was changed")
    return None


def bootstrap_admin(session: Session, payload: UserRegister) -> tuple[User, bool]:
    """Operator-only CLI action. Never promotes or resets an existing account implicitly."""
    lock_admin_changes(session)
    existing = find_bootstrap_admin(session, payload.username, payload.email)
    if existing is not None:
        return existing, False
    user = User(
        **payload.model_dump(),
        role=UserRole.ADMIN,
        hashed_password=hash_password(payload.password.get_secret_value()),
    )
    session.add(user)
    session.flush()
    record_audit(
        session,
        "ADMIN_BOOTSTRAPPED",
        actor_id=None,
        entity_id=str(user.id),
        new_value={"username": user.username, "role": "ADMIN"},
    )
    session.commit()
    return user, True
