import logging
from typing import Any
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import AuditLog

logger = logging.getLogger(__name__)


def record_audit(
    session: Session,
    action: str,
    *,
    actor_id: UUID | None,
    entity_id: str,
    old_value: dict[str, Any] | None = None,
    new_value: dict[str, Any] | None = None,
    ip_address: str | None = None,
    entity_type: str = "user",
) -> None:
    """Callers supply small, explicit snapshots; never pass request/token objects."""
    session.add(
        AuditLog(
            user_id=actor_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            old_value=old_value,
            new_value=new_value,
            ip_address=ip_address,
        )
    )
    session.flush()


def record_login_audit(session: Session, action: str, **kwargs) -> None:
    # Persist login/session changes before opening this independent savepoint.
    session.flush()
    try:
        with session.begin_nested():
            record_audit(session, action, **kwargs)
    except SQLAlchemyError as exc:
        logger.warning("Non-critical authentication audit failed (%s)", type(exc).__name__)
