"""Central status transitions and case mutations. Callers use the existing RBAC."""

from datetime import UTC, datetime

from sqlalchemy import select

from app.core.enums import IncidentStatus as Status
from app.core.enums import UserRole
from app.core.errors import ServiceError
from app.models import IncidentComment, User
from app.repositories import incident_repository as repository
from app.services.audit_service import record_audit

TRANSITIONS = {
    Status.OPEN: {Status.INVESTIGATING, Status.FALSE_POSITIVE},
    Status.INVESTIGATING: {Status.RESOLVED, Status.FALSE_POSITIVE},
    Status.RESOLVED: {Status.INVESTIGATING},
    Status.FALSE_POSITIVE: {Status.INVESTIGATING},
}


def require_writer(user):
    if not user.is_active or user.role not in {UserRole.ADMIN, UserRole.ANALYST}:
        raise ServiceError(403, "Your role does not permit this action")


def change_status(session, incident, payload, *, actor_id, ip_address=None, automatic=False):
    old = incident.status
    if payload.status not in TRANSITIONS[old]:
        raise ServiceError(409, f"Cannot transition from {old.value} to {payload.status.value}")
    before = {
        "status": old.value,
        "resolved_at": (incident.resolved_at.isoformat() if incident.resolved_at else None),
        "resolution_summary": incident.resolution_summary,
    }
    now = datetime.now(UTC)
    incident.status = payload.status
    action = None
    if payload.status in {Status.RESOLVED, Status.FALSE_POSITIVE}:
        note = payload.resolution_summary if payload.status == Status.RESOLVED else payload.reason
        if not note or not note.strip():
            raise ServiceError(422, "A resolution summary or false-positive reason is required")
        incident.resolution_summary = note
        incident.resolved_at = now
        action = (
            "INCIDENT_RESOLVED"
            if payload.status == Status.RESOLVED
            else "INCIDENT_MARKED_FALSE_POSITIVE"
        )
    elif old in {Status.RESOLVED, Status.FALSE_POSITIVE}:
        incident.resolved_at = None
        incident.resolution_summary = None
        action = "INCIDENT_REOPENED"
    after = {
        "status": incident.status.value,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "resolution_summary": incident.resolution_summary,
        "reason": payload.reason,
        "automatic": automatic,
    }
    for name in ["INCIDENT_STATUS_CHANGED"] + ([action] if action else []):
        record_audit(
            session,
            name,
            actor_id=actor_id,
            entity_type="incident",
            entity_id=str(incident.id),
            old_value=before,
            new_value=after,
            ip_address=ip_address,
        )


class IncidentWorkflow:
    def __init__(self, session):
        self.session = session

    def _case(self, incident_id, actor):
        require_writer(actor)
        if not repository.acquire_lock(self.session):
            raise ServiceError(409, "Another incident operation is running; retry shortly")
        return repository.get_incident(self.session, incident_id, lock=True)

    def status(self, incident_id, payload, actor, ip=None):
        try:
            row = self._case(incident_id, actor)
            change_status(self.session, row, payload, actor_id=actor.id, ip_address=ip)
            self.session.commit()
            return repository.get_incident(self.session, incident_id)
        except Exception:
            self.session.rollback()
            raise

    def assign(self, incident_id, payload, actor, ip=None):
        try:
            row = self._case(incident_id, actor)
            if payload.analyst_id is not None:
                target = self.session.scalar(
                    select(User).where(User.id == payload.analyst_id).with_for_update()
                )
                if target is None:
                    raise ServiceError(404, "Assigned analyst not found")
                if not target.is_active or target.role not in {UserRole.ADMIN, UserRole.ANALYST}:
                    raise ServiceError(422, "Assign an active ADMIN or ANALYST")
            if row.assigned_analyst_id != payload.analyst_id:
                old = str(row.assigned_analyst_id) if row.assigned_analyst_id else None
                row.assigned_analyst_id = payload.analyst_id
                record_audit(
                    self.session,
                    "INCIDENT_ASSIGNED",
                    actor_id=actor.id,
                    entity_type="incident",
                    entity_id=str(row.id),
                    old_value={"analyst_id": old},
                    new_value={
                        "analyst_id": str(payload.analyst_id) if payload.analyst_id else None
                    },
                    ip_address=ip,
                )
            self.session.commit()
            return repository.get_incident(self.session, incident_id)
        except Exception:
            self.session.rollback()
            raise

    def comment(self, incident_id, payload, actor, ip=None):
        try:
            row = self._case(incident_id, actor)
            note = IncidentComment(incident_id=row.id, user_id=actor.id, comment=payload.comment)
            self.session.add(note)
            self.session.flush()
            identifier = note.id
            record_audit(
                self.session,
                "INCIDENT_COMMENT_ADDED",
                actor_id=actor.id,
                entity_type="incident",
                entity_id=str(row.id),
                new_value={"comment_id": str(note.id), "character_count": len(note.comment)},
                ip_address=ip,
            )
            self.session.commit()
            return repository.get_comment(self.session, identifier)
        except Exception:
            self.session.rollback()
            raise
