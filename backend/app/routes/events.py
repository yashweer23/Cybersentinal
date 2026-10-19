from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from sqlalchemy.orm import Session

from app.core.enums import UserRole
from app.database import get_db
from app.models import User
from app.repositories import security_event_repository as repository
from app.schemas.event_ingestion import (
    BatchIngestRequest,
    BatchIngestResponse,
    EventIngestResponse,
    EventListResponse,
    EventQuery,
    EventStatsResponse,
)
from app.schemas.security_event import SecurityEventCreate, SecurityEventResponse
from app.security.dependencies import client_ip, get_current_user, require_roles
from app.services.event_ingestion import EventIngestionService

router = APIRouter(
    prefix="/api/events",
    tags=["Security Events"],
    responses={
        401: {"description": "Missing, expired or revoked access token"},
        503: {"description": "Database unavailable or write could not be confirmed"},
    },
)
SessionDep = Annotated[Session, Depends(get_db)]
ReaderDep = Annotated[User, Depends(get_current_user)]
WriterDep = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]


@router.post(
    "/ingest",
    response_model=EventIngestResponse,
    status_code=201,
    responses={
        200: {
            "model": EventIngestResponse,
            "description": "Duplicate event ID; existing data preserved",
        },
        403: {"description": "ADMIN or ANALYST role required"},
        413: {"description": "Request body exceeds configured limit"},
    },
)
def ingest_event(
    payload: SecurityEventCreate,
    request: Request,
    response: Response,
    user: WriterDep,
    session: SessionDep,
):
    """Normalize, validate and insert one event. New events remain processed=false."""
    outcome = EventIngestionService(session, request.app.state.settings).ingest_batch(
        [payload], actor_id=user.id, ip_address=client_ip(request)
    )
    result = outcome.summary
    if not result.complete:
        raise HTTPException(503, "Database write could not be confirmed; safely retry this event")
    if result.invalid:
        raise HTTPException(422, [e.model_dump() for e in result.errors])
    duplicate = result.duplicates > 0
    if duplicate:
        response.status_code = 200
        existing = repository.get_event(session, payload.event_id)
        if existing is None:
            raise HTTPException(503, "Event changed concurrently; retry this request")
        database_id = existing.id
    else:
        database_id = outcome.inserted_ids[payload.event_id]
    return EventIngestResponse(
        status="duplicate" if duplicate else "accepted",
        event_id=payload.event_id,
        database_id=database_id,
        duplicate=duplicate,
    )


@router.post(
    "/ingest/batch",
    response_model=BatchIngestResponse,
    responses={
        403: {"description": "ADMIN or ANALYST role required"},
        413: {"description": "Request body or configured event-count limit exceeded"},
        503: {"model": BatchIngestResponse, "description": "Write failed; inspect failed/complete"},
    },
)
def ingest_batch(
    payload: BatchIngestRequest,
    request: Request,
    response: Response,
    user: WriterDep,
    session: SessionDep,
):
    """Accept valid neighbors of invalid events; errors are bounded and indexes are one-based."""
    result = (
        EventIngestionService(session, request.app.state.settings)
        .ingest_batch(payload.events, actor_id=user.id, ip_address=client_ip(request))
        .summary
    )
    if not result.complete:
        response.status_code = 503
    return result


@router.get("", response_model=EventListResponse)
def list_events(filters: Annotated[EventQuery, Query()], user: ReaderDep, session: SessionDep):
    """SQL filters, limit/offset pagination, and whitelisted sorting (newest timestamp first)."""
    items, total = repository.list_events(session, filters)
    return EventListResponse(
        items=[SecurityEventResponse.model_validate(row) for row in items],
        total=total,
        limit=filters.limit,
        offset=filters.offset,
    )


@router.get("/stats", response_model=EventStatsResponse)
def stats(user: ReaderDep, session: SessionDep):
    """One grouped PostgreSQL query; storage counts only, without security classification."""
    return repository.event_stats(session)


@router.get(
    "/{event_id}",
    response_model=SecurityEventResponse,
    responses={
        404: {"description": "No event with this producer event_id"},
    },
)
def get_event(
    event_id: Annotated[str, Path(min_length=1, max_length=128)],
    user: ReaderDep,
    session: SessionDep,
):
    """Look up the exact, case-sensitive producer event_id, not the internal UUID."""
    row = repository.get_event(session, event_id)
    if row is None:
        raise HTTPException(404, "Security event not found")
    return row
