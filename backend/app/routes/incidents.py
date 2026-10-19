from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.enums import UserRole
from app.core.errors import ServiceError
from app.database import get_db
from app.incidents.engine import IncidentManagementService
from app.incidents.workflow import TRANSITIONS, IncidentWorkflow
from app.models import User
from app.repositories import incident_repository as repository
from app.schemas.incident import (
    AnalystPage,
    AssignmentRequest,
    CommentPage,
    CommentRequest,
    EligibleAnalystQuery,
    FindingPage,
    IncidentDetail,
    IncidentEventPage,
    IncidentEventQuery,
    IncidentListResponse,
    IncidentNote,
    IncidentPageQuery,
    IncidentQuery,
    IncidentRunRequest,
    IncidentRunResponse,
    IncidentStats,
    IncidentSummary,
    StatusRequest,
    TimelinePage,
    TimelineQuery,
)
from app.security.dependencies import client_ip, get_current_user, require_roles

router = APIRouter(
    prefix="/api/incidents",
    tags=["Incident management"],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "ADMIN or ANALYST required for changes"},
        404: {"description": "Incident or referenced user/finding not found"},
        409: {"description": "Invalid transition or another operation is running"},
        503: {"description": "Database or incident processing unavailable"},
    },
)
SessionDep = Annotated[Session, Depends(get_db)]
Reader = Annotated[User, Depends(get_current_user)]
Writer = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]
Identifier = Annotated[str, Path(min_length=1, max_length=64)]
Page = Annotated[IncidentPageQuery, Query()]


@router.get("", response_model=IncidentListResponse)
def list_incidents(filters: Annotated[IncidentQuery, Query()], user: Reader, session: SessionDep):
    return repository.list_incidents(session, filters)


# Static paths precede identifiers.
@router.get("/eligible-analysts", response_model=AnalystPage)
def eligible_analysts(
    filters: Annotated[EligibleAnalystQuery, Query()], user: Writer, session: SessionDep
):
    """Assignment directory: active operators only; no email or credential fields."""
    return repository.eligible_analysts(session, filters)


@router.get("/stats", response_model=IncidentStats)
def stats(user: Reader, session: SessionDep):
    return repository.stats(session)


@router.post("/process", response_model=IncidentRunResponse)
def process(
    request: Request, user: Writer, session: SessionDep, payload: IncidentRunRequest | None = None
):
    try:
        return IncidentManagementService(session, request.app.state.settings).run(
            payload, actor_id=user.id, ip_address=client_ip(request)
        )
    except ServiceError as exc:
        if hasattr(exc, "result"):
            return JSONResponse(
                status_code=exc.status_code, content=exc.result.model_dump(mode="json")
            )
        raise


@router.get("/{incident_id}", response_model=IncidentDetail)
def detail(incident_id: Identifier, user: Reader, session: SessionDep):
    row = repository.get_incident(session, incident_id)
    page = IncidentPageQuery(limit=20)
    evidence, total = repository.evidence_page(session, row)
    return IncidentDetail(
        **repository.summary(row).model_dump(),
        findings=repository.finding_page(session, row, page),
        evidence=evidence,
        evidence_total=total,
        comments=repository.comment_page(session, row, page),
        timeline=repository.timeline_page(session, row, page),
        allowed_transitions=sorted(TRANSITIONS[row.status], key=lambda status: status.value)
        if user.role in {UserRole.ADMIN, UserRole.ANALYST}
        else [],
        risk_assessment=repository.leading_assessment(session, row),
    )


@router.patch("/{incident_id}/assign", response_model=IncidentSummary)
def assign(
    incident_id: Identifier,
    payload: AssignmentRequest,
    request: Request,
    user: Writer,
    session: SessionDep,
):
    return repository.summary(
        IncidentWorkflow(session).assign(incident_id, payload, user, client_ip(request))
    )


@router.patch("/{incident_id}/status", response_model=IncidentSummary)
def status(
    incident_id: Identifier,
    payload: StatusRequest,
    request: Request,
    user: Writer,
    session: SessionDep,
):
    return repository.summary(
        IncidentWorkflow(session).status(incident_id, payload, user, client_ip(request))
    )


@router.post("/{incident_id}/comments", response_model=IncidentNote, status_code=201)
def add_comment(
    incident_id: Identifier,
    payload: CommentRequest,
    request: Request,
    user: Writer,
    session: SessionDep,
):
    return IncidentWorkflow(session).comment(incident_id, payload, user, client_ip(request))


@router.get("/{incident_id}/comments", response_model=CommentPage)
def comments(incident_id: Identifier, page: Page, user: Reader, session: SessionDep):
    return repository.comment_page(session, repository.get_incident(session, incident_id), page)


@router.get("/{incident_id}/findings", response_model=FindingPage)
def findings(incident_id: Identifier, page: Page, user: Reader, session: SessionDep):
    return repository.finding_page(session, repository.get_incident(session, incident_id), page)


@router.get("/{incident_id}/events", response_model=IncidentEventPage)
def events(
    incident_id: Identifier,
    page: Annotated[IncidentEventQuery, Query()],
    user: Reader,
    session: SessionDep,
):
    return repository.event_page(session, repository.get_incident(session, incident_id), page)


@router.get("/{incident_id}/timeline", response_model=TimelinePage)
def timeline(
    incident_id: Identifier,
    page: Annotated[TimelineQuery, Query()],
    user: Reader,
    session: SessionDep,
):
    return repository.timeline_page(session, repository.get_incident(session, incident_id), page)
