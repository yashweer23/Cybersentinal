from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request
from sqlalchemy.orm import Session

from app.ai.schemas import (
    AIStatus,
    AnalysisRead,
    AnalysisResponse,
    AnalyzeRequest,
    AnswerResponse,
    AskRequest,
    HistoryPage,
    OverviewResponse,
)
from app.ai.service import AIAnalystService, ai_status
from app.core.enums import UserRole
from app.database import get_db
from app.models import User
from app.security.dependencies import client_ip, get_current_user, require_roles

router = APIRouter(
    prefix="/api/ai",
    tags=["AI analyst"],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "ADMIN or ANALYST required for generation"},
        404: {"description": "Incident not found"},
        409: {"description": "Evidence changed or analysis already running"},
        429: {"description": "Generation rate limit"},
        503: {"description": "Disabled or database unavailable"},
    },
)
SessionDep = Annotated[Session, Depends(get_db)]
Reader = Annotated[User, Depends(get_current_user)]
Writer = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]
Identifier = Annotated[str, Path(min_length=1, max_length=64)]


def service(request, session, user=None):
    if user:
        request.app.state.ai_limiter.check(
            ("ai", str(user.id)), request.app.state.settings.ai_rate_limit_per_minute
        )
    return AIAnalystService(session, request.app.state.settings)


@router.get("/status", response_model=AIStatus)
def status(request: Request, session: SessionDep, user: Reader):
    return ai_status(request.app.state.settings, session)


@router.post("/incidents/{incident_id}/analyze", response_model=AnalysisResponse)
def analyze(
    incident_id: Identifier,
    request: Request,
    session: SessionDep,
    user: Writer,
    payload: AnalyzeRequest | None = None,
):
    return service(request, session, user).analyze_incident(
        incident_id, (payload or AnalyzeRequest()).force_refresh, user.id, client_ip(request)
    )


@router.get("/incidents/{incident_id}/analysis", response_model=AnalysisRead)
def read(incident_id: Identifier, request: Request, session: SessionDep, user: Reader):
    return service(request, session).read(incident_id)


@router.get("/incidents/{incident_id}/history", response_model=HistoryPage)
def history(
    incident_id: Identifier,
    request: Request,
    session: SessionDep,
    user: Reader,
    limit: Annotated[int, Query(ge=1, le=25)] = 10,
    offset: Annotated[int, Query(ge=0, le=100000)] = 0,
):
    return service(request, session).history(incident_id, limit, offset)


@router.post("/incidents/{incident_id}/ask", response_model=AnswerResponse)
def ask(
    incident_id: Identifier,
    payload: AskRequest,
    request: Request,
    session: SessionDep,
    user: Writer,
):
    return service(request, session, user).answer_incident_question(
        incident_id, payload.question, user.id, client_ip(request)
    )


@router.post("/overview/ask", response_model=OverviewResponse)
def ask_overview(payload: AskRequest, request: Request, session: SessionDep, user: Writer):
    return service(request, session, user).answer_overview(
        payload.question, user.id, client_ip(request)
    )
