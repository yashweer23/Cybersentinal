from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import UserRole
from app.core.errors import ServiceError
from app.database import get_db
from app.models import RiskAssessment, User
from app.repositories import risk_repository as repository
from app.risk.config import SCORE_VERSION
from app.risk.engine import RiskScoringEngine
from app.schemas.risk import (
    RiskListResponse,
    RiskQuery,
    RiskResponse,
    RiskRunRequest,
    RiskRunResponse,
    RiskStats,
    assessment_response,
)
from app.security.dependencies import client_ip, get_current_user, require_roles

router = APIRouter(
    prefix="/api/risk",
    tags=["Risk scoring"],
    responses={
        401: {"description": "Authentication required"},
        503: {"description": "Risk scoring or database unavailable"},
    },
)
SessionDep = Annotated[Session, Depends(get_db)]
Reader = Annotated[User, Depends(get_current_user)]
Operator = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]


@router.post(
    "/run",
    response_model=RiskRunResponse,
    responses={
        403: {"description": "ADMIN or ANALYST required"},
        409: {"description": "Another risk scoring batch is running"},
        503: {"model": RiskRunResponse},
    },
)
def run_risk(
    request: Request, user: Operator, session: SessionDep, payload: RiskRunRequest | None = None
):
    try:
        return RiskScoringEngine(session, request.app.state.settings).run(
            payload, actor_id=user.id, ip_address=client_ip(request)
        )
    except ServiceError as exc:
        if hasattr(exc, "result"):
            return JSONResponse(
                status_code=exc.status_code, content=exc.result.model_dump(mode="json")
            )
        raise


@router.get("", response_model=RiskListResponse)
def assessments(filters: Annotated[RiskQuery, Query()], user: Reader, session: SessionDep):
    rows, total = repository.list_assessments(session, filters)
    return RiskListResponse(
        items=[assessment_response(row) for row in rows],
        total=total,
        limit=filters.limit,
        offset=filters.offset,
    )


# Register static paths before the assessment-ID route.
@router.get("/stats", response_model=RiskStats)
def stats(
    user: Reader,
    session: SessionDep,
    score_version: Annotated[str, Query(min_length=1, max_length=32)] = SCORE_VERSION,
):
    return repository.stats(session, score_version)


@router.get("/{assessment_id}", response_model=RiskResponse)
def assessment(
    assessment_id: Annotated[str, Path(max_length=64)], user: Reader, session: SessionDep
):
    row = session.scalar(
        select(RiskAssessment).where(RiskAssessment.assessment_id == assessment_id)
    )
    if row is None:
        raise HTTPException(404, "Risk assessment not found")
    return assessment_response(row)
