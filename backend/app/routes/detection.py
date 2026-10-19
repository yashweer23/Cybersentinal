from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import UserRole
from app.core.errors import ServiceError
from app.database import get_db
from app.detection.configuration import validate_configuration
from app.detection.engine import DetectionEngine
from app.models import DetectionRule, User
from app.repositories import detection_repository as repository
from app.schemas.detection import (
    DetectionRunRequest,
    DetectionRunResponse,
    DetectionStats,
    FindingListResponse,
    FindingQuery,
    FindingResponse,
    RuleUpdate,
)
from app.schemas.detection_rule import DetectionRuleResponse
from app.security.dependencies import client_ip, get_current_user, require_roles
from app.services.audit_service import record_audit

router = APIRouter(
    prefix="/api",
    tags=["Detection"],
    responses={
        401: {"description": "Authentication required"},
        503: {"description": "Detection or database unavailable"},
    },
)
SessionDep = Annotated[Session, Depends(get_db)]
Reader = Annotated[User, Depends(get_current_user)]
Operator = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]
Administrator = Annotated[User, Depends(require_roles(UserRole.ADMIN))]


@router.post(
    "/detection/run",
    response_model=DetectionRunResponse,
    responses={
        403: {"description": "ADMIN or ANALYST required"},
        409: {"description": "Another detection batch is running"},
        503: {"model": DetectionRunResponse},
    },
)
def run_detection(
    request: Request,
    user: Operator,
    session: SessionDep,
    payload: DetectionRunRequest | None = None,
):
    try:
        return DetectionEngine(session, request.app.state.settings).run(
            payload, actor_id=user.id, ip_address=client_ip(request)
        )
    except ServiceError as exc:
        if hasattr(exc, "result"):
            return JSONResponse(
                status_code=exc.status_code, content=exc.result.model_dump(mode="json")
            )
        raise


@router.get("/detections", response_model=FindingListResponse)
def findings(filters: Annotated[FindingQuery, Query()], user: Reader, session: SessionDep):
    rows, total = repository.list_findings(session, filters)
    return FindingListResponse(
        items=[FindingResponse.model_validate(row) for row in rows],
        total=total,
        limit=filters.limit,
        offset=filters.offset,
    )


@router.get("/detections/{finding_id}", response_model=FindingResponse)
def finding(finding_id: Annotated[str, Path(max_length=64)], user: Reader, session: SessionDep):
    row = repository.get_finding(session, finding_id)
    if row is None:
        raise HTTPException(404, "Detection finding not found")
    return row


@router.get("/detection/stats", response_model=DetectionStats)
def stats(user: Reader, session: SessionDep):
    return repository.detection_stats(session)


@router.get("/detection-rules", response_model=list[DetectionRuleResponse])
def rules(
    user: Reader,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Preserves the existing list contract; available in every application environment."""
    return list(
        session.scalars(
            select(DetectionRule).order_by(DetectionRule.rule_id).offset(offset).limit(limit)
        )
    )


@router.patch(
    "/detection-rules/{rule_id}",
    response_model=DetectionRuleResponse,
    responses={
        403: {"description": "ADMIN required"},
        409: {"description": "Detection batch is running"},
    },
)
def update_rule(
    rule_id: Annotated[str, Path(pattern=r"^CS-\d{3}$")],
    payload: RuleUpdate,
    request: Request,
    user: Administrator,
    session: SessionDep,
):
    if not repository.acquire_lock(session):
        raise HTTPException(
            409, "A detection batch or configuration change is running; retry shortly"
        )
    row = session.scalar(
        select(DetectionRule).where(DetectionRule.rule_id == rule_id).with_for_update()
    )
    if row is None:
        raise HTTPException(404, "Detection rule not found")
    old = {
        "enabled": row.enabled,
        "severity": row.severity.value,
        "configuration": row.configuration,
    }
    config = {**row.configuration, **(payload.configuration or {})}
    try:
        validated = validate_configuration(rule_id, config)
    except (ValidationError, ValueError):
        raise HTTPException(
            422, "Invalid configuration for this rule; check documented fields and bounds"
        ) from None
    row.configuration = validated.model_dump(mode="json")
    if payload.enabled is not None:
        row.enabled = payload.enabled
    if payload.severity is not None:
        row.severity = payload.severity
    new = {
        "enabled": row.enabled,
        "severity": row.severity.value,
        "configuration": row.configuration,
    }
    record_audit(
        session,
        "DETECTION_RULE_UPDATED",
        actor_id=user.id,
        entity_type="detection_rule",
        entity_id=str(row.id),
        old_value=old,
        new_value=new,
        ip_address=client_ip(request),
    )
    session.commit()
    session.refresh(row)
    return row
