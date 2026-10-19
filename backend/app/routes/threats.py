from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request
from pydantic import AfterValidator
from sqlalchemy.orm import Session

from app.core.enums import UserRole
from app.core.errors import ServiceError
from app.database import get_db
from app.models import User
from app.security.dependencies import client_ip, get_current_user, require_roles
from app.services.incident_enrichment import read_related
from app.threat_intelligence.schemas import (
    EnrichmentSummary,
    EnrichRequest,
    IntelligenceResponse,
    LookupRequest,
    ProviderStatusResponse,
    RelatedIntelligence,
    RelatedQuery,
    ThreatPage,
    ThreatQuery,
)
from app.threat_intelligence.service import ThreatIntelligenceService
from app.threat_intelligence.utils.ip_validation import validate_ip

router = APIRouter(
    tags=["Threat intelligence"],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "ADMIN or ANALYST required for lookups/enrichment"},
        409: {"description": "Another intelligence writer is running"},
        503: {"description": "Database unavailable"},
    },
)
SessionDep = Annotated[Session, Depends(get_db)]
Reader = Annotated[User, Depends(get_current_user)]
Operator = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))]
Identifier = Annotated[str, Path(min_length=1, max_length=64)]
IPAddress = Annotated[
    str, Path(min_length=1, max_length=64), AfterValidator(lambda value: validate_ip(value).ip)
]


def service(request, session):
    return ThreatIntelligenceService(session, request.app.state.settings)


@router.post("/api/threats/lookup", response_model=IntelligenceResponse)
def lookup(payload: LookupRequest, request: Request, user: Operator, session: SessionDep):
    """Explicit lookup/refresh. Provider failures are typed results, never clean reputations."""
    return service(request, session).lookup_ip(
        payload.ip,
        force_refresh=payload.force_refresh,
        actor_id=user.id,
        ip_address=client_ip(request),
    )


@router.get("/api/threats", response_model=ThreatPage)
def list_threats(
    filters: Annotated[ThreatQuery, Query()], request: Request, user: Reader, session: SessionDep
):
    """Read stored results only. List projections omit raw payloads; retrieve an IP for detail."""
    return service(request, session).list_cached(filters)


@router.get("/api/threats/providers/status", response_model=ProviderStatusResponse)
def provider_status(request: Request, user: Reader, session: SessionDep):
    return service(request, session).provider_status()


@router.post("/api/threats/enrich/incidents", response_model=EnrichmentSummary)
def enrich(payload: EnrichRequest, request: Request, user: Operator, session: SessionDep):
    return service(request, session).enrich_pending(
        payload, actor_id=user.id, ip_address=client_ip(request)
    )


@router.get("/api/threats/ip/{ip}", response_model=IntelligenceResponse)
def ip_detail(
    ip: IPAddress,
    request: Request,
    user: Reader,
    session: SessionDep,
    mode: Annotated[str | None, Query(pattern="^(mock|live)$")] = None,
):
    """Cached only, including explicitly marked expired records. Never calls a provider."""
    result = service(request, session).get_cached_intelligence(ip, mode=mode)
    if result is None:
        raise ServiceError(404, "No cached intelligence for this IP and mode")
    return result


@router.get("/api/incidents/{incident_id}/threat-intelligence", response_model=RelatedIntelligence)
def incident_intelligence(
    incident_id: Identifier,
    query: Annotated[RelatedQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    return read_related(service(request, session), incident_id, "incident", query)


@router.get("/api/detections/{finding_id}/threat-intelligence", response_model=RelatedIntelligence)
def finding_intelligence(
    finding_id: Identifier,
    query: Annotated[RelatedQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    return read_related(service(request, session), finding_id, "finding", query)
