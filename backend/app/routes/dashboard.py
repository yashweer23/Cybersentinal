"""Read-only dashboard endpoints; all roles reuse the existing authenticated reader."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import dashboard as schema
from app.security.dependencies import get_current_user
from app.services.dashboard_service import DashboardService

router = APIRouter(
    prefix="/api/dashboard",
    tags=["Dashboard analytics"],
    responses={
        401: {"description": "Authentication required"},
        422: {"description": "Invalid time range, limit or cursor"},
        503: {"description": "Database unavailable"},
    },
)
SessionDep = Annotated[Session, Depends(get_db)]
Reader = Annotated[User, Depends(get_current_user)]


@router.get("/overview", response_model=schema.DashboardOverviewResponse)
def overview(
    query: Annotated[schema.TimeRangeQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """Selected-scope metrics plus explicitly global event totals."""
    return DashboardService(session, request.app.state.settings).execute("overview", query)


@router.get("/events/timeline", response_model=schema.SecurityTimelineResponse)
def timeline(
    query: Annotated[schema.TimeRangeQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """UTC event-occurrence buckets, with zero-filled gaps and exact half-open filtering."""
    return DashboardService(session, request.app.state.settings).execute("timeline", query)


@router.get("/events/types", response_model=schema.EventTypeDistributionResponse)
def event_types(
    query: Annotated[schema.TimeRangeQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """Observed event counts by stored event_type, descending count then type."""
    return DashboardService(session, request.app.state.settings).execute("event_types", query)


@router.get("/events/recent", response_model=schema.RecentEventsResponse)
def recent_events(
    query: Annotated[schema.RecentQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """Compact events sorted by timestamp DESC, id DESC; includes a polling watermark."""
    return DashboardService(session, request.app.state.settings).execute("recent_events", query)


@router.get("/events/updates", response_model=schema.EventUpdatesResponse)
def updates(
    query: Annotated[schema.UpdatesQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """Insertion-order polling. Omit after_id to initialize; pass 0 to drain all retained events."""
    return DashboardService(session, request.app.state.settings).execute("updates", query)


@router.get("/incidents/severity", response_model=schema.SeverityDistributionResponse)
def severity(
    query: Annotated[schema.TimeRangeQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """Stored current incident severities, including zero-count categories."""
    return DashboardService(session, request.app.state.settings).execute("severity", query)


@router.get("/incidents/status", response_model=schema.StatusDistributionResponse)
def status(
    query: Annotated[schema.TimeRangeQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """Current incident states in the selected detection-time cohort."""
    return DashboardService(session, request.app.state.settings).execute("status", query)


@router.get("/incidents/recent", response_model=schema.RecentIncidentsResponse)
def recent_incidents(
    query: Annotated[schema.RecentQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """Compact cases and safe analyst references, without notes or raw evidence."""
    return DashboardService(session, request.app.state.settings).execute("recent_incidents", query)


@router.get("/threats/top-ips", response_model=schema.TopSuspiciousIPsResponse)
def top_ips(
    query: Annotated[schema.TopIPQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """Distinct associated cases/findings with current cache context; no external lookup."""
    return DashboardService(session, request.app.state.settings).execute("top_ips", query)


@router.get("/threats/summary", response_model=schema.ThreatSummaryResponse)
def threats(
    query: Annotated[schema.ThreatScopeQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """Mode-specific cached intelligence checked in range, with explicit freshness and coverage."""
    return DashboardService(session, request.app.state.settings).execute("threats", query)


@router.get("/users/targeted", response_model=schema.TargetedUsersResponse)
def targeted_users(
    query: Annotated[schema.RankedQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """Accounts with observed failures/denials or findings/cases; not confirmed attacks."""
    return DashboardService(session, request.app.state.settings).execute("targeted_users", query)


@router.get("/detection/rules", response_model=schema.DetectionRuleStatsResponse)
def rules(
    query: Annotated[schema.TimeRangeQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """Stored rules, enabled/default severity and matching finding counts, not executions."""
    return DashboardService(session, request.app.state.settings).execute("rules", query)


@router.get("/risk/distribution", response_model=schema.RiskDistributionResponse)
def risk_distribution(
    query: Annotated[schema.TimeRangeQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """Current incident scores only, using the existing Phase 7 boundaries."""
    return DashboardService(session, request.app.state.settings).execute("risk_distribution", query)


@router.get("/activity/summary", response_model=schema.ActivitySummaryResponse)
def activity(
    query: Annotated[schema.TimeRangeQuery, Query()],
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """Observed event-type counts; no payloads and no security verdict inferred."""
    return DashboardService(session, request.app.state.settings).execute("activity", query)


@router.get("/system/health", response_model=schema.DashboardHealthResponse)
def health(
    request: Request,
    user: Reader,
    session: SessionDep,
):
    """Database-backed readiness and processing backlog; providers are configuration only."""
    return DashboardService(session, request.app.state.settings).execute("health")
