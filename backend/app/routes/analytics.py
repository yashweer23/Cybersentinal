"""Protected Phase 14 analytics; existing Phase 10 routes remain intact."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.core.enums import UserRole
from app.database import get_db
from app.models import User
from app.schemas import analytics as schema
from app.security.dependencies import get_current_user, require_roles
from app.services.security_analytics import SecurityAnalyticsService

router = APIRouter(
    prefix="/api/analytics",
    tags=["Advanced security analytics"],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "Role not permitted"},
        422: {"description": "Invalid UTC range or filters"},
        503: {"description": "Database unavailable"},
    },
)
Reader = Annotated[User, Depends(get_current_user)]
Admin = Annotated[User, Depends(require_roles(UserRole.ADMIN))]
DB = Annotated[Session, Depends(get_db)]
QueryScope = Annotated[schema.AnalyticsQuery, Query()]


def execute(request, session, operation, query):
    return SecurityAnalyticsService(session, request.app.state.settings).execute(operation, query)


@router.get("/overview", response_model=schema.Overview)
def overview(query: QueryScope, request: Request, session: DB, user: Reader):
    return execute(request, session, "overview", query)


@router.get("/events/trend", response_model=schema.EventTrend)
def events(
    query: Annotated[schema.EventTrendQuery, Query()], request: Request, session: DB, user: Reader
):
    return execute(request, session, "events", query)


@router.get("/incidents/trend", response_model=schema.IncidentTrend)
def incidents(query: QueryScope, request: Request, session: DB, user: Reader):
    return execute(request, session, "incidents", query)


@router.get("/detections/rules", response_model=schema.RulePerformance)
def rules(query: QueryScope, request: Request, session: DB, user: Reader):
    return execute(request, session, "rules", query)


@router.get("/risk/trend", response_model=schema.RiskTrend)
def risk(query: Annotated[schema.RiskQuery, Query()], request: Request, session: DB, user: Reader):
    return execute(request, session, "risk_trend", query)


@router.get("/risk/histogram", response_model=schema.Histogram)
def histogram(
    query: Annotated[schema.RiskQuery, Query()], request: Request, session: DB, user: Reader
):
    return execute(request, session, "histogram", query)


@router.get("/entities/high-risk", response_model=schema.EntityAnalytics)
def entities(
    query: Annotated[schema.EntityQuery, Query()], request: Request, session: DB, user: Reader
):
    return execute(request, session, "entities", query)


@router.get("/incidents/backlog", response_model=schema.Backlog)
def backlog(query: QueryScope, request: Request, session: DB, user: Reader):
    return execute(request, session, "backlog", query)


@router.get("/analysts/workload", response_model=schema.Workload)
def workload(
    query: Annotated[schema.WorkloadQuery, Query()], request: Request, session: DB, user: Admin
):
    return execute(request, session, "workload", query)


@router.get("/threat-intelligence", response_model=schema.IntelligenceAnalytics)
def intelligence(query: QueryScope, request: Request, session: DB, user: Reader):
    return execute(request, session, "intelligence", query)


@router.get("/categories", response_model=schema.Categories)
def categories(query: QueryScope, request: Request, session: DB, user: Reader):
    return execute(request, session, "categories", query)


@router.get("/geography", response_model=schema.Geography)
def geography(query: QueryScope, request: Request, session: DB, user: Reader):
    return execute(request, session, "geography", query)


@router.get("/ai/usage", response_model=schema.AIUsage)
def ai_usage(query: QueryScope, request: Request, session: DB, user: Reader):
    return execute(request, session, "ai", query)


@router.get("/detections/evaluation", response_model=schema.SyntheticEvaluation)
def evaluation(query: QueryScope, request: Request, session: DB, user: Reader):
    return execute(request, session, "evaluation", query)


@router.get("/incidents/status-history", response_model=schema.StatusHistory)
def status_history(query: QueryScope, request: Request, session: DB, user: Reader):
    return execute(request, session, "status_history", query)
