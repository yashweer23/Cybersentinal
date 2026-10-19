import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import Settings, get_settings
from app.core.errors import ServiceError
from app.database import build_engine
from app.operations.http import CanonicalHTTPSMiddleware, OperationalHTTPMiddleware
from app.operations.logging import configure_logging
from app.routes.access_checks import router as access_router
from app.routes.ai import router as ai_router
from app.routes.analytics import router as analytics_router
from app.routes.auth import router as auth_router
from app.routes.dashboard import router as dashboard_router
from app.routes.database import router as database_router
from app.routes.detection import router as detection_router
from app.routes.events import router as events_router
from app.routes.incidents import router as incidents_router
from app.routes.reports import router as reports_router
from app.routes.risk import router as risk_router
from app.routes.system import router as system_router
from app.routes.threats import router as threats_router
from app.routes.users import router as users_router
from app.security.ingestion_limits import IngestionBodyLimitMiddleware
from app.security.rate_limit import AuthRateLimiter


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        configure_logging(settings)
        application.state.engine = build_engine(settings)
        logging.getLogger("cybersentinel.startup").info(
            "CyberSentinel starting",
            extra={
                "environment": settings.app_env,
                "database": "configured",
                "threat_intelligence": (
                    "disabled"
                    if not settings.threat_intelligence_enabled
                    else "mock"
                    if settings.threat_intelligence_mock_mode
                    else "live (optional)"
                ),
                "ai_analyst": (
                    "disabled"
                    if not settings.ai_analyst_enabled
                    else "configured"
                    if settings.ai_provider == "openai"
                    and settings.ai_api_key.get_secret_value()
                    and settings.ai_model
                    else "fallback"
                ),
            },
        )
        try:
            yield
        finally:
            application.state.engine.dispose()
            logging.getLogger("cybersentinel.startup").info("CyberSentinel stopped; pool disposed")

    application = FastAPI(
        title="CyberSentinel API",
        description=(
            "Phase 15: operational infrastructure for the existing SOC workflows, "
            "analytics and protected reporting."
        ),
        version="0.15.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.api_docs_enabled else None,
        redoc_url="/redoc" if settings.api_docs_enabled else None,
        openapi_url="/openapi.json" if settings.api_docs_enabled else None,
    )
    application.state.settings = settings
    application.state.auth_limiter = AuthRateLimiter()
    application.state.ai_limiter = AuthRateLimiter()
    application.add_middleware(
        IngestionBodyLimitMiddleware, max_bytes=settings.ingestion_max_request_bytes
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Guard", "X-Request-ID"],
        expose_headers=[
            "X-Request-ID",
            "X-Export-Rows",
            "X-Export-Has-More",
            "X-Export-Next-Offset",
            "X-Report-Start",
            "X-Report-End",
        ],
    )

    @application.middleware("http")
    async def private_responses(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith(
            (
                "/api/auth",
                "/api/users",
                "/api/test",
                "/api/events",
                "/api/detection",
                "/api/risk",
                "/api/incidents",
                "/api/threats",
                "/api/dashboard",
                "/api/ai",
                "/api/analytics",
                "/api/reports",
            )
        ):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @application.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        if request.url.path.startswith("/api/dashboard"):
            logging.getLogger(__name__).info(
                "Dashboard input validation failed path=%s", request.url.path
            )
        # Pydantic/FastAPI errors normally include rejected inputs, including passwords.
        safe_errors = [
            {"loc": error["loc"], "msg": error["msg"], "type": error["type"]}
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": safe_errors})

    @application.exception_handler(ServiceError)
    async def service_error(request: Request, exc: ServiceError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers={"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else {},
        )

    @application.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, exc: SQLAlchemyError):
        logging.getLogger(__name__).warning("Database operation failed (%s)", type(exc).__name__)
        return JSONResponse(
            status_code=503,
            content={"detail": "Database unavailable; check connectivity and migrations"},
        )

    application.include_router(system_router)
    application.include_router(auth_router)
    application.include_router(users_router)
    application.include_router(events_router)
    application.include_router(detection_router)
    application.include_router(risk_router)
    application.include_router(incidents_router)
    application.include_router(threats_router)
    application.include_router(dashboard_router)
    application.include_router(ai_router)
    application.include_router(analytics_router)
    application.include_router(reports_router)
    if settings.app_env in {"development", "test"}:
        application.include_router(database_router)
        application.include_router(access_router)

    @application.get("/", tags=["System"])
    def root() -> dict[str, str | int | None]:
        return {
            "name": "CyberSentinel API",
            "version": "0.15.0",
            "phase": 15,
            "docs": "/docs" if settings.api_docs_enabled else None,
        }

    hosts = list(settings.allowed_hosts)
    if settings.app_env == "test":
        hosts.append("testserver")
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts, www_redirect=False)
    if settings.public_origin:
        application.add_middleware(CanonicalHTTPSMiddleware)
    application.add_middleware(OperationalHTTPMiddleware)

    return application


app = create_app()
