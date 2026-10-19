from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy.orm import Session

from app.core.enums import UserRole
from app.core.errors import ServiceError
from app.database import get_db
from app.models import User
from app.schemas.reports import ReportQuery, ReportResponse, ReportType
from app.security.dependencies import require_roles
from app.services.reporting_service import ReportingService, csv_document

router = APIRouter(
    prefix="/api/reports",
    tags=["Security reports"],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "ADMIN/ANALYST exports; ADMIN workload"},
        422: {"description": "Invalid range, type or export bounds"},
        503: {"description": "Database unavailable"},
    },
)


@router.get(
    "/{report_type}",
    response_model=ReportResponse,
    responses={200: {"content": {"text/csv": {"schema": {"type": "string"}}}}},
)
def report(
    report_type: ReportType,
    query: Annotated[ReportQuery, Query()],
    request: Request,
    session: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST))],
):
    if report_type == "analyst-workload" and user.role != UserRole.ADMIN:
        raise ServiceError(403, "Analyst workload exports require ADMIN")
    result = ReportingService(session, request.app.state.settings).generate(report_type, query)
    if query.format == "json":
        return result
    filename = (
        f"{report_type}_{result.scope.start:%Y%m%d}_{result.scope.end:%Y%m%d}_{query.offset}.csv"
    )
    return Response(
        csv_document(result),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Export-Rows": str(result.returned_rows),
            "X-Export-Has-More": str(result.has_more).lower(),
            "X-Export-Next-Offset": str(result.next_offset)
            if result.next_offset is not None
            else "",
            "X-Report-Start": result.scope.start.isoformat(),
            "X-Report-End": result.scope.end.isoformat(),
        },
    )
