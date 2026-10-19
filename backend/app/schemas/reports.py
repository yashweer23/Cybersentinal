from typing import Any, Literal

from pydantic import Field

from app.schemas.analytics import AnalyticsQuery
from app.schemas.common import Schema
from app.schemas.dashboard import DashboardScope, UTCTime

ReportType = Literal[
    "security-summary",
    "incidents",
    "detection-findings",
    "risk-assessments",
    "threat-indicators",
    "analyst-workload",
    "detection-rules",
]


class ReportQuery(AnalyticsQuery):
    format: Literal["json", "csv"] = "json"
    limit: int = Field(default=1000, ge=1, le=5000)
    offset: int = Field(default=0, ge=0, le=1000000)


class ReportResponse(Schema):
    report_type: ReportType
    generated_at: UTCTime
    scope: DashboardScope
    definition: str
    returned_rows: int
    limit: int
    offset: int
    has_more: bool
    next_offset: int | None
    columns: list[str]
    rows: list[dict[str, Any]]
    sections: dict[str, Any] = Field(default_factory=dict)
