"""Compact read-only dashboard contracts; UTC scopes and bounded result sets."""

from datetime import UTC
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BeforeValidator,
    Field,
    field_validator,
    model_validator,
)

from app.ai.schemas import AIStatus
from app.core.enums import IncidentStatus, SeverityLevel
from app.core.event_validation import timestamp_input
from app.schemas.common import Schema, Score
from app.schemas.incident import AnalystReference
from app.threat_intelligence.schemas import Level, Mode, ProviderStatusResponse

Preset = Literal["1h", "6h", "24h", "7d", "30d", "90d"]
UTCTime = Annotated[AwareDatetime, AfterValidator(lambda value: value.astimezone(UTC))]
# Decimal strings avoid JavaScript's loss of precision above 2**53.
Cursor = Annotated[str, BeforeValidator(str), Field(pattern=r"^[0-9]+$")]


class TimeRangeQuery(Schema):
    range: Preset | None = Field(default=None, description="Default 24h; excludes custom start/end")
    start: AwareDatetime | None = None
    end: AwareDatetime | None = None
    _iso = field_validator("start", "end", mode="before")(timestamp_input)

    @model_validator(mode="after")
    def complete_range(self) -> Self:
        if (self.start is None) != (self.end is None):
            raise ValueError("Supply both start and end, or a range preset")
        if self.range is not None and self.start is not None:
            raise ValueError("Use a range preset or custom start/end, not both")
        if self.start is not None and self.start >= self.end:
            raise ValueError("start must precede end")
        return self


class RecentQuery(TimeRangeQuery):
    limit: int = Field(default=20, ge=1, le=100)


class RankedQuery(TimeRangeQuery):
    limit: int = Field(default=10, ge=1, le=20)


class ThreatScopeQuery(TimeRangeQuery):
    mode: Mode | None = None


class TopIPQuery(RankedQuery):
    mode: Mode | None = None


class UpdatesQuery(Schema):
    after_id: int | None = Field(default=None, ge=0, le=9223372036854775807)
    limit: int = Field(default=20, ge=1, le=100)


class DashboardScope(Schema):
    start: UTCTime
    end: UTCTime
    preset: Preset | None
    as_of: UTCTime
    boundary: Literal["[start,end)"] = "[start,end)"


class DashboardOverviewResponse(Schema):
    scope: DashboardScope
    total_events: int
    events_in_range: int
    total_incidents: int
    active_incidents: int
    critical_incidents: int
    high_risk_incidents: int
    total_findings: int
    suspicious_ips: int
    average_risk_score: float | None
    unprocessed_events: int
    latest_event_timestamp: UTCTime | None


class TimelinePoint(Schema):
    timestamp: UTCTime
    total: int = 0
    login_failed: int = 0
    access_denied: int = 0
    api_requests: int = 0


class SecurityTimelineResponse(Schema):
    scope: DashboardScope
    interval: Literal["minute", "15_minutes", "hour", "day"]
    bucket_seconds: int
    total: int
    data: list[TimelinePoint]


class SeverityCount(Schema):
    severity: SeverityLevel
    count: int


class SeverityDistributionResponse(Schema):
    scope: DashboardScope
    total: int
    distribution: list[SeverityCount]


class StatusCount(Schema):
    status: IncidentStatus
    count: int


class StatusDistributionResponse(Schema):
    scope: DashboardScope
    total: int
    distribution: list[StatusCount]


class EventTypeCount(Schema):
    event_type: str
    count: int


class EventTypeDistributionResponse(Schema):
    scope: DashboardScope
    total: int
    distribution: list[EventTypeCount]


class EventPreview(Schema):
    id: UUID
    ingestion_sequence: Cursor
    event_id: str
    timestamp: UTCTime
    event_type: str
    source_ip: str
    destination_ip: str | None
    username: str | None
    service: str | None
    status: str
    processed: bool


class RecentEventsResponse(Schema):
    scope: DashboardScope
    items: list[EventPreview]
    limit: int
    polling_cursor: Cursor


class EventUpdatesResponse(Schema):
    items: list[EventPreview]
    next_cursor: Cursor
    head_cursor: Cursor
    has_more: bool
    initialized: bool = False


class IncidentPreview(Schema):
    incident_id: str
    title: str
    severity: SeverityLevel
    risk_score: Score
    status: IncidentStatus
    source_ip: str | None
    username: str | None
    assigned_analyst: AnalystReference | None
    detected_at: UTCTime


class RecentIncidentsResponse(Schema):
    scope: DashboardScope
    items: list[IncidentPreview]
    limit: int


class SuspiciousIP(Schema):
    ip: str
    incident_count: int
    finding_count: int
    highest_risk_score: Score | None
    highest_finding_risk_score: Score | None
    latest_activity: UTCTime
    reputation_level: Level = "UNKNOWN"
    cached_reputation_level: Level | None = None
    intelligence_status: Literal["fresh", "expired", "incompatible", "missing"]
    mode: Mode
    simulation: bool


class TopSuspiciousIPsResponse(Schema):
    scope: DashboardScope
    mode: Mode
    items: list[SuspiciousIP]
    limit: int
    ranking: str = (
        "incident risk DESC, incident count DESC, finding count DESC, latest activity DESC, IP ASC"
    )
    finding_score_version: str


class TargetedUser(Schema):
    username: str
    failed_logins: int
    access_denials: int
    finding_count: int
    incident_count: int


class TargetedUsersResponse(Schema):
    scope: DashboardScope
    items: list[TargetedUser]
    limit: int
    ranking: str = (
        "finding count DESC, incident count DESC, failed logins + denials DESC, username ASC"
    )


class RuleStatistic(Schema):
    rule_id: str
    name: str
    enabled: bool
    severity: SeverityLevel
    finding_count: int
    latest_finding_timestamp: UTCTime | None


class DetectionRuleStatsResponse(Schema):
    scope: DashboardScope
    items: list[RuleStatistic]


class ThreatSummaryResponse(Schema):
    scope: DashboardScope
    mode: Mode
    simulation: bool
    cached_indicators: int
    malicious_indicators: int
    suspicious_indicators: int
    no_adverse_signal_indicators: int
    unknown_indicators: int
    expired_indicators: int
    incompatible_indicators: int
    last_refresh: UTCTime | None
    cache_hits: int
    providers: ProviderStatusResponse


class RiskCount(Schema):
    level: SeverityLevel
    count: int


class RiskDistributionResponse(Schema):
    scope: DashboardScope
    population: Literal["current_incident_scores"] = "current_incident_scores"
    total: int
    distribution: list[RiskCount]
    average_risk_score: float | None


class ActivitySummaryResponse(Schema):
    scope: DashboardScope
    successful_logins: int
    failed_logins: int
    access_denials: int
    api_requests: int
    sensitive_record_accesses: int
    privilege_changes: int


class ProcessingHealth(Schema):
    status: Literal["available_on_demand"] = "available_on_demand"
    events_processed: int
    unprocessed_events: int
    last_processing_time: UTCTime | None
    last_processing_duration_ms: float | None


class DashboardHealthResponse(Schema):
    as_of: UTCTime
    api: Literal["healthy"] = "healthy"
    database: Literal["connected"] = "connected"
    detection_engine: ProcessingHealth
    threat_intelligence: ProviderStatusResponse
    ai_analyst: AIStatus
    total_events: int
    latest_event_timestamp: UTCTime | None
