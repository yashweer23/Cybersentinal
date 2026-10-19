from typing import Any, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, IPvAnyAddress, model_validator

from app.core.enums import IncidentStatus, SeverityLevel
from app.schemas.common import Confidence, Schema, Score, UpdatedResponse
from app.schemas.risk import RiskResponse


class IncidentCreate(Schema):
    incident_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=10000)
    detection_rule_id: UUID
    source_ip: IPvAnyAddress | None = None
    username: str | None = Field(default=None, max_length=255)
    risk_score: Score
    severity: SeverityLevel
    confidence: Confidence
    status: IncidentStatus = IncidentStatus.OPEN
    assigned_analyst_id: UUID | None = None
    detected_at: AwareDatetime
    resolved_at: AwareDatetime | None = None
    ai_analysis: dict[str, Any] | None = None
    recommended_actions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_resolution_time(self) -> Self:
        if self.resolved_at is not None and self.resolved_at < self.detected_at:
            raise ValueError("resolved_at must not precede detected_at")
        return self


class IncidentResponse(IncidentCreate, UpdatedResponse):
    pass


# Phase 8 API schemas are explicit projections; legacy create/response schemas remain compatible.
from typing import Literal  # noqa: E402

from pydantic import field_validator  # noqa: E402


class IncidentPageQuery(Schema):
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0, le=1000000)


class EligibleAnalystQuery(IncidentPageQuery):
    q: str | None = Field(default=None, min_length=1, max_length=100)


class IncidentEventQuery(IncidentPageQuery):
    event_type: str | None = Field(default=None, min_length=1, max_length=64)
    source_ip: IPvAnyAddress | None = None
    username: str | None = Field(default=None, min_length=1, max_length=255)
    service: str | None = Field(default=None, min_length=1, max_length=100)
    status: str | None = Field(default=None, min_length=1, max_length=32)


class TimelineQuery(IncidentPageQuery):
    order: Literal["asc", "desc"] = "asc"


class IncidentQuery(IncidentPageQuery):
    status: IncidentStatus | None = None
    severity: SeverityLevel | None = None
    minimum_risk: Score | None = None
    maximum_risk: Score | None = None
    assigned_analyst: UUID | None = None
    username: str | None = Field(default=None, min_length=1, max_length=255)
    source_ip: IPvAnyAddress | None = None
    rule_id: str | None = Field(default=None, pattern=r"^CS-\d{3}$")
    start_time: AwareDatetime | None = None
    end_time: AwareDatetime | None = None

    @model_validator(mode="after")
    def ordered_filters(self):
        if (
            self.minimum_risk is not None
            and self.maximum_risk is not None
            and self.minimum_risk > self.maximum_risk
        ):
            raise ValueError("minimum_risk must not exceed maximum_risk")
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValueError("start_time must not exceed end_time")
        return self


class IncidentRunRequest(Schema):
    until_empty: bool = False
    minimum_risk: int | None = Field(default=None, ge=0, le=100, strict=True)
    finding: str | None = Field(default=None, min_length=1, max_length=64)
    dry_run: bool = False
    batch_size: int | None = Field(default=None, ge=1, le=500, strict=True)


class IncidentDecision(Schema):
    finding_id: str
    decision: Literal["CREATE", "ATTACH", "REFRESH", "DEFER"]
    incident_id: str | None
    reason: str
    correlation: dict[str, Any] = Field(default_factory=dict)


class IncidentRunResponse(Schema):
    run_id: UUID
    policy_hash: str
    findings_evaluated: int = 0
    eligible_findings: int = 0
    incidents_created: int = 0
    incidents_updated: int = 0
    findings_attached: int = 0
    correlated_findings: int = 0
    findings_skipped: int = 0
    invalid_findings: int = 0
    projected_incidents_created: int = 0
    projected_findings_attached: int = 0
    batches: int = 0
    complete: bool = True
    dry_run: bool = False
    remaining: int = 0
    duration_ms: float = 0
    by_severity: dict[str, int] = Field(default_factory=lambda: {s.value: 0 for s in SeverityLevel})
    decisions: list[IncidentDecision] = Field(default_factory=list)
    skipped: list[dict[str, str]] = Field(default_factory=list)
    error: str | None = None


class AnalystReference(Schema):
    id: UUID
    username: str
    full_name: str | None
    role: str
    is_active: bool


class AnalystPage(Schema):
    items: list[AnalystReference]
    total: int
    limit: int
    offset: int


class IncidentSummary(UpdatedResponse):
    incident_id: str
    title: str
    description: str
    severity: SeverityLevel
    risk_score: Score
    status: IncidentStatus
    confidence: Confidence
    source_ip: IPvAnyAddress | None
    username: str | None
    assigned_analyst_id: UUID | None
    assigned_analyst: AnalystReference | None
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    detected_at: AwareDatetime
    resolved_at: AwareDatetime | None
    resolution_summary: str | None
    risk_score_version: str | None
    risk_updated_at: AwareDatetime | None


class IncidentListResponse(Schema):
    items: list[IncidentSummary]
    total: int
    limit: int
    offset: int


class LinkedFinding(Schema):
    finding_id: str
    rule_id: str
    rule_name: str
    title: str
    severity: SeverityLevel
    confidence: int
    event_count: int
    risk_score: Score | None
    risk_level: SeverityLevel | None
    score_version: str | None
    assessment_id: str | None
    source_ip: IPvAnyAddress | None
    username: str | None
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    added_at: AwareDatetime
    relationship_reason: str
    correlation_data: dict[str, Any]


class FindingPage(Schema):
    items: list[LinkedFinding]
    total: int
    limit: int
    offset: int


class IncidentEvent(Schema):
    id: UUID
    event_id: str
    timestamp: AwareDatetime
    event_type: str
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress | None
    source_port: int | None
    destination_port: int | None
    username: str | None
    service: str | None
    device: str | None
    status: str


class IncidentEventPage(Schema):
    items: list[IncidentEvent]
    total: int
    limit: int
    offset: int


class EvidenceReference(Schema):
    id: UUID
    security_event_id: UUID
    event_id: str
    detection_finding_id: UUID | None
    evidence_type: str
    description: str


class IncidentNote(UpdatedResponse):
    comment: str
    author: AnalystReference | None


class CommentPage(Schema):
    items: list[IncidentNote]
    total: int
    limit: int
    offset: int


class TimelineEntry(Schema):
    timestamp: AwareDatetime
    type: str
    title: str
    reference_id: str
    actor_id: UUID | None = None
    actor_username: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class TimelinePage(Schema):
    items: list[TimelineEntry]
    total: int
    limit: int
    offset: int


class IncidentDetail(IncidentSummary):
    findings: FindingPage
    evidence: list[EvidenceReference]
    evidence_total: int
    comments: CommentPage
    timeline: TimelinePage
    allowed_transitions: list[IncidentStatus] = Field(default_factory=list)
    risk_assessment: RiskResponse | None = None


class AssignmentRequest(Schema):
    analyst_id: UUID | None


class StatusRequest(Schema):
    status: IncidentStatus
    resolution_summary: str | None = Field(default=None, min_length=1, max_length=4000)
    reason: str | None = Field(default=None, min_length=1, max_length=4000)

    @field_validator("reason", "resolution_summary", mode="before")
    @classmethod
    def trim_note(cls, value):
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def required_note(self):
        if self.status == IncidentStatus.RESOLVED and not self.resolution_summary:
            raise ValueError("resolution_summary is required to resolve an incident")
        if self.status == IncidentStatus.FALSE_POSITIVE and not self.reason:
            raise ValueError("reason is required to mark a false positive")
        return self


class CommentRequest(Schema):
    comment: str = Field(min_length=1, max_length=4000)

    @field_validator("comment", mode="before")
    @classmethod
    def trim_comment(cls, value):
        return value.strip() if isinstance(value, str) else value


class IncidentStats(Schema):
    total: int
    open: int
    investigating: int
    resolved: int
    false_positive: int
    by_severity: dict[str, int]
    average_risk_score: float
    unassigned_incidents: int
