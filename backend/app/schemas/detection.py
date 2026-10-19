from typing import Any
from uuid import UUID

from pydantic import AwareDatetime, Field, IPvAnyAddress, model_validator

from app.core.enums import SeverityLevel
from app.schemas.common import CreatedResponse, Schema
from app.schemas.detection_rule import DetectionRuleResponse


class DetectionRunRequest(Schema):
    batch_size: int | None = Field(default=None, ge=1, le=1000)
    until_empty: bool = False
    rule: str | None = Field(default=None, pattern=r"^CS-\d{3}$")
    dry_run: bool = False
    replay: bool = False


class DetectionRunResponse(Schema):
    run_id: UUID
    events_evaluated: int = 0
    events_processed: int = 0
    findings_matched: int = 0
    findings_created: int = 0
    duplicate_findings: int = 0
    rules_executed: int = 0
    rule_matches: dict[str, int] = Field(default_factory=dict)
    batches: int = 0
    duration_ms: float = 0
    unprocessed_events: int | None = None
    complete: bool = True
    dry_run: bool = False
    selected_rule: str | None = None
    replay: bool = False
    error: str | None = None
    findings_preview: list[dict[str, Any]] = Field(default_factory=list)


class FindingResponse(CreatedResponse):
    finding_id: str
    detection_rule_id: UUID
    rule: DetectionRuleResponse
    title: str
    description: str
    severity: SeverityLevel
    confidence: int
    source_ip: IPvAnyAddress | None
    username: str | None
    primary_event_id: UUID
    evidence_event_ids: list[str]
    evidence_data: dict[str, Any]
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    event_count: int
    entity_key: str
    fingerprint: str


class FindingQuery(Schema):
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0, le=1000000)
    rule_id: str | None = Field(default=None, pattern=r"^CS-\d{3}$")
    severity: SeverityLevel | None = None
    source_ip: IPvAnyAddress | None = None
    username: str | None = Field(default=None, max_length=255)
    start_time: AwareDatetime | None = None
    end_time: AwareDatetime | None = None

    @model_validator(mode="after")
    def ordered(self):
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValueError("start_time must not be after end_time")
        return self


class FindingListResponse(Schema):
    items: list[FindingResponse]
    total: int
    limit: int
    offset: int


class DetectionStats(Schema):
    total_findings: int
    by_rule: dict[str, int]
    by_severity: dict[str, int]
    unprocessed_events: int


class RuleUpdate(Schema):
    enabled: bool | None = None
    severity: SeverityLevel | None = None
    configuration: dict[str, Any] | None = None

    @model_validator(mode="after")
    def nonempty(self):
        if not self.model_fields_set or any(
            getattr(self, name) is None for name in self.model_fields_set
        ):
            raise ValueError("Supply at least one non-null rule setting")
        return self
