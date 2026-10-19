from typing import Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, IPvAnyAddress, model_validator

from app.core.enums import SeverityLevel
from app.risk.config import SCORE_VERSION
from app.schemas.common import CreatedResponse, Schema


class RiskRunRequest(Schema):
    finding: str | None = Field(default=None, min_length=1, max_length=64)
    rule: str | None = Field(default=None, pattern=r"^CS-\d{3}$")
    batch_size: int | None = Field(default=None, ge=1, le=500)
    until_empty: bool = False
    rescore: bool = False
    reputation_source: Literal["local", "cached"] = "local"
    dry_run: bool = False


class RiskRunResponse(Schema):
    run_id: UUID
    score_version: str = SCORE_VERSION
    config_hash: str
    findings_evaluated: int = 0
    assessments_created: int = 0
    assessments_updated: int = 0
    unchanged_assessments: int = 0
    already_scored: int = 0
    invalid_findings: int = 0
    batches: int = 0
    duration_ms: float = 0
    average_score: float = 0
    by_level: dict[str, int] = Field(default_factory=lambda: {x.value: 0 for x in SeverityLevel})
    complete: bool = True
    remaining_unscored: int | None = None
    dry_run: bool = False
    rescore: bool = False
    error: str | None = None
    skipped: list[dict[str, str]] = Field(default_factory=list)
    previews: list[dict[str, Any]] = Field(default_factory=list)


class RiskResponse(CreatedResponse):
    assessment_id: str
    detection_finding_id: UUID
    finding_id: str
    rule_id: str
    source_ip: IPvAnyAddress | None
    username: str | None
    detection_severity: SeverityLevel
    detection_confidence: int
    risk_score: int
    risk_level: SeverityLevel
    score_version: str
    config_hash: str
    input_hash: str
    severity_score: int
    confidence_score: int
    behavioural_score: int
    frequency_score: int
    asset_sensitivity_score: int
    reputation_score: int
    breakdown: dict[str, Any]
    evidence_summary: dict[str, Any]
    calculated_at: AwareDatetime


class RiskQuery(Schema):
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0, le=1000000)
    risk_level: SeverityLevel | None = None
    minimum_score: int | None = Field(default=None, ge=0, le=100)
    maximum_score: int | None = Field(default=None, ge=0, le=100)
    rule_id: str | None = Field(default=None, pattern=r"^CS-\d{3}$")
    finding_id: str | None = Field(default=None, max_length=64)
    source_ip: IPvAnyAddress | None = None
    username: str | None = Field(default=None, max_length=255)
    start_time: AwareDatetime | None = None
    end_time: AwareDatetime | None = None
    score_version: str = Field(default=SCORE_VERSION, min_length=1, max_length=32)

    @model_validator(mode="after")
    def ordered(self):
        if (
            self.minimum_score is not None
            and self.maximum_score is not None
            and self.minimum_score > self.maximum_score
        ):
            raise ValueError("minimum_score must not exceed maximum_score")
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValueError("start_time must not exceed end_time")
        return self


class RiskListResponse(Schema):
    items: list[RiskResponse]
    total: int
    limit: int
    offset: int


class RiskStats(Schema):
    score_version: str
    total_assessments: int
    average_score: float
    highest_score: int
    by_level: dict[str, int]


def assessment_response(row):
    finding = row.finding
    values = {key: getattr(row, key) for key in RiskResponse.model_fields if hasattr(row, key)}
    return RiskResponse(
        **values,
        finding_id=finding.finding_id,
        rule_id=finding.rule.rule_id,
        source_ip=finding.source_ip,
        username=finding.username,
        detection_severity=finding.severity,
        detection_confidence=finding.confidence,
        evidence_summary={
            "event_count": finding.event_count,
            "event_ids": finding.evidence_event_ids,
            "first_seen": finding.first_seen.isoformat(),
            "last_seen": finding.last_seen.isoformat(),
            "truncated": finding.evidence_data.get("evidence_truncated", False),
        },
    )
