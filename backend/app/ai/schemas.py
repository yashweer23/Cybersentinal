from datetime import datetime
from typing import Literal

from pydantic import Field

from app.schemas.common import Schema

Mode = Literal["AI", "FALLBACK"]


class AnalyzeRequest(Schema):
    force_refresh: bool = False


class AskRequest(Schema):
    question: str = Field(min_length=3, max_length=800)


class Reference(Schema):
    reference_id: str
    kind: Literal["incident", "finding", "event", "risk", "indicator", "note", "audit"]
    label: str


class Evidence(Schema):
    statement: str = Field(min_length=1, max_length=3000)
    reference_ids: list[str] = Field(max_length=12)


class AnalysisContent(Schema):
    summary: str
    why_flagged: str
    risk_explanation: list[Evidence]
    key_evidence: list[Evidence]
    potential_impact: str
    investigation_steps: list[str]
    recommended_actions: list[str]
    uncertainty: str
    references: list[Reference]
    coverage: dict[str, int]


class AnalysisResponse(AnalysisContent):
    analysis_id: str
    incident_id: str
    analysis_mode: Mode
    provider: str
    model: str | None
    generated_at: datetime
    generated_by_user_id: str | None
    context_hash: str
    is_current: bool
    stale: bool
    cached: bool = False
    fallback_reason: str | None = None
    context_build_ms: float
    provider_duration_ms: float
    duration_ms: float


class AnalysisRead(Schema):
    analysis: AnalysisResponse | None


class HistoryPage(Schema):
    items: list[AnalysisResponse]
    total: int
    limit: int
    offset: int


class AIStatus(Schema):
    enabled: bool
    configured: bool
    mode: Literal["AI", "FALLBACK", "DISABLED"]
    status: Literal["READY", "FALLBACK", "DISABLED", "CONFIGURED"]
    provider: str
    model: str | None = None
    note: str


class AnswerResponse(Schema):
    incident_id: str
    analysis_mode: Mode
    answer: str
    evidence_ids: list[str]
    references: list[Reference]
    confidence: Literal["HIGH", "LIMITED", "INSUFFICIENT"]
    uncertainty: str
    context_hash: str
    fallback_reason: str | None = None
    context_build_ms: float
    provider_duration_ms: float
    duration_ms: float


class OverviewResponse(Schema):
    analysis_mode: Literal["FALLBACK"] = "FALLBACK"
    query: str
    scope: str
    answer: str
    evidence: list[dict[str, str | int | None]]
    total: int
    truncated: bool
    generated_at: datetime
    note: str = "Controlled read-only database query; no model-generated SQL or external call."


class EvidencePlan(Schema):
    """Only IDs may be generated; server-owned statements cannot be overwritten."""

    incident_id: str
    context_hash: str
    risk_score: int = Field(ge=0, le=100, strict=True)
    summary_fact_ids: list[str] = Field(min_length=1, max_length=5)
    evidence_fact_ids: list[str] = Field(min_length=1, max_length=12)
    investigation_action_ids: list[str] = Field(min_length=1, max_length=8)
    recommendation_action_ids: list[str] = Field(min_length=1, max_length=8)
