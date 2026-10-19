from typing import Any, Literal

from pydantic import AwareDatetime, Field, field_validator

from app.schemas.common import Schema, Score
from app.threat_intelligence.utils.ip_validation import validate_ip

Mode = Literal["mock", "live"]
Level = Literal["MALICIOUS", "SUSPICIOUS", "NO_ADVERSE_SIGNALS", "UNKNOWN"]
Status = Literal[
    "success",
    "unknown",
    "not_applicable",
    "not_configured",
    "disabled",
    "auth_error",
    "rate_limited",
    "timeout",
    "provider_error",
    "invalid_response",
    "not_found",
]


class ProviderResult(Schema):
    provider: str
    indicator: str
    lookup_status: Status
    reputation_level: Level = "UNKNOWN"
    malicious: bool | None = None
    provider_score: int | None = None
    normalized_score: Score | None = None
    reports: int | None = Field(default=None, ge=0)
    country: str | None = None
    isp: str | None = None
    tags: list[str] = Field(default_factory=list)
    checked_at: AwareDatetime
    expires_at: AwareDatetime
    last_seen: AwareDatetime | None = None
    simulation: bool = False
    explanation: str
    raw_response: dict[str, Any] = Field(default_factory=dict)
    retry_at: AwareDatetime | None = None
    http_status: int | None = None


class IntelligenceResponse(Schema):
    indicator: str
    indicator_type: Literal["IP"] = "IP"
    mode: Mode
    simulation: bool
    data_label: str
    lookup_status: str
    reputation_level: Level
    normalized_score: Score | None
    malicious: bool | None
    sources_checked: int
    sources_with_adverse_signals: int
    partial: bool
    explanation: str
    providers: list[ProviderResult]
    checked_at: AwareDatetime
    expires_at: AwareDatetime
    first_seen: AwareDatetime | None = None
    cache_hit: bool = False
    stale: bool = False
    configuration_changed: bool = False
    external_requests: int = 0
    provider_evaluations: int = 0
    provider_cache_hits: int = 0
    duration_ms: float = 0


class LookupRequest(Schema):
    ip: str = Field(min_length=1, max_length=64)
    force_refresh: bool = False

    @field_validator("ip")
    @classmethod
    def canonical(cls, value):
        return validate_ip(value).ip


class ThreatQuery(Schema):
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=1000000)
    indicator: str | None = Field(default=None, max_length=64)
    provider: str | None = Field(default=None, max_length=64)
    reputation_level: Level | None = None
    malicious: bool | None = None
    last_checked: AwareDatetime | None = None
    mode: Mode | None = None

    @field_validator("indicator")
    @classmethod
    def canonical(cls, value):
        return validate_ip(value).ip if value is not None else None


class ThreatPage(Schema):
    items: list[IntelligenceResponse]
    total: int
    limit: int
    offset: int


class EnrichRequest(Schema):
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=1000000)
    force_refresh: bool = False
    incident_id: str | None = Field(default=None, min_length=1, max_length=64)


class EnrichmentSummary(Schema):
    mode: Mode
    simulation: bool
    incidents_evaluated: int = 0
    unique_indicators: int = 0
    indicators_evaluated: int = 0
    cache_hits: int = 0
    external_lookups: int = 0
    provider_requests: int = 0
    provider_evaluations: int = 0
    failed_lookups: int = 0
    unknown_lookups: int = 0
    incidents_enriched: int = 0
    duration_ms: float = 0
    complete: bool = True
    next_offset: int | None = None
    error: str | None = None


class RelatedIntelligence(Schema):
    entity_id: str
    entity_type: Literal["finding", "incident"]
    mode: Mode
    indicators: list[IntelligenceResponse]
    missing_indicators: list[str]
    total_indicators: int
    limit: int
    offset: int


class ProviderStateResponse(Schema):
    name: str
    configured: bool
    enabled: bool
    active: bool
    next_allowed_at: AwareDatetime | None = None
    last_status: str | None = None


class ProviderStatusResponse(Schema):
    enabled: bool
    mode: Mode
    simulation: bool
    providers: list[ProviderStateResponse]
    note: str = "Configuration and stored cooldown only; this endpoint makes no external requests."


class RelatedQuery(Schema):
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=1000000)
    mode: Mode | None = None
