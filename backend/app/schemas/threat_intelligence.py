from typing import Any, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from app.core.enums import IndicatorType
from app.core.validation import normalize_indicator
from app.schemas.common import Confidence, Schema, Score, utc_now


class ThreatIntelligenceCreate(Schema):
    indicator: str = Field(min_length=1, max_length=253)
    indicator_type: IndicatorType
    malicious: bool | None = False
    abuse_score: Score | None = 0
    confidence_score: Confidence | None = 0
    reports: int | None = Field(default=0, ge=0)
    country: str | None = Field(default=None, max_length=100)
    isp: str | None = Field(default=None, max_length=255)
    source: list[str] = Field(default_factory=list)
    raw_response: dict[str, Any] = Field(default_factory=dict)
    first_seen: AwareDatetime = Field(default_factory=utc_now)
    last_checked: AwareDatetime = Field(default_factory=utc_now)
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def validate_cache_entry(self) -> Self:
        self.indicator = normalize_indicator(self.indicator, self.indicator_type)
        if self.first_seen > self.last_checked:
            raise ValueError("first_seen must not be after last_checked")
        if self.expires_at <= self.last_checked:
            raise ValueError("expires_at must be after last_checked")
        return self


class ThreatIntelligenceResponse(ThreatIntelligenceCreate):
    id: UUID
