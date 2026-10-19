from decimal import Decimal
from typing import Any
from uuid import UUID

from pydantic import AliasChoices, AwareDatetime, Field

from app.schemas.common import Schema, utc_now


class SystemMetricCreate(Schema):
    metric_name: str = Field(min_length=1, max_length=100)
    metric_value: Decimal = Field(max_digits=20, decimal_places=6, allow_inf_nan=False)
    unit: str = Field(min_length=1, max_length=32)
    timestamp: AwareDatetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("metric_metadata", "metadata"),
    )

    def to_model_values(self) -> dict[str, Any]:
        values = self.model_dump()
        values["metric_metadata"] = values.pop("metadata")
        return values


class SystemMetricResponse(SystemMetricCreate):
    id: UUID
