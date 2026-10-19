from typing import Any

from pydantic import Field

from app.core.enums import SeverityLevel
from app.schemas.common import Schema, UpdatedResponse


class DetectionRuleCreate(Schema):
    rule_id: str = Field(min_length=1, max_length=32, pattern=r"^CS-\d{3}$")
    name: str = Field(min_length=1, max_length=150)
    description: str = Field(min_length=1, max_length=10000)
    severity: SeverityLevel
    enabled: bool = True
    configuration: dict[str, Any] = Field(default_factory=dict)


class DetectionRuleResponse(DetectionRuleCreate, UpdatedResponse):
    pass
