"""Versioned development policy. These mappings are not enterprise standards."""

import hashlib
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCORE_VERSION = "v1"
SEVERITY_POINTS = {"LOW": 5, "MEDIUM": 12, "HIGH": 20, "CRITICAL": 25}
REPUTATION_BANDS = ((90, 10), (75, 7), (25, 4))
ADMIN_BEHAVIOUR_POINTS = 15
OTHER_ROLE_BEHAVIOUR_POINTS = 5
MISSING_APPROVAL_POINTS = 5
API_COMPRESSION_MAX = 10
API_ERROR_COMPOSITION_MAX = 5
CAPS = {
    "severity": 25,
    "confidence": 15,
    "behavioural_intensity": 20,
    "event_frequency": 15,
    "asset_sensitivity": 15,
    "reputation": 10,
}
Sensitivity = Annotated[int, Field(strict=True, ge=0, le=15)]


class RiskScoringConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    severity_max: Literal[25] = 25
    confidence_max: Literal[15] = 15
    behavioural_max: Literal[20] = 20
    frequency_max: Literal[15] = 15
    sensitivity_max: Literal[15] = 15
    reputation_max: Literal[10] = 10
    intensity_full_ratio: float = Field(default=10, ge=2, le=100, allow_inf_nan=False)
    success_lookahead_seconds: int = Field(default=300, ge=1, le=3600)
    success_bonus: int = Field(default=4, ge=0, le=10)
    unusual_full_hours: float = Field(default=6, ge=1, le=12, allow_inf_nan=False)
    denied_resource_full_count: int = Field(default=10, ge=2, le=100)
    administrative_ports: list[Annotated[int, Field(ge=0, le=65535)]] = [22, 3389, 5432, 3306]
    administrative_port_sensitivity: Sensitivity = 12
    sensitive_record_points: Sensitivity = 12
    default_service_points: Sensitivity = 0
    service_points: dict[str, Sensitivity] = {
        "employee-portal": 4,
        "files-service": 7,
        "records-api": 12,
        "identity-service": 13,
        "admin-console": 15,
        "database": 15,
        "authentication": 10,
    }
    action_points: dict[str, Sensitivity] = {
        "LOGIN_FAILED": 7,
        "LOGIN_SUCCESS": 7,
        "API_REQUEST": 4,
        "FILE_ACCESS": 7,
        "SENSITIVE_RECORD_ACCESS": 12,
        "ADMIN_LOGIN": 12,
        "PRIVILEGE_CHANGE": 7,
        "ACCESS_DENIED": 7,
        "PORT_CONNECTION": 4,
    }
    role_points: dict[str, Sensitivity] = {"ADMIN": 15, "ADMINISTRATOR": 15, "MANAGER": 9}
    endpoint_points: dict[str, Sensitivity] = {
        "/admin": 15,
        "/identity": 13,
        "/records": 12,
        "/health": 1,
        "/api/admin": 15,
        "/api/records": 12,
    }
    account_points: dict[str, Sensitivity] = {}
    destination_points: dict[str, Sensitivity] = {}

    @model_validator(mode="after")
    def policy_bounds(self):
        if (
            sum(
                getattr(self, key)
                for key in (
                    "severity_max",
                    "confidence_max",
                    "behavioural_max",
                    "frequency_max",
                    "sensitivity_max",
                    "reputation_max",
                )
            )
            != 100
        ):
            raise ValueError("Risk component maximums must sum to 100")
        for name in (
            "service_points",
            "action_points",
            "role_points",
            "endpoint_points",
            "account_points",
            "destination_points",
        ):
            mapping = getattr(self, name)
            if len(mapping) > 500 or any(not key or len(key) > 255 for key in mapping):
                raise ValueError("Sensitivity maps require at most 500 nonempty bounded keys")
        if any(not key.startswith("/") for key in self.endpoint_points):
            raise ValueError("Endpoint mappings must start with a slash")
        return self

    @property
    def fingerprint(self):
        return hashlib.sha256(
            json.dumps(
                self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        ).hexdigest()
