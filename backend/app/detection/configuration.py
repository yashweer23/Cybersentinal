"""Typed rule settings. Existing seed keys remain valid; defaults are persisted on admin updates."""

from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class RuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class WindowConfig(RuleConfig):
    window_seconds: int = Field(default=120, ge=1, le=86400)


class BruteForceConfig(WindowConfig):
    failed_attempt_threshold: int = Field(default=5, ge=2, le=10000)
    # Retained for Phase 2 compatibility. Cross-account severity is deferred; CS-002 handles it.
    multiple_users_escalation_threshold: int = Field(default=2, ge=2, le=1000)


class PasswordSprayConfig(WindowConfig):
    distinct_user_threshold: int = Field(default=8, ge=2, le=10000)
    window_seconds: int = Field(default=300, ge=1, le=86400)
    max_attempts_per_user: int = Field(default=3, ge=1, le=100)


class TravelConfig(WindowConfig):
    minimum_distance_km: float = Field(default=500, gt=0, le=20040, allow_inf_nan=False)
    max_speed_kmh: float = Field(default=900, gt=0, le=100000, allow_inf_nan=False)
    window_seconds: int = Field(default=7200, ge=1, le=604800)


class LoginTimeConfig(RuleConfig):
    normal_start_hour: int = Field(default=8, ge=0, le=23)
    normal_end_hour: int = Field(default=20, ge=0, le=24)
    timezone: str = "Asia/Kolkata"
    event_types: list[Literal["LOGIN_SUCCESS", "ADMIN_LOGIN"]] = ["LOGIN_SUCCESS", "ADMIN_LOGIN"]
    baseline_days: int = Field(default=30, ge=1, le=90)
    minimum_baseline_events: int = Field(default=20, ge=5, le=10000)
    baseline_padding_hours: int = Field(default=1, ge=0, le=4)

    @field_validator("timezone")
    @classmethod
    def timezone_exists(cls, value):
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("Use a valid IANA timezone") from None
        return value

    @model_validator(mode="after")
    def valid_hours(self):
        if self.normal_start_hour == self.normal_end_hour or not self.event_types:
            raise ValueError("Working hours must differ and event_types must not be empty")
        return self


class PrivilegeConfig(RuleConfig):
    event_type: Literal["PRIVILEGE_CHANGE"] = "PRIVILEGE_CHANGE"
    target_privileges: list[str] = Field(default=["ADMIN"], min_length=1, max_length=20)
    require_approval_reference: bool = True

    @field_validator("target_privileges")
    @classmethod
    def targets(cls, values):
        if any(not value.strip() or len(value) > 64 for value in values):
            raise ValueError("Privilege names must contain 1–64 characters")
        return values


class PortsConfig(WindowConfig):
    distinct_port_threshold: int = Field(default=20, ge=2, le=65536)
    window_seconds: int = Field(default=60, ge=1, le=86400)
    event_type: Literal["PORT_CONNECTION"] = "PORT_CONNECTION"
    passive_only: Literal[True] = True


class VolumeConfig(WindowConfig):
    baseline_enabled: bool = True
    baseline_days: int = Field(default=14, ge=2, le=60)
    minimum_baseline_days: int = Field(default=7, ge=2, le=60)
    baseline_multiplier: float = Field(default=5, ge=1, le=1000, allow_inf_nan=False)

    @model_validator(mode="after")
    def valid_baseline(self):
        if self.minimum_baseline_days > self.baseline_days:
            raise ValueError("minimum_baseline_days must not exceed baseline_days")
        return self


class AccessConfig(VolumeConfig):
    record_threshold: int = Field(default=500, ge=2, le=10000000)
    window_seconds: int = Field(default=1200, ge=1, le=86400)
    # FILE_ACCESS was the Phase 2 setting; sensitive-record events are always supported too.
    event_type: Literal["FILE_ACCESS", "SENSITIVE_RECORD_ACCESS"] = "FILE_ACCESS"
    sensitive_only: Literal[True] = True


class ReputationConfig(RuleConfig):
    abuse_score_threshold: int = Field(default=75, ge=0, le=100)
    require_unexpired_cache: bool = True


class DeniedConfig(WindowConfig):
    denied_attempt_threshold: int = Field(default=10, ge=2, le=10000)
    window_seconds: int = Field(default=300, ge=1, le=86400)


class APIConfig(VolumeConfig):
    request_threshold: int = Field(default=200, ge=2, le=1000000)
    window_seconds: int = Field(default=60, ge=1, le=86400)
    group_by: Literal["source_ip", "username"] = "source_ip"


CONFIG_TYPES = dict(
    zip(
        [f"CS-{number:03}" for number in range(1, 11)],
        [
            BruteForceConfig,
            PasswordSprayConfig,
            TravelConfig,
            LoginTimeConfig,
            PrivilegeConfig,
            PortsConfig,
            AccessConfig,
            ReputationConfig,
            DeniedConfig,
            APIConfig,
        ],
        strict=True,
    )
)


def validate_configuration(rule_id, values):
    if rule_id not in CONFIG_TYPES:
        raise ValueError("No implementation registered for this rule ID")
    return CONFIG_TYPES[rule_id].model_validate(values)
