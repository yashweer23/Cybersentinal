"""Offline generation parameters; intentionally independent of server secrets/.env."""

from datetime import UTC, date, datetime, time, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.simulation.constants import PRESETS, Scenario


class SimulationConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    count: int | None = Field(default=None, ge=1, le=1_000_000)
    preset: Literal["small", "medium", "large"] | None = None
    seed: int = Field(default=42, ge=0, le=2**63 - 1)
    # A fixed default makes --seed reproducible even on different calendar days.
    start_date: date = date(2026, 9, 26)
    days: int = Field(default=7, ge=1, le=365)
    scenario: Scenario = Scenario.MIXED
    normal_ratio: float = Field(default=0.95, ge=0, le=1, allow_inf_nan=False)
    run_id: str = Field(default="demo", min_length=1, max_length=80, pattern=r"^[\w.-]+$")
    ground_truth: bool = True
    employee_count: int = Field(default=100, ge=50, le=150)
    manager_count: int = Field(default=8, ge=5, le=10)
    analyst_count: int = Field(default=4, ge=3, le=5)
    administrator_count: int = Field(default=3, ge=2, le=4)
    working_start_hour: int = Field(default=8, ge=6, le=10)
    working_end_hour: int = Field(default=20, ge=18, le=22)
    normal_records_min: int = Field(default=5, ge=5, le=30)
    normal_records_max: int = Field(default=30, ge=5, le=30)
    brute_force_min_failures: int = Field(default=10, ge=10, le=30)
    brute_force_max_failures: int = Field(default=30, ge=10, le=30)
    brute_force_window_seconds: int = Field(default=60, ge=30, le=120)
    spray_min_users: int = Field(default=15, ge=15, le=40)
    spray_max_users: int = Field(default=40, ge=15, le=40)
    spray_max_attempts: int = Field(default=3, ge=1, le=3)
    spray_window_seconds: int = Field(default=120, ge=30, le=300)
    excessive_records: int = Field(default=500, ge=300, le=700)
    records_per_event: int = Field(default=25, ge=1, le=100)
    excessive_window_seconds: int = Field(default=1200, ge=600, le=1800)
    api_burst_min: int = Field(default=500, ge=500, le=3000)
    api_burst_max: int = Field(default=3000, ge=500, le=3000)
    api_burst_window_seconds: int = Field(default=45, ge=10, le=60)

    @model_validator(mode="after")
    def coherent_settings(self):
        if self.count is not None and self.preset is not None:
            raise ValueError("Choose --count or --preset, not both")
        for low, high in (
            (self.normal_records_min, self.normal_records_max),
            (self.brute_force_min_failures, self.brute_force_max_failures),
            (self.spray_min_users, self.spray_max_users),
            (self.api_burst_min, self.api_burst_max),
        ):
            if low > high:
                raise ValueError("Minimum generation limits must not exceed maximum limits")
        if not date(2000, 1, 1) <= self.start_date <= date(2099, 1, 1):
            raise ValueError("Use a start date from 2000-01-01 through 2099-01-01")
        return self

    @property
    def requested_count(self) -> int | None:
        if self.count is not None:
            return self.count
        if self.preset:
            return PRESETS[self.preset]
        return PRESETS["small"] if self.scenario in {Scenario.MIXED, Scenario.NORMAL} else None

    @property
    def start(self) -> datetime:
        return datetime.combine(self.start_date, time(), tzinfo=UTC)

    @property
    def end(self) -> datetime:
        return self.start + timedelta(days=self.days)
