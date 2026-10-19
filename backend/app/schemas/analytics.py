"""Read-only advanced analytics contracts. All periods use [start,end) UTC."""

from typing import Literal

from pydantic import Field

from app.schemas.common import Schema
from app.schemas.dashboard import DashboardScope, TimelinePoint, TimeRangeQuery, UTCTime


class AnalyticsQuery(TimeRangeQuery):
    range: Literal["24h", "7d", "30d", "90d"] | None = None


class EventTrendQuery(AnalyticsQuery):
    event_type: str | None = Field(default=None, max_length=100)
    service: str | None = Field(default=None, max_length=100)
    status: str | None = Field(default=None, max_length=100)
    source_ip: str | None = Field(default=None, max_length=45)
    username: str | None = Field(default=None, max_length=255)


class EntityQuery(AnalyticsQuery):
    kind: Literal["username", "source_ip", "service", "device"] = "username"
    limit: int = Field(default=20, ge=1, le=100)
    recurring_only: bool = False
    mode: Literal["mock", "live"] | None = None


class RiskQuery(AnalyticsQuery):
    population: Literal["incidents", "findings"] = "incidents"


class Response(Schema):
    scope: DashboardScope
    definition: str


class Overview(Response):
    total_events: int
    detection_findings: int
    incidents_created: int
    critical_incidents: int
    resolved_incidents: int
    false_positives: int
    average_risk_score: float | None
    median_risk_score: float | None
    unique_suspicious_ips: int
    unique_targeted_users: int
    acknowledged_incidents: int
    measured_resolutions: int
    mean_time_to_acknowledge_seconds: float | None
    mean_time_to_resolve_seconds: float | None
    p90_resolution_seconds: float | None
    resolution_rate: float | None
    false_positive_rate: float | None


class EventPoint(TimelinePoint):
    sensitive_access: int = 0
    privilege_changes: int = 0


class EventTrend(Response):
    interval: str
    bucket_seconds: int
    total: int
    data: list[EventPoint]


class IncidentPoint(Schema):
    timestamp: UTCTime
    created: int = 0
    critical: int = 0
    resolved: int = 0
    false_positive: int = 0
    reopened: int = 0


class IncidentTrend(Response):
    interval: str
    bucket_seconds: int
    data: list[IncidentPoint]


class RuleRow(Schema):
    rule_id: str
    name: str
    enabled: bool
    findings: int
    incidents: int
    average_risk: float | None
    critical_incidents: int
    false_positives: int
    closed_incidents: int
    false_positive_rate: float | None
    latest_detection: UTCTime | None


class RulePerformance(Response):
    items: list[RuleRow]


class RiskPoint(Schema):
    timestamp: UTCTime
    count: int = 0
    average_risk: float | None = None
    median_risk: float | None = None
    maximum_risk: int | None = None
    critical_count: int = 0


class RiskTrend(Response):
    population: str
    score_version: str
    interval: str
    bucket_seconds: int
    data: list[RiskPoint]


class Bucket(Schema):
    label: str
    count: int


class Histogram(Response):
    population: str
    total: int
    data: list[Bucket]


class EntityRow(Schema):
    entity: str
    event_count: int
    suspicious_event_count: int
    failed_logins: int
    access_denials: int
    incident_count: int
    finding_count: int
    average_risk: float | None
    highest_risk: int | None
    critical_incidents: int
    first_seen: UTCTime | None
    latest_activity: UTCTime | None
    detection_rules: list[str]
    reputation: str | None = None
    intelligence_mode: str | None = None


class EntityAnalytics(Response):
    kind: str
    items: list[EntityRow]
    limit: int
    has_more: bool


class OldestIncident(Schema):
    incident_id: str
    created_at: UTCTime
    age_seconds: float


class Backlog(Response):
    open_count: int
    investigating_count: int
    critical_unresolved: int
    average_age_seconds: float | None
    oldest: OldestIncident | None
    age_distribution: list[Bucket]


class WorkloadRow(Schema):
    analyst_id: str
    username: str
    assigned: int
    open: int
    investigating: int
    resolved: int
    average_resolution_seconds: float | None


class ActivityPoint(Schema):
    timestamp: UTCTime
    assignments: int = 0
    comments: int = 0
    status_transitions: int = 0
    resolutions: int = 0


class Workload(Response):
    limit: int = 100
    offset: int = 0
    has_more: bool = False
    items: list[WorkloadRow]
    unassigned: int
    assigned_to_ineligible: int
    activity: list[ActivityPoint]


class CategoryRow(Schema):
    category: str
    findings: int
    incidents: int


class Categories(Response):
    items: list[CategoryRow]


class GeographyRow(Schema):
    country: str
    finding_count: int
    incident_count: int


class Geography(Response):
    items: list[GeographyRow]
    limit: int = 30
    has_more: bool


class ProviderUsage(Schema):
    provider: str
    lookup_status: str
    bundles: int


class IntelligenceMode(Schema):
    mode: Literal["mock", "live"]
    simulation: bool
    indicators_checked: int
    malicious: int
    suspicious: int
    unknown: int
    no_adverse_signals: int
    expired: int
    cache_hits: int
    lookups: int
    provider_failures: int
    provider_usage: list[ProviderUsage]


class IntelligenceAnalytics(Response):
    modes: list[IntelligenceMode]


class AIUsage(Response):
    analyses_generated: int
    fallback_analyses: int
    provider_analyses: int
    analysis_failures: int
    cache_hits: int
    average_response_ms: float | None
    stale_analyses: int | None = None
    stale_measurement: str = (
        "Not materialized; exact freshness is computed by each incident analysis read."
    )


class SyntheticEvaluation(Response):
    label: Literal["Synthetic Evaluation Only"] = "Synthetic Evaluation Only"
    expected_scenarios: int
    detected_scenarios: int
    missed_scenarios: int
    unexpected_findings: int
    findings_evaluated: int
    scenario_recall: float | None
    finding_label_agreement: float | None
    precision: float | None = None
    precision_note: str = (
        "Label agreement is not precision: overlapping behavior and retained "
        "evidence cannot establish false positives."
    )


class WorkloadQuery(AnalyticsQuery):
    limit: int = Field(default=100, ge=1, le=5000)
    offset: int = Field(default=0, ge=0, le=1000000)


class StatusPoint(Schema):
    timestamp: UTCTime
    open: int = 0
    investigating: int = 0
    resolved: int = 0
    false_positive: int = 0
    unresolved: int = 0


class StatusHistory(Response):
    tracked_cases: int
    excluded_cases: int
    interval: str
    bucket_seconds: int
    data: list[StatusPoint]
