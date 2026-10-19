"""Threshold and timezone contracts, independent of simulation labels."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.detection.configuration import ReputationConfig
from app.detection.reputation import Reputation
from app.detection.rules.malicious_ip import SuspiciousIP
from app.detection.utils.geo import haversine
from tests.test_detection_rules import evaluate, event


@pytest.mark.parametrize("offset", [-1, 0, 1])
@pytest.mark.parametrize(
    "rule,kind,threshold,field,metric",
    [
        ("CS-001", "LOGIN_FAILED", 5, "failed_attempt_threshold", "attempt_count"),
        ("CS-002", "LOGIN_FAILED", 10, "distinct_user_threshold", "unique_username_count"),
        ("CS-006", "PORT_CONNECTION", 10, "distinct_port_threshold", "unique_port_count"),
        ("CS-007", "SENSITIVE_RECORD_ACCESS", 100, "record_threshold", "access_count"),
        ("CS-009", "ACCESS_DENIED", 5, "denied_attempt_threshold", "denial_count"),
        ("CS-010", "API_REQUEST", 300, "request_threshold", "request_count"),
    ],
)
def test_volume_threshold_below_equal_above(rule, kind, threshold, field, metric, offset):
    rows = []
    for index in range(threshold + offset):
        values = {}
        if rule == "CS-002":
            values["username"] = f"employee{index}"
        if rule == "CS-006":
            values["destination_port"] = 1000 + index
        rows.append(event(kind, seconds=index / 10, **values))
    matches = evaluate(rule, rows, **{field: threshold})
    assert len(matches) == (0 if offset < 0 else 1)
    if matches:
        match = matches[0]
        assert match.evidence[metric] >= threshold
        assert {row.id for row in match.events} <= {row.id for row in rows}
        assert match.anchor.id in {row.id for row in match.events}
        assert 0 <= match.confidence <= 100


@pytest.mark.parametrize("hours,expected", [(0.999, 1), (1, 0), (1.001, 0)])
def test_travel_speed_strictly_exceeds_threshold(hours, expected):
    a, b = {"latitude": 0, "longitude": 0}, {"latitude": 0, "longitude": 10}
    rows = [
        event("LOGIN_SUCCESS", raw_data={"geo": a}),
        event("LOGIN_SUCCESS", seconds=3600 * hours, raw_data={"geo": b}),
    ]
    assert len(evaluate("CS-003", rows, max_speed_kmh=haversine(a, b))) == expected


@pytest.mark.parametrize("hour,minute,expected", [(7, 59, 1), (8, 0, 0), (19, 59, 0), (20, 0, 1)])
def test_working_hours_start_inclusive_end_exclusive(hour, minute, expected):
    row = event("LOGIN_SUCCESS")
    row.timestamp = datetime(2026, 10, 16, hour, minute, tzinfo=UTC)
    assert len(evaluate("CS-004", [row], timezone="UTC")) == expected


@pytest.mark.parametrize("utc_hour", [5, 6])
def test_fall_back_ambiguous_hour_preserves_utc_instant(utc_hour):
    row = event("LOGIN_SUCCESS")
    row.timestamp = datetime(2026, 11, 1, utc_hour, 30, tzinfo=UTC)
    match = evaluate("CS-004", [row], timezone="America/New_York")[0]
    local = datetime.fromisoformat(match.evidence["local_login_time"])
    assert local.hour == 1 and local.astimezone(UTC) == row.timestamp
    assert local.utcoffset() == timedelta(hours=-4 if utc_hour == 5 else -5)


@pytest.mark.parametrize("score,expected", [(74, 0), (75, 1), (76, 1)])
def test_reputation_threshold_boundary(score, expected):
    provider = SimpleNamespace(lookup_ip=lambda _: Reputation(score, "Test fixture", True))
    row = event()
    matches = list(SuspiciousIP(provider).evaluate([row], {row.id}, ReputationConfig()))
    assert len(matches) == expected
    if matches:
        assert matches[0].evidence["reputation_score"] == score
