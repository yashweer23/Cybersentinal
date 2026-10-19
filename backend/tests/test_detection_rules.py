"""Behavior fixtures deliberately do not depend on simulation labels."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.detection.configuration import validate_configuration
from app.detection.rules import RULE_TYPES
from app.detection.utils.fingerprints import fingerprint
from app.detection.utils.geo import haversine
from app.detection.utils.time_windows import confidence
from app.models import SecurityEvent
from scripts.seed_detection_rules import DEFAULT_RULES

START = datetime(2026, 9, 26, 5, tzinfo=UTC)


def event(kind="LOGIN_FAILED", seconds=0, **kwargs):
    fields = dict(
        id=uuid4(),
        event_id=f"EVT-{uuid4()}",
        timestamp=START + timedelta(seconds=seconds),
        source_ip="198.51.100.44",
        destination_ip="10.0.0.12",
        username="employee014",
        event_type=kind,
        status="success"
        if kind in {"LOGIN_SUCCESS", "ADMIN_LOGIN", "PRIVILEGE_CHANGE", "SENSITIVE_RECORD_ACCESS"}
        else "failed",
        raw_data={},
        processed=False,
    )
    fields.update(kwargs)
    return SecurityEvent(**fields)


def evaluate(key, events, **overrides):
    seeded = next(row["configuration"] for row in DEFAULT_RULES if row["rule_id"] == key)
    config = validate_configuration(key, {**seeded, **overrides})
    return list(RULE_TYPES[key]().evaluate(events, {e.id for e in events}, config))


@pytest.mark.parametrize(
    "count,spacing,expected", [(4, 10, 0), (5, 10, 1), (5, 40, 0), (5, 30, 1), (5, 30.01, 0)]
)
def test_brute_force_boundaries(count, spacing, expected):
    matches = evaluate("CS-001", [event(seconds=i * spacing) for i in range(count)])
    assert len(matches) == expected
    if matches:
        assert matches[0].evidence["attempt_count"] == 5


def test_brute_force_groups_account_and_source():
    rows = [event(seconds=i, username=f"user{i}") for i in range(10)]
    assert evaluate("CS-001", rows) == []
    rows = [event(seconds=i, source_ip=f"192.0.2.{i + 1}") for i in range(10)]
    assert evaluate("CS-001", rows) == []


def test_rising_edge_suppresses_follow_on_events_and_recovers_after_gap():
    rows = [event(seconds=i) for i in range(30)] + [event(seconds=1000 + i) for i in range(5)]
    assert len(evaluate("CS-001", rows)) == 2


def test_password_spray_is_distinct():
    assert evaluate("CS-002", [event(seconds=i) for i in range(40)]) == []
    matches = evaluate(
        "CS-002",
        [event(seconds=i, username=f"u{i}") for i in range(10)],
        distinct_user_threshold=10,
    )
    assert len(matches) == 1 and matches[0].evidence["qualifying_username_count"] == 10


@pytest.mark.parametrize(
    "geo,expected",
    [
        ({"latitude": 17.4, "longitude": 78.5}, 0),
        ({"latitude": 51.5074, "longitude": -0.1278}, 1),
        ({}, 0),
        ({"latitude": "unknown", "longitude": []}, 0),
    ],
)
def test_impossible_travel(geo, expected):
    rows = [
        event("LOGIN_SUCCESS", raw_data={"geo": {"latitude": 17.385, "longitude": 78.4867}}),
        event("LOGIN_SUCCESS", seconds=3000, raw_data={"geo": geo}),
    ]
    matches = evaluate("CS-003", rows)
    assert len(matches) == expected
    if matches:
        assert matches[0].evidence["required_speed_kmh"] > 900


def test_zero_elapsed_travel_is_finite_and_explicit():
    rows = [
        event("LOGIN_SUCCESS", id=UUID(int=1), raw_data={"geo": {"latitude": 0, "longitude": 0}}),
        event("LOGIN_SUCCESS", id=UUID(int=2), raw_data={"geo": {"latitude": 50, "longitude": 50}}),
    ]
    data = evaluate("CS-003", rows)[0].evidence
    assert data["simultaneous_logins"] and data["required_speed_kmh"] is None


@pytest.mark.parametrize("hour,expected", [(5, 0), (21, 1)])
def test_unusual_login_explicit_india_timezone(hour, expected):
    assert (
        len(evaluate("CS-004", [event("LOGIN_SUCCESS", timestamp=START.replace(hour=hour))]))
        == expected
    )


def test_historical_baseline_excludes_current_day_and_uses_padding():
    rows = [event("LOGIN_SUCCESS", timestamp=START - timedelta(days=day)) for day in range(1, 7)]
    rows += [event("LOGIN_SUCCESS", timestamp=START.replace(hour=12))]
    result = evaluate("CS-004", rows, minimum_baseline_events=5)
    latest = next(m for m in result if m.anchor.id == rows[-1].id)
    assert latest.evidence["baseline_source"] == "historical_central_80_percent"
    assert latest.evidence["baseline_event_count"] == 6


def test_overnight_organization_schedule():
    assert (
        evaluate(
            "CS-004",
            [event("LOGIN_SUCCESS", timestamp=START.replace(hour=21))],
            normal_start_hour=22,
            normal_end_hour=6,
        )
        == []
    )


@pytest.mark.parametrize(
    "before,after,approval,expected",
    [
        ("employee", "analyst", None, 0),
        ("employee", "administrator", None, 1),
        ("analyst", "ADMIN", None, 1),
        ("ADMIN", "administrator", None, 0),
        ("employee", "administrator", "CHG-123", 0),
        (None, "ADMIN", None, 0),
    ],
)
def test_privilege_transitions(before, after, approval, expected):
    rows = [
        event(
            "PRIVILEGE_CHANGE",
            raw_data={
                "previous_role": before,
                "new_role": after,
                "approval_reference": approval,
                "changed_by": "actor",
            },
        )
    ]
    assert len(evaluate("CS-005", rows)) == expected


@pytest.mark.parametrize("count,expected", [(3, 0), (10, 1)])
def test_unique_ports(count, expected):
    rows = [event("PORT_CONNECTION", seconds=i, destination_port=20 + i) for i in range(count)]
    assert len(evaluate("CS-006", rows, distinct_port_threshold=10)) == expected


def test_ports_do_not_mix_destinations_or_count_repeats():
    rows = [event("PORT_CONNECTION", seconds=i, destination_port=443) for i in range(25)]
    assert evaluate("CS-006", rows) == []
    rows = [
        event(
            "PORT_CONNECTION", seconds=i, destination_port=20 + i, destination_ip=f"10.0.0.{i + 1}"
        )
        for i in range(25)
    ]
    assert evaluate("CS-006", rows) == []


@pytest.mark.parametrize("count,expected", [(20, 0), (500, 1)])
def test_sensitive_access_counts_records_not_rows(count, expected):
    result = evaluate(
        "CS-007",
        [
            event(
                "SENSITIVE_RECORD_ACCESS",
                raw_data={"record_count": count, "resource_type": "synthetic_record"},
            )
        ],
    )
    assert len(result) == expected
    if result:
        assert result[0].evidence["access_count"] == 500
        assert len(result[0].events) == 1


def test_sensitive_file_access_and_missing_count_fallback():
    assert (
        evaluate(
            "CS-007",
            [
                event(
                    "FILE_ACCESS",
                    status="success",
                    raw_data={"sensitive": False, "record_count": 9999},
                )
            ],
        )
        == []
    )
    assert (
        len(
            evaluate(
                "CS-007",
                [
                    event(
                        "FILE_ACCESS",
                        status="success",
                        raw_data={"sensitive": True, "record_count": 600},
                    )
                ],
            )
        )
        == 1
    )
    rows = [
        event("SENSITIVE_RECORD_ACCESS", seconds=i, raw_data={"record_count": "bad"})
        for i in range(5)
    ]
    assert len(evaluate("CS-007", rows, record_threshold=5)) == 1


@pytest.mark.parametrize(
    "ip,expected", [("10.0.0.10", 0), ("192.0.2.44", 1), ("198.51.100.73", 1), ("203.0.113.18", 1)]
)
def test_local_reputation_independent_of_labels(ip, expected):
    rows = [event(source_ip=ip, raw_data={"simulation": {"scenario": "normal_activity"}})]
    assert len(evaluate("CS-008", rows)) == expected
    rows[0].source_ip = "10.0.0.10"
    rows[0].raw_data = {
        "simulation": {"scenario": "known_malicious_ip", "simulation_expected_reputation": 100}
    }
    assert evaluate("CS-008", rows) == []


@pytest.mark.parametrize("count,expected", [(4, 0), (5, 1)])
def test_repeated_denials(count, expected):
    rows = [
        event("ACCESS_DENIED", seconds=i, raw_data={"resource": "/protected"}) for i in range(count)
    ]
    assert len(evaluate("CS-009", rows, denied_attempt_threshold=5)) == expected


@pytest.mark.parametrize("count,spacing,expected", [(30, 1, 0), (300, 0.1, 1), (300, 1, 0)])
def test_abnormal_api(count, spacing, expected):
    rows = [
        event(
            "API_REQUEST",
            seconds=i * spacing,
            raw_data={"http_status": 200, "endpoint": "/api/test"},
        )
        for i in range(count)
    ]
    assert len(evaluate("CS-010", rows, request_threshold=300)) == expected


def test_api_account_grouping():
    rows = [event("API_REQUEST", seconds=i, source_ip=f"192.0.2.{i + 1}") for i in range(5)]
    assert evaluate("CS-010", rows, request_threshold=5) == []
    assert len(evaluate("CS-010", rows, request_threshold=5, group_by="username")) == 1


@pytest.mark.parametrize("key", list(RULE_TYPES))
def test_malformed_metadata_never_crashes_rule(key):
    rows = [
        event(
            kind,
            raw_data={
                "geo": [],
                "record_count": True,
                "record_ids": [None],
                "previous_role": {},
                "new_role": [],
                "resource": {},
                "endpoint": [],
                "http_status": {},
            },
        )
        for kind in (
            "LOGIN_SUCCESS",
            "PRIVILEGE_CHANGE",
            "SENSITIVE_RECORD_ACCESS",
            "FILE_ACCESS",
            "API_REQUEST",
            "ACCESS_DENIED",
            "PORT_CONNECTION",
        )
    ]
    evaluate(key, rows)


@pytest.mark.parametrize(
    "key,patch",
    [
        ("CS-001", {"failed_attempt_threshold": 0}),
        ("CS-001", {"window_seconds": True}),
        ("CS-002", {"distinct_user_threshold": "10"}),
        ("CS-004", {"timezone": "invalid/location"}),
        ("CS-004", {"normal_start_hour": 8, "normal_end_hour": 8}),
        ("CS-006", {"passive_only": False}),
        ("CS-010", {"group_by": "raw_sql"}),
        ("CS-007", {"unknown": 1}),
    ],
)
def test_invalid_rule_settings_rejected(key, patch):
    with pytest.raises(ValidationError):
        validate_configuration(key, patch)


def test_fingerprint_and_confidence_are_explainable():
    assert fingerprint("CS-001", ("ip", "user"), "evt") == fingerprint(
        "CS-001", ("ip", "user"), "evt"
    )
    assert fingerprint("CS-001", ("ip", "user"), "evt") != fingerprint(
        "CS-002", ("ip", "user"), "evt"
    )
    assert confidence(5, 5) == 75 and confidence(40, 5) == 95
    assert haversine({"latitude": 0, "longitude": 0}, {"latitude": 0, "longitude": 0}) == 0


def test_detector_code_never_imports_generator_or_evaluation_labels():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "app" / "detection"
    for path in root.rglob("*.py"):
        code = path.read_text()
        assert "app.simulation" not in code
        assert "evaluate_detections" not in code
        assert '["simulation"]' not in code and '.get("simulation"' not in code


@pytest.mark.parametrize("module", ["scripts/run_detection.py", "scripts/evaluate_detections.py"])
def test_detection_cli_help(module):
    import subprocess
    import sys
    from pathlib import Path

    backend = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, module, "--help"], cwd=backend, capture_output=True, text=True
    )
    assert result.returncode == 0 and "usage:" in result.stdout


def test_local_reputation_expiry_is_checked():
    from app.detection.reputation import Reputation
    from app.detection.rules.malicious_ip import SuspiciousIP

    class Provider:
        def lookup_ip(self, value):
            return Reputation(92, "fixture", True, expires_at=START)

    detector = SuspiciousIP(Provider(), now=START + timedelta(seconds=1))
    row = event()
    assert list(detector.evaluate([row], {row.id}, validate_configuration("CS-008", {}))) == []


def test_access_daily_baseline_increases_threshold_only_with_enough_history():
    rows = [
        event(
            "SENSITIVE_RECORD_ACCESS",
            timestamp=START - timedelta(days=day),
            raw_data={"record_count": 150},
        )
        for day in (1, 2)
    ]
    rows += [event("SENSITIVE_RECORD_ACCESS", raw_data={"record_count": 120})]
    matches = evaluate(
        "CS-007", rows, record_threshold=100, minimum_baseline_days=2, baseline_multiplier=2
    )
    assert not any(m.anchor.id == rows[-1].id for m in matches)
    fallback = evaluate("CS-007", rows, record_threshold=100, baseline_enabled=False)
    assert any(m.anchor.id == rows[-1].id for m in fallback)


def test_api_baseline_uses_completed_days_and_explains_adjusted_threshold():
    rows = [
        event("API_REQUEST", timestamp=START - timedelta(days=day) + timedelta(seconds=i))
        for day in (1, 2)
        for i in range(10)
    ]
    rows += [event("API_REQUEST", seconds=i) for i in range(25)]
    matches = evaluate(
        "CS-010", rows, request_threshold=5, minimum_baseline_days=2, baseline_multiplier=2
    )
    latest = next(m for m in matches if m.anchor.timestamp >= START)
    assert latest.evidence["threshold"] == 20
    assert latest.evidence["baseline_active_days"] == 2
    assert latest.evidence["baseline_value"] == 10
    assert latest.evidence["request_count"] == 20
