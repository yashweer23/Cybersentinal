from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.enums import SeverityLevel
from app.risk import components
from app.risk.calculator import InvalidEvidence, calculate
from app.risk.config import CAPS, RiskScoringConfig
from tests.test_detection_rules import event


def example(rule="CS-001", **overrides):
    evidence = {
        "CS-001": {"attempt_count": 5, "threshold": 5},
        "CS-002": {"qualifying_username_count": 8, "threshold": 8, "usernames": ["employee014"]},
        "CS-003": {
            "distance_km": 1000,
            "elapsed_hours": 0.5,
            "required_speed_kmh": 2000,
            "speed_threshold_kmh": 900,
            "simultaneous_logins": False,
        },
        "CS-004": {
            "local_login_time": "2026-09-26T02:00:00+05:30",
            "normal_start_hour": 8,
            "normal_end_hour": 20,
        },
        "CS-005": {"previous_role": "EMPLOYEE", "new_role": "ADMIN", "approval_reference": None},
        "CS-006": {"unique_port_count": 20, "threshold": 20},
        "CS-007": {"access_count": 500, "threshold": 500, "baseline_value": 20},
        "CS-008": {"reputation_score": 92},
        "CS-009": {"denial_count": 10, "threshold": 10, "resource_paths": ["/private"]},
        "CS-010": {
            "request_count": 200,
            "threshold": 200,
            "endpoints": ["/health"],
            "response_status_distribution": {"200": 200},
        },
    }[rule]
    evidence.update(configuration={"window_seconds": 120}, **overrides)
    kinds = {
        "CS-003": "LOGIN_SUCCESS",
        "CS-004": "LOGIN_SUCCESS",
        "CS-005": "PRIVILEGE_CHANGE",
        "CS-006": "PORT_CONNECTION",
        "CS-007": "SENSITIVE_RECORD_ACCESS",
        "CS-008": "LOGIN_FAILED",
        "CS-009": "ACCESS_DENIED",
        "CS-010": "API_REQUEST",
    }
    events = [event(kinds.get(rule, "LOGIN_FAILED"), seconds=i * 10) for i in range(5)]
    finding = SimpleNamespace(
        id=uuid4(),
        finding_id=f"FIND-{uuid4().hex}",
        rule=SimpleNamespace(rule_id=rule),
        evidence_data=evidence,
        evidence_event_ids=[row.event_id for row in events],
        primary_event_id=events[-1].id,
        event_count=len(events),
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        severity=SeverityLevel.HIGH,
        confidence=80,
        source_ip=events[0].source_ip,
        username=events[0].username,
    )
    return finding, events


def score(finding, events, successes=None, reputations=None, config=None):
    return calculate(
        finding, events, successes or [], reputations or {}, config or RiskScoringConfig()
    )


@pytest.mark.parametrize(
    "value,level",
    [
        (0, "LOW"),
        (24, "LOW"),
        (25, "MEDIUM"),
        (49, "MEDIUM"),
        (50, "HIGH"),
        (74, "HIGH"),
        (75, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_category_boundaries(value, level):
    assert components.risk_level(value).value == level


@pytest.mark.parametrize("value", [-1, 101, float("nan"), 1.1, True])
def test_category_rejects_invalid_totals(value):
    with pytest.raises(ValueError):
        components.risk_level(value)


@pytest.mark.parametrize(
    "level,points", [("LOW", 5), ("MEDIUM", 12), ("HIGH", 20), ("CRITICAL", 25)]
)
def test_severity(level, points):
    assert components.severity(level)["points"] == points


@pytest.mark.parametrize("confidence,points", [(0, 0), (50, 8), (93, 14), (100, 15)])
def test_confidence_transparent_half_up_rounding(confidence, points):
    assert components.confidence(confidence)["points"] == points


@pytest.mark.parametrize("rule", [f"CS-{index:03}" for index in range(1, 11)])
def test_every_rule_is_deterministic_explained_and_bounded(rule):
    finding, events = example(rule)
    first, second = score(finding, events), score(finding, list(reversed(events)))
    assert first == second
    assert first["risk_score"] == sum(first["breakdown"][key]["points"] for key in CAPS)
    for key, maximum in CAPS.items():
        item = first["breakdown"][key]
        assert 0 <= item["points"] <= maximum and item["max"] == maximum and item["reason"]
    assert components.risk_level(first["risk_score"]) == first["risk_level"]


@pytest.mark.parametrize(
    "rule,key,low,high",
    [
        ("CS-001", "attempt_count", 5, 50),
        ("CS-002", "qualifying_username_count", 10, 70),
        ("CS-003", "required_speed_kmh", 950, 4500),
        ("CS-006", "unique_port_count", 20, 100),
        ("CS-007", "access_count", 510, 5000),
        ("CS-009", "denial_count", 10, 100),
        ("CS-010", "request_count", 200, 2000),
    ],
)
def test_rule_specific_intensity_increases_without_recounting_volume(rule, key, low, high):
    finding, events = example(rule, **{key: low})
    before = score(finding, events)
    finding.evidence_data[key] = high
    after = score(finding, events)
    assert after["behavioural_score"] > before["behavioural_score"]
    assert after["frequency_score"] == before["frequency_score"]
    assert after["risk_score"] > before["risk_score"]


def test_strong_brute_force_success_and_local_reputation():
    finding, events = example()
    before = score(finding, events)
    finding.evidence_data["attempt_count"] = 50
    success = event("LOGIN_SUCCESS", seconds=50)
    reputation = {
        str(finding.source_ip): {
            "ip": str(finding.source_ip),
            "score": 92,
            "source": "Local fixture",
            "synthetic": True,
        }
    }
    after = score(finding, events, [success], reputation)
    assert after["risk_score"] >= before["risk_score"] + 20
    assert "does not prove compromise" in after["breakdown"]["behavioural_intensity"]["reason"]
    assert after["breakdown"]["context"]["successful_authentication_count"] == 1


def test_success_requires_matching_source_user_and_short_followup_window():
    finding, events = example()
    invalid = [
        event("LOGIN_SUCCESS", seconds=50, username="unrelated"),
        event("LOGIN_SUCCESS", seconds=50, source_ip="192.0.2.1"),
        event("LOGIN_SUCCESS", seconds=39),
        event("LOGIN_SUCCESS", seconds=341),
        event("LOGIN_SUCCESS", seconds=50, status="failed"),
    ]
    assert score(finding, events, invalid)["behavioural_score"] == 0
    success = event("LOGIN_SUCCESS", seconds=340)
    assert score(finding, events, [success])["behavioural_score"] == 4


def test_spray_success_for_another_target_and_configured_account_sensitivity():
    finding, events = example("CS-002", usernames=["target"])
    success = event("LOGIN_SUCCESS", seconds=50, username="target")
    assert score(finding, events, [success])["behavioural_score"] == 4
    events[0].username = "sensitive-account"
    config = RiskScoringConfig(account_points={"sensitive-account": 15})
    assert score(finding, events, config=config)["asset_sensitivity_score"] == 15


def test_simultaneous_travel_uses_finite_full_intensity():
    finding, events = example(
        "CS-003", required_speed_kmh=None, elapsed_hours=0, simultaneous_logins=True
    )
    assert score(finding, events)["behavioural_score"] == 20


def test_unusual_hour_distance_and_overnight_schedule():
    finding, events = example("CS-004", local_login_time="2026-09-26T07:50:00+05:30")
    marginal = score(finding, events)
    finding.evidence_data["local_login_time"] = "2026-09-26T02:00:00+05:30"
    assert score(finding, events)["behavioural_score"] > marginal["behavioural_score"]
    finding.evidence_data.update(normal_start_hour=20, normal_end_hour=8)
    assert score(finding, events)["behavioural_score"] == 0


def test_administrator_gain_exceeds_manager_and_approval_context():
    finding, events = example("CS-005", new_role="MANAGER")
    manager = score(finding, events)
    finding.evidence_data["new_role"] = "ADMIN"
    admin = score(finding, events)
    assert admin["asset_sensitivity_score"] > manager["asset_sensitivity_score"]
    assert admin["behavioural_score"] > manager["behavioural_score"]
    finding.evidence_data["approval_reference"] = "APPROVED-FIXTURE"
    assert score(finding, events)["behavioural_score"] < admin["behavioural_score"]


def test_ports_resource_breadth_and_admin_endpoints():
    finding, events = example("CS-006")
    ordinary = score(finding, events)
    events[-1].destination_port = 3389
    assert score(finding, events)["asset_sensitivity_score"] > ordinary["asset_sensitivity_score"]
    finding, events = example("CS-009")
    one = score(finding, events)
    finding.evidence_data["resource_paths"] = [f"/admin/{i}" for i in range(10)]
    many = score(finding, events)
    assert (
        many["frequency_score"] > one["frequency_score"] and many["asset_sensitivity_score"] == 15
    )


def test_api_sensitivity_and_response_composition():
    finding, events = example("CS-010")
    low = score(finding, events)
    finding.evidence_data["endpoints"] = ["/api/admin/users"]
    finding.evidence_data["response_status_distribution"] = {"403": 200}
    high = score(finding, events)
    assert high["asset_sensitivity_score"] > low["asset_sensitivity_score"]
    assert high["frequency_score"] > low["frequency_score"]
    assert high["behavioural_score"] == low["behavioural_score"]
    finding.evidence_data["endpoints"] = ["/administrator"]
    assert score(finding, events)["asset_sensitivity_score"] < 15


@pytest.mark.parametrize(
    "value,points", [(0, 0), (24, 0), (25, 4), (74, 4), (75, 7), (89, 7), (90, 10), (100, 10)]
)
def test_reputation_bands_without_double_counting_indicator(value, points):
    result = components.reputation({"reputation_context": [{"score": value}]})
    assert result["points"] == points
    finding, events = example("CS-008")
    assert score(finding, events)["behavioural_score"] == 0


def test_total_reaches_cap_and_bad_component_is_not_silently_clamped():
    finding, events = example("CS-001", attempt_count=5000)
    finding.severity, finding.confidence = SeverityLevel.CRITICAL, 100
    finding.last_seen = finding.first_seen + timedelta(seconds=0.1)
    events[0].service = "admin-console"
    reputation = {str(finding.source_ip): {"score": 100, "synthetic": True}}
    result = score(finding, events, reputations=reputation)
    assert result["risk_score"] == 100
    for invalid in [-1, 26, float("nan"), float("inf")]:
        with pytest.raises(ValueError):
            components.component("severity", invalid, "invalid")


def test_missing_events_malformed_metrics_and_unknown_rules_are_skippable():
    finding, events = example()
    with pytest.raises(InvalidEvidence, match="missing"):
        score(finding, events[:-1])
    for value in [None, "five", True, -1, float("inf")]:
        finding.evidence_data["attempt_count"] = value
        with pytest.raises(InvalidEvidence):
            score(finding, events)
    finding.rule.rule_id = "CS-999"
    with pytest.raises(InvalidEvidence, match="No scoring policy"):
        score(finding, events)


def test_no_modification_or_simulation_label_dependency():
    finding, events = example()
    original = deepcopy(finding.evidence_data)
    first = score(finding, events)
    for row in events:
        row.raw_data = {"simulation": {"scenario": "normal_activity", "risk_score": 100}}
    assert score(finding, events) == first and finding.evidence_data == original


def test_policy_validation_and_identity():
    for settings in [
        {"severity_max": 26},
        {"service_points": {"bad": 16}},
        {"intensity_full_ratio": 1},
        {"unrecognized": True},
    ]:
        with pytest.raises(ValidationError):
            RiskScoringConfig(**settings)
    config = RiskScoringConfig()
    assert len(config.fingerprint) == 64
    assert config.fingerprint == RiskScoringConfig().fingerprint
    assert config.fingerprint != RiskScoringConfig(service_points={"test": 1}).fingerprint


def test_settings_accept_json_policy_without_changing_recipe_caps(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("RISK_SCORING", '{"service_points":{"internal-api":12}}')
    settings = Settings(_env_file=None)
    assert settings.risk_scoring.service_points == {"internal-api": 12}
    assert settings.risk_scoring.confidence_max == 15


def test_detection_severity_snapshot_not_current_rule_definition():
    finding, events = example()
    expected = score(finding, events)
    finding.rule.severity = SeverityLevel.CRITICAL
    finding.rule.configuration = {"threshold": 999}
    assert score(finding, events) == expected


@pytest.mark.parametrize("data", [{"unexpected": 1}, {"600": 1}, {"200": 201}, {"200": True}])
def test_malformed_api_status_context_is_skipped(data):
    finding, events = example("CS-010", response_status_distribution=data)
    with pytest.raises(InvalidEvidence):
        score(finding, events)
