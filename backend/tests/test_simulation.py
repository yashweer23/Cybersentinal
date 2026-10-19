"""Offline behavioral fixtures for future detection tests; no database is needed."""

from collections import Counter, defaultdict
from datetime import timedelta
from ipaddress import ip_address, ip_network
from math import asin, cos, radians, sin, sqrt

import pytest
from pydantic import ValidationError

from app.schemas.security_event import SecurityEventCreate
from app.simulation.config import SimulationConfig
from app.simulation.constants import INDIA_TIME, SYNTHETIC_THREAT_IPS, EventType, Scenario
from app.simulation.generator import SecurityEventGenerator


def events_for(scenario, **kwargs):
    return list(SecurityEventGenerator(SimulationConfig(scenario=scenario, **kwargs)).iter_events())


@pytest.fixture(scope="module")
def small():
    return list(SecurityEventGenerator(SimulationConfig(count=1000, seed=42)).iter_events())


def test_required_small_dataset(small):
    scenarios = Counter(e.raw_data["simulation"]["scenario"] for e in small)
    assert len(small) == 1000
    assert scenarios["normal_activity"] == 950
    assert scenarios["brute_force"] >= 10
    assert scenarios["password_spray"] >= 15
    assert scenarios["impossible_travel"] >= 2
    assert scenarios["unusual_login"] >= 1
    assert scenarios["excessive_access"] >= 1


def test_schema_ips_ports_timestamps_and_ids(small):
    allowed = [
        ip_network(n)
        for n in (
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "192.0.2.0/24",
            "198.51.100.0/24",
            "203.0.113.0/24",
        )
    ]
    cfg = SimulationConfig()
    assert len({e.event_id for e in small}) == 1000
    assert [e.timestamp for e in small] == sorted(e.timestamp for e in small)
    for event in small:
        data = event.model_dump(mode="json")
        assert SecurityEventCreate.model_validate(data) == event
        assert not {"id", "created_at", "processed", "risk_score", "malicious"} & data.keys()
        assert cfg.start <= event.timestamp < cfg.end
        assert event.timestamp.utcoffset() == timedelta(0)
        assert data["timestamp"].endswith("Z")
        assert event.event_id.startswith("EVT-")
        assert event.event_type in EventType
        for address in (event.source_ip, event.destination_ip):
            assert any(ip_address(address) in network for network in allowed)
        assert 0 <= event.source_port <= 65535
        assert 0 <= event.destination_port <= 65535


def test_normal_sessions_profiles_and_sensitive_daily_limits():
    generator = SecurityEventGenerator(SimulationConfig(scenario="normal", count=10000))
    events = list(generator.iter_events())
    profiles = {p.username: p for p in generator.profiles}
    roles = Counter(p.role for p in profiles.values())
    assert roles == {"employee": 100, "manager": 8, "analyst": 4, "administrator": 3}
    sessions = defaultdict(list)
    record_counts = Counter()
    login_minutes = set()
    for event in events:
        profile = profiles[event.username]
        local = event.timestamp.astimezone(INDIA_TIME)
        assert profile.normal_start_minute <= local.hour * 60 + local.minute
        assert local.hour * 60 + local.minute <= profile.normal_end_minute
        assert event.device in profile.typical_devices
        assert str(event.source_ip) == profile.internal_ip
        assert event.raw_data["geo"]["city"] == profile.location.city
        sessions[(event.username, local.date())].append(event)
        if event.event_type == "SENSITIVE_RECORD_ACCESS":
            count = event.raw_data["record_count"]
            assert count == len(set(event.raw_data["record_ids"]))
            record_counts[(event.username, local.date())] += count
        if event.event_type in {"LOGIN_SUCCESS", "ADMIN_LOGIN"}:
            login_minutes.add((local.hour, local.minute))
    assert len(login_minutes) > 30
    assert record_counts and all(5 <= count <= 30 for count in record_counts.values())
    for session in sessions.values():
        kinds = [e.event_type for e in session]
        assert kinds[-1] == "LOGOUT"
        assert "MFA_SUCCESS" in kinds and "FILE_ACCESS" in kinds and "API_REQUEST" in kinds
        assert kinds.count("PASSWORD_CHANGE") <= 1
        assert kinds.count("ACCESS_DENIED") <= 1
        assert kinds.count("LOGIN_FAILED") <= 1


def test_seed_reproducibility_and_independent_namespaces(small):
    assert small == list(
        SecurityEventGenerator(SimulationConfig(count=1000, seed=42)).iter_events()
    )
    assert small == list(SecurityEventGenerator(SimulationConfig(preset="small")).iter_events())
    original_ids = {e.event_id for e in small}
    for overrides in ({"seed": 43}, {"run_id": "batch-two"}, {"count": 1001}):
        other = list(SecurityEventGenerator(SimulationConfig(**overrides)).iter_events())
        assert not original_ids.intersection(e.event_id for e in other)


def test_brute_force_one_user_and_intended_window():
    events = events_for("brute_force")
    failures = [e for e in events if e.event_type == "LOGIN_FAILED"]
    assert 10 <= len(failures) <= 30
    assert 30 <= (failures[-1].timestamp - failures[0].timestamp).total_seconds() <= 120
    assert len({e.source_ip for e in events}) == len({e.username for e in events}) == 1
    assert len({e.raw_data["simulation"]["scenario_id"] for e in events}) == 1
    assert events[-1].event_type in {"ACCOUNT_LOCKED", "LOGIN_SUCCESS"}
    assert events[-1].timestamp > failures[-1].timestamp


def test_password_spray_many_users_few_attempts():
    events = events_for("password_spray")
    targets = Counter(e.username for e in events)
    assert 15 <= len(targets) <= 40
    assert all(1 <= n <= 3 for n in targets.values())
    assert len({e.source_ip for e in events}) == 1
    assert all(e.event_type == "LOGIN_FAILED" for e in events)
    assert (events[-1].timestamp - events[0].timestamp).total_seconds() <= 300


def test_impossible_travel_is_physically_unrealistic():
    first, second = events_for("impossible_travel")
    assert first.username == second.username
    assert first.event_type == second.event_type == "LOGIN_SUCCESS"
    assert first.country != second.country
    a, b = first.raw_data["geo"], second.raw_data["geo"]
    lat1, lat2 = radians(a["latitude"]), radians(b["latitude"])
    dl = radians(b["longitude"] - a["longitude"])
    distance = (
        6371
        * 2
        * asin(sqrt(sin((lat2 - lat1) / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dl / 2) ** 2))
    )
    hours = (second.timestamp - first.timestamp).total_seconds() / 3600
    assert 0 < hours < 1 and distance > 5000 and distance / hours > 1000


def test_unusual_login_uses_profile_local_time():
    generator = SecurityEventGenerator(SimulationConfig(scenario="unusual_login", days=1))
    (event,) = generator.iter_events()
    profile = next(p for p in generator.profiles if p.username == event.username)
    local = event.timestamp.astimezone(INDIA_TIME)
    assert 2 <= local.hour <= 4
    assert local.hour < profile.normal_start_hour
    assert generator.config.start <= event.timestamp < generator.config.end


def test_privilege_escalation_sequence_and_roles():
    events = events_for("privilege_escalation")
    assert [e.event_type for e in events] == [
        "LOGIN_SUCCESS",
        "ACCESS_DENIED",
        "PRIVILEGE_CHANGE",
        "ADMIN_LOGIN",
    ]
    assert len({e.username for e in events}) == 1
    assert events[2].raw_data["previous_role"] == "employee"
    assert events[2].raw_data["new_role"] == "administrator"
    assert events[2].raw_data["changed_by"] == events[2].username


def test_port_activity_uses_many_ports_one_destination():
    events = events_for("port_activity")
    assert len({e.destination_port for e in events}) >= 20
    assert len({e.source_ip for e in events}) == 1
    assert len({e.destination_ip for e in events}) == 1
    assert all(e.event_type == "PORT_CONNECTION" for e in events)
    assert (events[-1].timestamp - events[0].timestamp).total_seconds() <= 60


@pytest.mark.parametrize("batch_size", [1, 25, 37, 100])
def test_excessive_access_record_volume_and_time(batch_size):
    events = events_for("excessive_access", records_per_event=batch_size, excessive_records=503)
    assert len({e.username for e in events}) == 1
    assert all(e.event_type == "SENSITIVE_RECORD_ACCESS" for e in events)
    ids = [rid for e in events for rid in e.raw_data["record_ids"]]
    assert len(ids) == len(set(ids)) == 503
    assert sum(e.raw_data["record_count"] for e in events) == 503
    assert all(e.raw_data["resource_type"] == "patient_record" for e in events)
    assert 600 <= (events[-1].timestamp - events[0].timestamp).total_seconds() <= 1800


def test_abnormal_api_burst_is_actual_events_with_http_metadata():
    events = events_for("abnormal_api")
    assert 500 <= len(events) <= 3000
    assert len({e.source_ip for e in events}) == len({e.username for e in events}) == 1
    assert (events[-1].timestamp - events[0].timestamp).total_seconds() <= 60
    for event in events:
        assert event.event_type == "API_REQUEST"
        assert event.raw_data["endpoint"] == "/api/records"
        assert event.raw_data["method"] == "GET"
        assert event.raw_data["response_time_ms"] > 0
        assert event.status == (
            "rate_limited" if event.raw_data["http_status"] == 429 else "success"
        )


def test_access_denied_repeats_protected_resources():
    events = events_for("access_denied")
    assert len(events) >= 8
    assert len({e.username for e in events}) == 1
    assert {e.raw_data["resource"] for e in events} == {
        "/admin/users",
        "/admin/audit",
        "/internal/config",
    }
    assert all(e.status == "denied" and e.event_type == "ACCESS_DENIED" for e in events)


def test_synthetic_reputation_is_ground_truth_only():
    (event,) = events_for("malicious_ip")
    assert str(event.source_ip) in SYNTHETIC_THREAT_IPS
    assert event.raw_data["simulation"]["simulation_expected_reputation"] == 92
    assert "malicious" not in event.model_dump()
    (unlabeled,) = events_for("malicious_ip", ground_truth=False)
    assert "simulation" not in unlabeled.raw_data
    assert "simulation_expected_reputation" not in unlabeled.model_dump_json()
    assert event.event_id == unlabeled.event_id


def test_simulated_endpoint_alert():
    (event,) = events_for("malware_alert")
    assert event.event_type == "MALWARE_ALERT" and event.status == "quarantined"
    assert event.raw_data["signature"] == "SIM-DEMO-001"
    assert event.raw_data["detection_source"] == "simulated_endpoint_security"


def test_labels_can_be_removed_without_altering_behavior(small):
    unlabeled = list(SecurityEventGenerator(SimulationConfig(ground_truth=False)).iter_events())
    for a, b in zip(small, unlabeled, strict=True):
        expected = a.model_dump(mode="json")
        expected["raw_data"].pop("simulation")
        assert expected == b.model_dump(mode="json")


@pytest.mark.parametrize("scenario", [s for s in Scenario if s != Scenario.MIXED])
def test_every_scenario_valid_in_single_day(scenario):
    cfg = SimulationConfig(scenario=scenario, days=1)
    events = list(SecurityEventGenerator(cfg).iter_events())
    assert events
    assert all(cfg.start <= e.timestamp < cfg.end for e in events)
    assert len({e.event_id for e in events}) == len(events)
    assert [e.timestamp for e in events] == sorted(e.timestamp for e in events)


@pytest.mark.parametrize(
    "scenario,count",
    [
        ("brute_force", 60),
        ("password_spray", 118),
        ("impossible_travel", 8),
        ("privilege_escalation", 12),
        ("excessive_access", 60),
        ("abnormal_api", 3001),
    ],
)
def test_explicit_counts_are_partitioned_into_whole_episodes(scenario, count):
    assert len(events_for(scenario, count=count)) == count


@pytest.mark.parametrize(
    "scenario,count",
    [
        ("brute_force", 5),
        ("password_spray", 2),
        ("impossible_travel", 3),
        ("privilege_escalation", 5),
        ("excessive_access", 21),
        ("abnormal_api", 100),
    ],
)
def test_impossible_counts_rejected_without_truncated_sequences(scenario, count):
    with pytest.raises(ValueError, match="complete episodes"):
        SecurityEventGenerator(SimulationConfig(scenario=scenario, count=count))


@pytest.mark.parametrize(
    "overrides",
    [
        {"count": 0},
        {"count": 1000001},
        {"days": 0},
        {"normal_ratio": 1.1},
        {"normal_ratio": float("nan")},
        {"seed": -1},
        {"start_date": "invalid"},
        {"scenario": "unknown"},
        {"count": 100, "preset": "small"},
        {"normal_records_min": 30, "normal_records_max": 5},
        {"records_per_event": 0},
    ],
)
def test_invalid_generator_configuration(overrides):
    with pytest.raises(ValidationError):
        SimulationConfig(**overrides)


@pytest.mark.parametrize("count,ratio", [(1, 0.95), (47, 0), (300, 1), (1000, 0.97)])
def test_mixed_budget_boundaries_are_exact_and_omissions_visible(count, ratio):
    generator = SecurityEventGenerator(SimulationConfig(count=count, normal_ratio=ratio))
    records = list(generator.iter_records())
    assert len(records) == count
    assert sum(r.scenario == Scenario.NORMAL for r in records) == int(count * ratio + 0.5)
    assert generator.omitted_scenarios


def test_all_event_types_and_scenarios_appear_in_larger_demo():
    generator = SecurityEventGenerator(SimulationConfig(count=10000, normal_ratio=0.92))
    events = list(generator.iter_events())
    assert not generator.omitted_scenarios
    assert {e.event_type for e in events} == {t.value for t in EventType}
    assert len({e.event_id for e in events}) == 10000
