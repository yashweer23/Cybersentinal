from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.incident import IncidentCreate
from app.schemas.security_event import SecurityEventCreate
from app.schemas.system_metric import SystemMetricCreate
from app.schemas.threat_intelligence import ThreatIntelligenceCreate
from app.schemas.user import UserCreate


@pytest.mark.parametrize(
    "override",
    [
        {"source_port": -1},
        {"destination_port": 65536},
        {"source_ip": "not-an-ip"},
        {"timestamp": "2026-09-25T12:00:00"},
        {"raw_data": ["not-an-object"]},
    ],
)
def test_event_schema_rejects_invalid_input(override):
    values = {
        "event_id": "evt-fixture",
        "timestamp": datetime.now(UTC),
        "source_ip": "192.0.2.1",
        "event_type": "LOGIN_FAILED",
        "status": "failed",
    }
    with pytest.raises(ValidationError):
        SecurityEventCreate(**(values | override))


@pytest.mark.parametrize(
    "override",
    [
        {"severity": "URGENT"},
        {"status": "CLOSED"},
        {"risk_score": 101},
        {"confidence": -1},
        {"confidence": float("nan")},
        {"resolved_at": "2000-01-01T00:00:00Z"},
    ],
)
def test_incident_schema_rejects_invalid_input(override):
    values = {
        "incident_id": "CS-fixture",
        "title": "Fixture",
        "description": "Fixture",
        "detection_rule_id": uuid4(),
        "risk_score": 65,
        "severity": "HIGH",
        "confidence": 80,
        "detected_at": datetime.now(UTC),
    }
    with pytest.raises(ValidationError):
        IncidentCreate(**(values | override))


def test_user_input_cannot_assign_a_role_and_password_is_redacted():
    values = {
        "username": "Admin",
        "email": "ADMIN@cybersentinel.local",
        "password": "not-a-real-secret-password",
    }
    user = UserCreate(**values)
    assert user.email == "admin@cybersentinel.local" and user.username == "admin"
    assert values["password"] not in repr(user)
    assert "password" not in user.model_dump()
    with pytest.raises(ValidationError):
        UserCreate(**values, role="ADMIN")


@pytest.mark.parametrize("password", ["short", "x" * 73, "€" * 25])
def test_bcrypt_password_limits_are_validated(password):
    with pytest.raises(ValidationError):
        UserCreate(username="viewer", email="viewer@example.test", password=password)


@pytest.mark.parametrize("indicator,kind", [("bad-ip", "IP"), ("https://example.test", "DOMAIN")])
def test_indicator_validation(indicator, kind):
    with pytest.raises(ValidationError):
        ThreatIntelligenceCreate(
            indicator=indicator,
            indicator_type=kind,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )


def test_expiry_and_metric_metadata_mapping():
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        ThreatIntelligenceCreate(
            indicator="192.0.2.1",
            indicator_type="IP",
            first_seen=now,
            last_checked=now,
            expires_at=now,
        )
    metric = SystemMetricCreate(
        metric_name="events", metric_value=5, unit="count", metadata={"source": "fixture"}
    )
    assert metric.to_model_values()["metric_metadata"] == {"source": "fixture"}
