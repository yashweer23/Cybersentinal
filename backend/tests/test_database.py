from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import DataError, IntegrityError, StatementError

from alembic import command
from app.core.enums import IncidentStatus, SeverityLevel, UserRole
from app.models import (
    AuditLog,
    DetectionRule,
    Incident,
    IncidentComment,
    IncidentEvidence,
    SecurityEvent,
    SystemMetric,
    User,
)
from app.schemas.system_metric import SystemMetricResponse
from tests.database_fixtures import isolated_schema, migration_config


@pytest.fixture
def event_row(db):
    row = SecurityEvent(
        event_id=f"evt-{uuid4()}",
        timestamp=datetime.now(UTC),
        source_ip="192.0.2.10",
        destination_ip="10.0.0.12",
        username="employee01",
        event_type="LOGIN_FAILED",
        source_port=54321,
        destination_port=443,
        status="failed",
        raw_data={"fixture": True, "nested": {"count": 5}},
    )
    db.add(row)
    db.flush()
    return row


@pytest.fixture
def rule_row(db):
    row = DetectionRule(
        rule_id="CS-999",
        name="Fixture rule",
        description="Database fixture only",
        severity=SeverityLevel.HIGH,
        configuration={"threshold": 5},
    )
    db.add(row)
    db.flush()
    return row


@pytest.fixture
def incident_row(db, rule_row):
    row = Incident(
        incident_id=f"CS-{uuid4()}",
        title="Fixture incident",
        description="Supplied evidence",
        detection_rule_id=rule_row.id,
        source_ip="192.0.2.10",
        risk_score=63,
        severity=SeverityLevel.HIGH,
        confidence=Decimal("88.25"),
        detected_at=datetime.now(UTC),
    )
    db.add(row)
    db.flush()
    return row


def test_database_connection_and_migrated_tables(db):
    assert db.scalar(text("SELECT 1")) == 1
    assert db.scalar(text("SELECT version()")).startswith("PostgreSQL")
    assert set(inspect(db.connection()).get_table_names()) == {
        "alembic_version",
        "users",
        "security_events",
        "detection_rules",
        "detection_findings",
        "risk_assessments",
        "incidents",
        "incident_findings",
        "incident_processing",
        "threat_intelligence_results",
        "threat_provider_state",
        "incident_evidence",
        "threat_intelligence",
        "incident_comments",
        "audit_logs",
        "auth_sessions",
        "system_metrics",
        "ai_analyses",
    }


def test_security_event_roundtrip(db, event_row):
    original_timestamp = event_row.timestamp
    db.expire_all()
    row = db.get(SecurityEvent, event_row.id)
    assert str(row.source_ip) == "192.0.2.10"
    assert row.raw_data["nested"]["count"] == 5
    assert row.processed is False
    assert row.timestamp == original_timestamp
    assert row.created_at.tzinfo is not None


def test_detection_rule_and_incident_relationship(db, rule_row, incident_row):
    db.expire_all()
    assert incident_row.detection_rule.id == rule_row.id
    assert rule_row.incidents[0].id == incident_row.id
    assert incident_row.status is IncidentStatus.OPEN
    assert incident_row.confidence == Decimal("88.25")


def test_evidence_survives_as_event_when_incident_deleted(db, event_row, incident_row):
    evidence = IncidentEvidence(
        incident=incident_row,
        security_event=event_row,
        evidence_type="AUTH_FAILURE",
        description="Observed failed login",
        evidence_data={"attempts": 5},
    )
    comment = IncidentComment(incident=incident_row, comment="Needs investigation")
    db.add_all([evidence, comment])
    db.flush()
    evidence_id, comment_id, event_id = evidence.id, comment.id, event_row.id
    assert incident_row.evidence[0].security_event.id == event_id
    with pytest.raises(IntegrityError), db.begin_nested():
        db.delete(event_row)
        db.flush()
    db.delete(incident_row)
    db.flush()
    db.expire_all()
    assert db.get(SecurityEvent, event_id) is not None
    assert db.get(IncidentEvidence, evidence_id) is None
    assert db.get(IncidentComment, comment_id) is None


def test_rule_in_use_cannot_be_deleted(db, rule_row, incident_row):
    with pytest.raises(IntegrityError), db.begin_nested():
        db.delete(rule_row)
        db.flush()


def test_user_deletion_preserves_comments_audits_and_incidents(db, incident_row):
    user = User(
        username="fixture",
        email="fixture@example.test",
        role=UserRole.ANALYST,
        hashed_password="a-database-test-placeholder-hash",
    )
    db.add(user)
    db.flush()
    incident_row.assigned_analyst = user
    note = IncidentComment(incident=incident_row, user=user, comment="Investigating")
    audit = AuditLog(
        user=user,
        action="ASSIGN",
        entity_type="incident",
        entity_id=str(incident_row.id),
        new_value={"status": "OPEN"},
    )
    db.add_all([note, audit])
    db.flush()
    note_id, audit_id = note.id, audit.id
    db.delete(user)
    db.flush()
    db.expire_all()
    assert incident_row.assigned_analyst_id is None
    assert db.get(IncidentComment, note_id).user_id is None
    assert db.get(AuditLog, audit_id).user_id is None
    db.delete(incident_row)
    db.flush()
    assert db.get(AuditLog, audit_id).new_value == {"status": "OPEN"}


@pytest.mark.parametrize(
    "field,value",
    [
        ("risk_score", -1),
        ("risk_score", 101),
        ("confidence", -0.01),
        ("confidence", 100.01),
    ],
)
def test_incident_score_constraints(db, incident_row, field, value):
    with pytest.raises(IntegrityError), db.begin_nested():
        setattr(incident_row, field, value)
        db.flush()


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_port", -1),
        ("destination_port", 65536),
        ("raw_data", ["not an object"]),
    ],
)
def test_event_constraints(db, event_row, field, value):
    with pytest.raises(IntegrityError), db.begin_nested():
        setattr(event_row, field, value)
        db.flush()


def test_native_enum_rejects_unknown_value_even_with_direct_sql(db, incident_row):
    with pytest.raises(DataError), db.begin_nested():
        db.execute(
            text("UPDATE incidents SET status = 'UNKNOWN' WHERE id = :id"), {"id": incident_row.id}
        )
    with pytest.raises(StatementError), db.begin_nested():
        incident_row.severity = "EMERGENCY"
        db.flush()


@pytest.mark.parametrize("kind", ["event", "rule", "incident", "username", "email"])
def test_business_identifiers_are_unique(db, event_row, rule_row, incident_row, kind):
    if kind == "event":
        duplicate = SecurityEvent(
            event_id=event_row.event_id,
            timestamp=datetime.now(UTC),
            source_ip="192.0.2.11",
            event_type="API_REQUEST",
            status="ok",
        )
    elif kind == "rule":
        duplicate = DetectionRule(
            rule_id=rule_row.rule_id,
            name="Duplicate",
            description="Fixture",
            severity=SeverityLevel.LOW,
        )
    elif kind == "incident":
        duplicate = Incident(
            incident_id=incident_row.incident_id,
            title="Duplicate",
            description="Fixture",
            detection_rule_id=rule_row.id,
            risk_score=5,
            confidence=25,
            severity=SeverityLevel.LOW,
            detected_at=datetime.now(UTC),
        )
    else:
        user = User(
            username="existing",
            email="existing@example.test",
            hashed_password="a-database-test-placeholder-hash",
        )
        db.add(user)
        db.flush()
        duplicate = User(
            username="EXISTING" if kind == "username" else "different",
            email="EXISTING@example.test" if kind == "email" else "other@example.test",
            hashed_password="a-database-test-placeholder-hash",
        )
    with pytest.raises(IntegrityError), db.begin_nested():
        db.add(duplicate)
        db.flush()


def test_foreign_key_rejects_missing_rule(db):
    with pytest.raises(IntegrityError), db.begin_nested():
        db.add(
            Incident(
                incident_id="missing-rule",
                title="Fixture",
                description="Fixture",
                detection_rule_id=uuid4(),
                risk_score=10,
                confidence=30,
                severity=SeverityLevel.LOW,
                detected_at=datetime.now(UTC),
            )
        )
        db.flush()


def test_metric_metadata_alias_roundtrip(db):
    metric = SystemMetric(
        metric_name="events_processed",
        metric_value=12,
        unit="events",
        metric_metadata={"worker": "fixture"},
    )
    db.add(metric)
    db.flush()
    result = SystemMetricResponse.model_validate(metric).model_dump(mode="json")
    assert result["metadata"] == {"worker": "fixture"}
    assert "metric_metadata" not in result


def test_updated_at_trigger_works_for_direct_sql(db, rule_row):
    before = rule_row.updated_at
    db.execute(
        text("UPDATE detection_rules SET enabled = false WHERE id = :id"), {"id": rule_row.id}
    )
    db.refresh(rule_row)
    assert rule_row.updated_at >= before
    triggers = db.scalar(
        text("""
        SELECT count(*) FROM pg_trigger t JOIN pg_class c ON t.tgrelid = c.oid
        JOIN pg_namespace n ON c.relnamespace = n.oid
        JOIN pg_proc p ON t.tgfoid = p.oid
        WHERE n.nspname = current_schema() AND NOT t.tgisinternal
          AND p.proname = 'touch_updated_at'
    """)
    )
    assert triggers == 4


def test_required_query_indexes(db):
    inspector = inspect(db.connection())
    expected = {
        "security_events": {"timestamp", "source_ip", "username", "event_type", "processed"},
        "incidents": {"detected_at", "severity", "status", "source_ip", "risk_score"},
        "threat_intelligence": {"indicator"},
        "audit_logs": {"timestamp"},
    }
    for table, columns in expected.items():
        indexed = {col for index in inspector.get_indexes(table) for col in index["column_names"]}
        assert columns <= indexed


def test_migration_roundtrip_and_no_model_drift(database_url):
    with isolated_schema(database_url) as engine, engine.begin() as connection:
        config = migration_config(connection)
        command.upgrade(config, "head")
        command.upgrade(config, "head")
        command.check(config)
        assert (
            len(
                inspect(connection).get_enums(
                    schema=connection.scalar(text("SELECT current_schema()"))
                )
            )
            == 4
        )
        command.downgrade(config, "base")
        assert inspect(connection).get_table_names() == ["alembic_version"]
        assert (
            inspect(connection).get_enums(schema=connection.scalar(text("SELECT current_schema()")))
            == []
        )
        command.upgrade(config, "head")
        assert (
            connection.scalar(text("SELECT version_num FROM alembic_version")) == "0008_ai_analyses"
        )
