import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event as sa_event
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from app.config import Settings
from app.core.enums import UserRole
from app.database import get_db
from app.main import create_app
from app.models import AuditLog, AuthSession, Incident, SecurityEvent, User
from app.repositories import security_event_repository as repository
from app.security.jwt import create_access_token
from app.services.event_files import ingest_file
from app.services.event_ingestion import EventIngestionService
from app.simulation.config import SimulationConfig
from app.simulation.exporter import export_events
from app.simulation.generator import SecurityEventGenerator
from tests.test_event_ingestion_unit import event_payload


@pytest.fixture
def settings():
    return Settings(_env_file=None, app_env="test", auth_rate_limit_enabled=False)


@pytest.fixture
def service(db, settings):
    return EventIngestionService(db, settings)


@pytest.fixture
def http(db, settings, monkeypatch):
    monkeypatch.setattr("app.main.build_engine", lambda cfg: MagicMock())
    app = create_app(settings)
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as client:
        yield client


@pytest.fixture
def tokens(db, settings):
    result = {}
    for role in UserRole:
        user = User(
            username=role.value.lower(),
            email=f"{role.value.lower()}@cybersentinel.local",
            hashed_password="fixture-not-used-for-login" * 2,
            role=role,
        )
        db.add(user)
        db.flush()
        login = AuthSession(
            user_id=user.id,
            refresh_token_hash="0" * 64,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        db.add(login)
        db.flush()
        token = create_access_token(user.id, login.id, role, settings)
        result[role.value] = {"Authorization": "Bearer " + token}
    db.commit()
    return result


def count(db):
    return db.scalar(select(func.count()).select_from(SecurityEvent))


def test_single_insert_duplicate_preserves_raw_and_processed(service, db):
    payload = event_payload()
    first = service.ingest_batch([payload]).summary
    assert (first.received, first.inserted, first.invalid, first.duplicates) == (1, 1, 0, 0)
    stored = repository.get_event(db, payload["event_id"])
    assert stored.processed is False and stored.raw_data == payload["raw_data"]
    stored.processed = True
    db.commit()
    second = service.ingest_batch(
        [dict(payload, status="success", raw_data={"replace": True})]
    ).summary
    assert second.inserted == 0 and second.duplicates == 1 and count(db) == 1
    db.refresh(stored)
    assert (
        stored.processed is True
        and stored.status == "failed"
        and stored.raw_data == payload["raw_data"]
    )
    assert db.scalar(select(func.count()).select_from(Incident)) == 0


def test_batch_existing_intrabatch_duplicates_and_invalid_neighbors(service, db):
    existing, new, invalid = event_payload(), event_payload(), event_payload(source_ip="bad")
    service.ingest_batch([existing])
    result = service.ingest_batch([existing, new, new, invalid, None]).summary
    assert (result.received, result.inserted, result.duplicates, result.invalid, result.failed) == (
        5,
        1,
        2,
        2,
        0,
    )
    assert count(db) == 2 and result.valid == 3
    assert [e.index for e in result.errors] == [4, 5]


def test_normalization_and_ipv6_persist(service, db):
    payload = event_payload(
        event_type=" login_failed ",
        status=" FAILED ",
        username=" EmployeeCASE ",
        timestamp="2026-09-26T15:30:00+05:30",
        source_ip="2001:0db8::1",
    )
    assert service.ingest_batch([payload]).summary.inserted == 1
    row = repository.get_event(db, payload["event_id"])
    assert str(row.source_ip) == "2001:db8::1" and row.username == "EmployeeCASE"
    assert row.timestamp == datetime(2026, 9, 26, 10, tzinfo=UTC)


@pytest.mark.parametrize("kind", ["jsonl", "json"])
def test_phase4_thousand_event_file_and_repeat(tmp_path, service, db, kind):
    target = tmp_path / f"demo.{kind}"
    generator = SecurityEventGenerator(SimulationConfig(count=1000, seed=42))
    export_events(generator, target, kind)
    first = ingest_file(service, target, batch_size=200)
    second = ingest_file(service, target, batch_size=500)
    assert (first.received, first.inserted, first.duplicates, first.invalid, first.failed) == (
        1000,
        1000,
        0,
        0,
        0,
    )
    assert (second.received, second.inserted, second.duplicates, second.invalid, second.failed) == (
        1000,
        0,
        1000,
        0,
        0,
    )
    assert count(db) == 1000
    assert (
        db.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.processed.is_(False))
        )
        == 1000
    )
    expected = next(generator.iter_events())
    assert repository.get_event(db, expected.event_id).raw_data == expected.raw_data


def test_bad_jsonl_neighbors_and_bounded_diagnostics(tmp_path, service, db):
    target = tmp_path / "mixed.jsonl"
    target.write_text(
        json.dumps(event_payload())
        + "\n"
        + "{invalid secret-token}\n" * 25
        + json.dumps(event_payload())
        + "\n"
    )
    errors = []
    result = ingest_file(service, target, batch_size=10, error_sink=errors.append)
    assert result.inserted == 2 and result.invalid == 25 and count(db) == 2
    assert result.received == 27 and result.errors_omitted == 5 and len(result.errors) == 20
    assert len(errors) == 25 and errors[0].line == 2 and errors[-1].line == 26
    assert "secret-token" not in result.model_dump_json()


def test_bulk_write_uses_one_insert_no_per_event_select(service, db):
    statements = []
    connection = db.connection()

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.upper())

    sa_event.listen(connection, "before_cursor_execute", capture)
    try:
        result = service.ingest_batch([event_payload() for _ in range(500)]).summary
    finally:
        sa_event.remove(connection, "before_cursor_execute", capture)
    assert result.inserted == 500
    assert sum(sql.startswith("INSERT INTO SECURITY_EVENTS") for sql in statements) == 1
    assert not any(sql.startswith("SELECT") and "SECURITY_EVENTS" in sql for sql in statements)


def test_database_failure_rollback_and_session_recovery(service, db, monkeypatch, caplog):
    original = repository.insert_batch

    def fail_after_insert(session, events):
        original(session, events)
        raise OperationalError("sql-with-secret", {}, Exception("password=SECRET"))

    monkeypatch.setattr(repository, "insert_batch", fail_after_insert)
    result = service.ingest_batch([event_payload(), event_payload()]).summary
    assert result.failed == 2 and result.inserted == 0 and not result.complete and count(db) == 0
    assert "SECRET" not in caplog.text and "sql-with-secret" not in caplog.text
    assert "SECRET" not in result.model_dump_json()
    monkeypatch.setattr(repository, "insert_batch", original)
    assert service.ingest_batch([event_payload()]).summary.inserted == 1


def test_file_stops_on_database_failure_and_retry_recovers(tmp_path, service, db, monkeypatch):
    target = tmp_path / "file.jsonl"
    target.write_text("\n".join(json.dumps(event_payload()) for _ in range(6)))
    original, calls = repository.insert_batch, 0

    def fail_second(session, events):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OperationalError("", {}, Exception("fixture"))
        return original(session, events)

    monkeypatch.setattr(repository, "insert_batch", fail_second)
    result = ingest_file(service, target, batch_size=2)
    assert not result.complete and result.received == 4 and result.failed == 2 and count(db) == 2
    monkeypatch.setattr(repository, "insert_batch", original)
    repeated = ingest_file(service, target, batch_size=2)
    assert repeated.duplicates == 2 and repeated.inserted == 4 and count(db) == 6


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST"])
def test_writers_ingest_and_audit_once_per_request(http, tokens, db, role):
    payload = event_payload()
    response = http.post("/api/events/ingest", json=payload, headers=tokens[role])
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "accepted" and response.json()["duplicate"] is False
    duplicate = http.post("/api/events/ingest", json=payload, headers=tokens[role])
    assert duplicate.status_code == 200 and duplicate.json()["duplicate"] is True
    assert duplicate.json()["database_id"] == response.json()["database_id"]
    batch = http.post(
        "/api/events/ingest/batch",
        json={"events": [payload, event_payload(), {"password": "HIDDEN"}]},
        headers=tokens[role],
    )
    assert batch.status_code == 200 and batch.json()["inserted"] == 1
    assert batch.json()["duplicates"] == batch.json()["invalid"] == 1
    audits = db.scalars(select(AuditLog).where(AuditLog.action == "EVENT_BATCH_INGESTED")).all()
    assert len(audits) == 3 and all(a.user_id is not None for a in audits)
    assert "HIDDEN" not in batch.text and count(db) == 2


@pytest.mark.parametrize("route", ["/api/events/ingest", "/api/events/ingest/batch"])
def test_viewer_and_anonymous_cannot_ingest(http, tokens, db, route):
    body = event_payload() if route.endswith("/ingest") else {"events": [event_payload()]}
    assert http.post(route, json=body, headers=tokens["VIEWER"]).status_code == 403
    assert http.post(route, json=body).status_code == 401
    assert count(db) == 0


def test_invalid_single_and_batch_caps(http, tokens, settings, db):
    response = http.post(
        "/api/events/ingest", json=event_payload(source_ip="not-an-ip"), headers=tokens["ADMIN"]
    )
    assert response.status_code == 422 and "not-an-ip" not in response.text
    settings.ingestion_max_batch_size = 2
    response = http.post(
        "/api/events/ingest/batch", json={"events": [event_payload()] * 3}, headers=tokens["ADMIN"]
    )
    assert response.status_code == 413 and count(db) == 0
    assert (
        http.post(
            "/api/events/ingest/batch", json={"events": []}, headers=tokens["ADMIN"]
        ).status_code
        == 422
    )


def test_listing_lookup_stats_filters_and_roles(http, tokens, service, db):
    data = [
        event_payload(
            timestamp=f"2026-09-26T10:00:0{i}Z",
            username=f"user{i}",
            source_ip=f"192.0.2.{i + 1}",
            event_type="LOGIN_FAILED" if i < 3 else "API_REQUEST",
        )
        for i in range(5)
    ]
    service.ingest_batch(data)
    row = repository.get_event(db, data[0]["event_id"])
    row.processed = True
    db.commit()
    for role in tokens:
        response = http.get("/api/events?limit=2&offset=1", headers=tokens[role])
        assert response.status_code == 200 and response.json()["total"] == 5
        assert [e["username"] for e in response.json()["items"]] == ["user3", "user2"]
        assert response.headers["cache-control"] == "no-store"
        assert (
            http.get(f"/api/events/{data[0]['event_id']}", headers=tokens[role]).json()["processed"]
            is True
        )
        stats = http.get("/api/events/stats", headers=tokens[role]).json()
        assert (stats["total_events"], stats["processed_events"], stats["unprocessed_events"]) == (
            5,
            1,
            4,
        )
        assert stats["event_types"] == {"API_REQUEST": 2, "LOGIN_FAILED": 3}
        assert stats["latest_event_timestamp"] == "2026-09-26T10:00:04Z"
    cases = [
        ({"event_type": " login_failed "}, 3),
        ({"username": "user2"}, 1),
        ({"source_ip": "192.0.2.1"}, 1),
        ({"destination_ip": "10.0.10.15"}, 5),
        ({"service": "authentication"}, 5),
        ({"status": " FAILED "}, 5),
        ({"processed": "false"}, 4),
        ({"start_time": "2026-09-26T15:30:02+05:30"}, 3),
        ({"end_time": "2026-09-26T10:00:01Z"}, 2),
        ({"username": "' OR 1=1 --"}, 0),
        ({"event_type": "LOGIN_FAILED", "processed": "false"}, 2),
    ]
    for params, expected in cases:
        result = http.get("/api/events", params=params, headers=tokens["VIEWER"])
        assert result.status_code == 200, result.text
        assert result.json()["total"] == expected
    oldest = http.get("/api/events?sort_order=asc&limit=1", headers=tokens["VIEWER"])
    assert oldest.json()["items"][0]["username"] == "user0"
    assert http.get("/api/events/EVT-missing", headers=tokens["VIEWER"]).status_code == 404
    assert http.get("/api/events").status_code == 401
    assert http.get("/api/events/stats").status_code == 401


@pytest.mark.parametrize(
    "query",
    [
        "limit=501",
        "offset=-1",
        "sort_by=timestamp;DROP TABLE users",
        "source_ip=bad",
        "source_ip=fe80::1%25eth0",
        "start_time=2026-09-26T10:00:00",
        "start_time=2026-09-27T10:00:00Z&end_time=2026-09-26T10:00:00Z",
    ],
)
def test_invalid_queries_return_422(http, tokens, query):
    assert http.get("/api/events?" + query, headers=tokens["VIEWER"]).status_code == 422


def test_api_database_failure_is_503_without_secrets(http, tokens, monkeypatch):
    def fail(*args, **kwargs):
        raise OperationalError("secret-url", {}, Exception("secret-password"))

    monkeypatch.setattr(repository, "insert_batch", fail)
    response = http.post(
        "/api/events/ingest/batch", json={"events": [event_payload()]}, headers=tokens["ADMIN"]
    )
    assert response.status_code == 503 and response.json()["failed"] == 1
    assert "secret" not in response.text


def test_openapi_documents_contract_and_auth(http):
    assert http.get("/docs").status_code == 200
    schema = http.get("/openapi.json").json()
    paths = schema["paths"]
    for path in ("/api/events", "/api/events/stats", "/api/events/{event_id}"):
        assert paths[path]["get"]["security"] == [{"BearerAuth": []}]
    for path in ("/api/events/ingest", "/api/events/ingest/batch"):
        assert paths[path]["post"]["security"] == [{"BearerAuth": []}]
    assert "SecurityEventCreate" in schema["components"]["schemas"]
    assert "limit" in {p["name"] for p in paths["/api/events"]["get"]["parameters"]}


def test_cli_summary_exit_codes_repeat_and_safe_reject_file(
    tmp_path, db, settings, monkeypatch, capsys
):
    from contextlib import nullcontext

    from scripts import ingest_events

    engine = MagicMock()
    monkeypatch.setattr(ingest_events, "get_settings", lambda: settings)
    monkeypatch.setattr(ingest_events, "build_engine", lambda _: engine)
    monkeypatch.setattr(ingest_events, "Session", lambda _: nullcontext(db))
    path = tmp_path / "cli.jsonl"
    path.write_text(json.dumps(event_payload()) + "\n")
    assert ingest_events.main(["--file", str(path)]) == 0
    assert "Inserted: 1" in capsys.readouterr().out
    assert ingest_events.main(["--file", str(path)]) == 0
    output = capsys.readouterr().out
    assert "Inserted: 0" in output and "Duplicates: 1" in output
    with path.open("a") as handle:
        handle.write('{"event_id":"EVT-bad","password":"secret-never-report"}\n')
    report = tmp_path / "rejected.jsonl"
    assert ingest_events.main(["--file", str(path), "--rejected-output", str(report)]) == 2
    output = capsys.readouterr().out
    assert "Invalid: 1" in output and "Line 2:" in output
    assert "secret-never-report" not in output + report.read_text()
    assert "event" not in json.loads(report.read_text())
    assert count(db) == 1 and engine.dispose.call_count == 3


def test_cli_production_guard_does_not_open_database(tmp_path, settings, monkeypatch):
    from scripts import ingest_events

    settings.app_env = "production"
    monkeypatch.setattr(ingest_events, "get_settings", lambda: settings)
    engine = MagicMock()
    monkeypatch.setattr(ingest_events, "build_engine", engine)
    assert ingest_events.main(["--file", str(tmp_path / "unused.jsonl")]) == 1
    engine.assert_not_called()


def test_audit_failure_rolls_back_api_events(http, tokens, db, monkeypatch):
    def fail(*args, **kwargs):
        raise OperationalError("", {}, Exception("audit unavailable"))

    monkeypatch.setattr("app.services.event_ingestion.record_audit", fail)
    result = http.post("/api/events/ingest", json=event_payload(), headers=tokens["ADMIN"])
    assert result.status_code == 503 and count(db) == 0


def test_empty_stats_and_limits_do_not_require_event_rows(http, tokens):
    response = http.get("/api/events/stats", headers=tokens["VIEWER"])
    assert response.json() == {
        "total_events": 0,
        "processed_events": 0,
        "unprocessed_events": 0,
        "latest_event_timestamp": None,
        "event_types": {},
    }
    response = http.post(
        "/api/events/ingest/batch",
        json={"events": [event_payload()] * 1001},
        headers=tokens["ADMIN"],
    )
    assert response.status_code == 422
