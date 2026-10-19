"""Phase 15 operational smoke checks; the broader verification matrix is Phase 16."""

import json
import logging
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from alembic import command
from app.config import Settings
from app.database import build_engine, get_engine
from app.main import create_app
from app.operations.http import correlation_id
from app.operations.logging import SafeJsonFormatter, request_id
from app.routes.system import migration_heads
from tests.database_fixtures import isolated_schema, migration_config


@pytest.mark.parametrize(
    "values",
    [
        {"allowed_hosts": ["*"]},
        {"allowed_hosts": ["https://example.com"]},
        {"forwarded_allow_ips": ["*"]},
        {"forwarded_allow_ips": ["0.0.0.0/0"]},
        {"forwarded_allow_ips": ["::/0"]},
        {"server_workers": 2},
        {"db_pool_size": 0},
        {"app_env": "production", "log_level": "DEBUG"},
        {"app_env": "production", "jwt_secret_key": "development-secret-" * 3},
    ],
)
def test_rejects_unsafe_operational_configuration(values):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)


def test_pool_and_proxy_defaults():
    settings = Settings(_env_file=None, db_pool_size=3, db_max_overflow=2)
    engine = build_engine(settings)
    try:
        assert engine.pool.size() == 3
        assert engine.pool._max_overflow == 2
        assert engine.pool._pre_ping is True
        assert engine.pool._recycle == 1800
        assert settings.proxy_headers_enabled is False
        assert settings.server_workers == 1
    finally:
        engine.dispose()


def test_json_logs_redact_secrets_and_drop_request_payloads():
    record = logging.LogRecord(
        "operations",
        logging.ERROR,
        "",
        0,
        "password=private Bearer some.token fixture-secret",
        (),
        None,
    )
    record.body = {"password": "never-log-body"}
    record.query = "sensitive-query"
    record.route = "/api/incidents/{incident_id}"
    token = request_id.set("correlated")
    try:
        encoded = SafeJsonFormatter(["fixture-secret"]).format(record)
    finally:
        request_id.reset(token)
    assert all(
        value not in encoded
        for value in (
            "private",
            "some.token",
            "fixture-secret",
            "never-log-body",
            "sensitive-query",
        )
    )
    parsed = json.loads(encoded)
    assert parsed["request_id"] == "correlated"
    assert parsed["route"] == "/api/incidents/{incident_id}"
    assert parsed["level"] == "ERROR"


def test_exception_message_is_not_logged():
    try:
        raise RuntimeError("SQL password and raw event contents")
    except RuntimeError:
        import sys

        record = logging.LogRecord("operations", 40, "", 0, "Failure", (), sys.exc_info())
    encoded = SafeJsonFormatter().format(record)
    assert "SQL password" not in encoded
    assert json.loads(encoded)["error_type"] == "RuntimeError"


def test_request_ids_hosts_errors_and_cors(caplog):
    app = create_app(Settings(_env_file=None))

    @app.get("/operational-test/{item}")
    def failure(item: str):
        raise RuntimeError("private SQL and password")

    with TestClient(app) as client:
        identifier = uuid4()
        result = client.get(
            "/api/system/live",
            headers={"X-Request-ID": str(identifier), "Origin": "http://localhost:5173"},
        )
        assert result.headers["x-request-id"] == identifier.hex
        assert "X-Request-ID" in result.headers["access-control-expose-headers"]
        assert result.headers["x-frame-options"] == "DENY"
        assert client.get("/", headers={"Host": "untrusted.example"}).status_code == 400
        response = client.get("/operational-test/private-event?password=do-not-log")
        assert response.status_code == 500
        assert "private SQL" not in response.text
        assert len(response.headers["x-request-id"]) == 32
        assert response.headers["cache-control"] == "no-store"
    assert "do-not-log" not in caplog.text
    assert "private-event" not in caplog.text
    assert len(correlation_id("bad\nrequest")) == 32


def test_docs_can_be_disabled_without_losing_application_routes():
    app = create_app(Settings(_env_file=None, api_docs_enabled=False))
    with TestClient(app) as client:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code == 404
        assert client.get("/api/system/live").status_code == 200
        assert client.get("/api/auth/me").status_code == 401


def test_openapi_contains_all_phases_without_collisions():
    app = create_app(Settings(_env_file=None))
    schema = app.openapi()
    identifiers = [
        operation["operationId"]
        for path in schema["paths"].values()
        for operation in path.values()
        if isinstance(operation, dict) and "operationId" in operation
    ]
    assert len(identifiers) == len(set(identifiers))
    paths = schema["paths"]
    for prefix in (
        "auth",
        "events",
        "detection",
        "risk",
        "incidents",
        "threats",
        "dashboard",
        "ai",
        "analytics",
        "reports",
    ):
        assert any(path.startswith(f"/api/{prefix}") for path in paths)
    assert "/api/system/ready" in paths


def test_readiness_recovers_after_connection_failure():
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    connection.execute.return_value.scalars.return_value = migration_heads()
    app = create_app(Settings(_env_file=None))
    app.dependency_overrides[get_engine] = lambda: engine
    with TestClient(app) as client:
        engine.connect.side_effect = OperationalError("SELECT 1", {}, Exception("secret"))
        assert client.get("/api/system/ready").status_code == 503
        assert client.get("/api/system/live").status_code == 200
        engine.connect.side_effect = None
        assert client.get("/api/system/ready").json()["status"] == "ready"


def test_clean_and_existing_migrations_with_readiness(database_url):
    with isolated_schema(database_url) as engine:
        app = create_app(Settings(_env_file=None))
        app.dependency_overrides[get_engine] = lambda: engine
        with TestClient(app) as client:
            before = client.get("/api/system/ready")
            assert before.status_code == 503
            assert before.json()["database"] == "connected"
            assert before.json()["migrations"] == "pending"
            with engine.begin() as connection:
                command.upgrade(migration_config(connection), "head")
                connection.execute(
                    text(
                        "INSERT INTO system_metrics (metric_name,metric_value,unit) "
                        "VALUES ('operational_sentinel',1,'count')"
                    )
                )
            assert client.get("/api/system/ready").status_code == 200
            with engine.begin() as connection:
                command.upgrade(migration_config(connection), "head")
                command.check(migration_config(connection))
                assert (
                    connection.scalar(
                        text(
                            "SELECT count(*) FROM system_metrics "
                            "WHERE metric_name='operational_sentinel'"
                        )
                    )
                    == 1
                )


def test_server_entrypoint_uses_validated_runtime_settings(monkeypatch):
    import uvicorn

    from app import server

    settings = Settings(_env_file=None)
    monkeypatch.setattr(server, "get_settings", lambda: settings)
    run = MagicMock()
    monkeypatch.setattr(uvicorn, "run", run)
    assert server.main() == 0
    kwargs = run.call_args.kwargs
    assert kwargs["reload"] is False
    assert kwargs["proxy_headers"] is False
    assert kwargs["workers"] == 1
    assert kwargs["access_log"] is False


def test_entrypoint_reports_configuration_fields_without_values(monkeypatch, capsys):
    from app import server

    def invalid():
        return Settings(_env_file=None, postgres_password="private-invalid")

    monkeypatch.setattr(server, "get_settings", invalid)
    assert server.main() == 1
    output = capsys.readouterr().err
    assert "postgres_password" in output
    assert "private-invalid" not in output
