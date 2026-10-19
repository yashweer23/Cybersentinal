"""Cloud compatibility checks; these do not claim a remote deployment exists."""

import argparse
import logging
from contextlib import nullcontext
from datetime import date
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import text

from app.config import Settings
from app.database import get_db, get_engine
from app.main import create_app
from app.operations.logging import SafeJsonFormatter
from scripts.cloud_release import release, verify_schema
from scripts.populate_cloud_demo import populate
from scripts.seed_detection_rules import seed_detection_rules
from scripts.verify_cloud import public_origin, verify
from tests.database_fixtures import isolated_schema
from tests.test_auth_api import PASSWORD
from tests.test_auth_api import fixture_hash as fixture_hash
from tests.test_auth_api import users as users

ORIGIN = "https://soc.example.com"
PASSWORD_URL = "url-only-validation-fixture"


@pytest.mark.parametrize("scheme", ["postgres", "postgresql", "postgresql+psycopg"])
def test_provider_url_normalizes_without_changing_local_settings(monkeypatch, scheme):
    monkeypatch.delenv("POSTGRES_PASSWORD")
    supplied = f"{scheme}://cloud:{PASSWORD_URL}%40%2F%25@private-db:5432/managed"
    settings = Settings(_env_file=None, DATABASE_URL=supplied)
    assert settings.database_url.drivername == "postgresql+psycopg"
    assert settings.database_url.password == PASSWORD_URL + "@/%"
    assert settings.database_url.host == "private-db"
    assert settings.database_url.database == "managed"
    assert settings.database_url.query["sslmode"] == "require"
    assert supplied not in repr(settings)
    assert PASSWORD_URL not in settings.model_dump_json()
    assert PASSWORD_URL not in str(settings.database_url)


@pytest.mark.parametrize(
    "url",
    [
        "not-a-url",
        "sqlite:///memory",
        "mysql://u:p@host/db",
        "postgresql://u@host/db",
        "postgresql://u:p@host",
        "postgresql://u:p@/db",
        "postgresql://u:p@host:99999/db",
        "postgresql://u:p@host:invalid/db",
        "postgresql://u:p@host/db?sslmode=disable",
        "postgresql://u:p@host/db?sslmode=prefer",
        "postgresql://u:p@host/db?host=other",
        "postgresql://u:p@host/db?options=-c%20role=other",
        "postgresql://u:p@host/db?sslmode=require&sslmode=require",
    ],
)
def test_bad_provider_urls_fail_without_printing_input(url):
    with pytest.raises(ValidationError) as failure:
        Settings(_env_file=None, DATABASE_URL=url)
    assert url not in str(failure.value)


def test_certificate_validation_is_preserved():
    url = f"postgresql://u:{PASSWORD_URL}@host/db?sslmode=verify-full&sslrootcert=/certs/ca.pem"
    settings = Settings(_env_file=None, DATABASE_URL=url)
    assert settings.database_url.query["sslmode"] == "verify-full"
    assert settings.database_url.query["sslrootcert"] == "/certs/ca.pem"
    with pytest.raises(ValueError):
        Settings(_env_file=None, DATABASE_URL=url, database_sslmode="require").database_url


def test_missing_url_and_local_password_fails(monkeypatch):
    monkeypatch.delenv("POSTGRES_PASSWORD")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_provider_url_preserves_production_minimum_password_length():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            app_env="production",
            DATABASE_URL="postgresql://u:abcdefgh@host/managed",
        )


def test_port_alias_keeps_existing_server_port_precedence(monkeypatch):
    monkeypatch.setenv("PORT", "10000")
    assert Settings(_env_file=None).server_port == 10000
    monkeypatch.setenv("SERVER_PORT", "8000")
    assert Settings(_env_file=None).server_port == 8000
    assert Settings(_env_file=None, server_port=19000).server_port == 19000


@pytest.mark.parametrize(
    "value",
    [
        "http://soc.example.com",
        "https://soc.example.com/",
        "https://soc.example.com?token=a",
        "https://u:p@host",
        "https://soc.example.com:8080",
        "https://*.example.com",
    ],
)
def test_public_origin_is_exact_https(value):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, public_origin=value)
    with pytest.raises(argparse.ArgumentTypeError):
        public_origin(value)


def test_canonical_https_ignores_spoofed_forwarding_and_retains_host_validation(monkeypatch):
    monkeypatch.setattr("app.main.build_engine", lambda _: MagicMock())
    settings = Settings(_env_file=None, app_env="production", public_origin=ORIGIN)
    assert settings.cors_origins == [ORIGIN]
    assert settings.trusted_browser_origins == {ORIGIN}
    app = create_app(settings)

    @app.get("/cloud-request-test")
    def request_data(request: Request):
        return {"scheme": request.url.scheme, "peer": request.client.host}

    with TestClient(app, base_url=ORIGIN) as client:
        response = client.get(
            "/cloud-request-test",
            headers={
                "X-Forwarded-Proto": "http",
                "X-Forwarded-For": "198.51.100.73",
                "Forwarded": "proto=http;host=attacker.invalid",
            },
        )
        assert response.json() == {"scheme": "https", "peer": "testclient"}
        assert (
            client.get("/api/system/live", headers={"Host": "attacker.invalid"}).status_code == 400
        )
        assert (
            client.post(
                "/api/auth/refresh",
                headers={"Origin": "https://attacker.invalid", "X-CSRF-Guard": "1"},
            ).status_code
            == 403
        )
    with pytest.raises(ValidationError):
        Settings(_env_file=None, public_origin=ORIGIN, proxy_headers_enabled=True)


def test_database_url_is_redacted_even_if_driver_spelling_changes():
    record = logging.LogRecord(
        "cloud", 40, "", 0, f"Failed postgresql+psycopg://u:{PASSWORD_URL}@db/demo", (), None
    )
    encoded = SafeJsonFormatter().format(record)
    assert PASSWORD_URL not in encoded
    assert "[REDACTED_DATABASE_URL]" in encoded


def test_release_migrates_clean_database_and_checks_objects(database_url):
    with isolated_schema(database_url) as engine:
        with engine.begin() as connection:
            db_name = connection.scalar(text("SELECT current_database()"))
            with pytest.raises(RuntimeError, match="Target database"):
                release(connection, expected_database="not-the-target", migrate=True)
            result = release(connection, expected_database=db_name, migrate=True)
            assert result["tables"] == 17
            assert result["foreign_keys"] > 0 and result["indexes"] > 0
            assert result["enums"] > 0
            connection.execute(
                text(
                    "INSERT INTO system_metrics(metric_name, metric_value, unit) "
                    "VALUES ('cloud-release-sentinel', 1, 'count')"
                )
            )
        with engine.begin() as connection:
            assert release(connection, expected_database=db_name, migrate=True) == result
            assert connection.scalar(text("SELECT count(*) FROM system_metrics")) == 1
            connection.execute(text("DROP INDEX ix_security_events_timestamp"))
            with pytest.raises(RuntimeError, match="Missing index"):
                verify_schema(connection)


def test_release_rejects_missing_migrations(database_url):
    with isolated_schema(database_url) as engine, engine.connect() as connection:
        with pytest.raises(RuntimeError, match="not current"):
            verify_schema(connection)


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST", "VIEWER"])
def test_smoke_runner_exercises_real_production_auth_rbac(db, users, monkeypatch, role):
    monkeypatch.setattr("app.main.build_engine", lambda _: MagicMock())
    app = create_app(Settings(_env_file=None, app_env="production", public_origin=ORIGIN))
    app.dependency_overrides[get_db] = lambda: db
    # Keep readiness inside the test's rollback-isolated connection too.
    app.dependency_overrides[get_engine] = lambda: SimpleNamespace(
        connect=lambda: nullcontext(db.connection())
    )

    # The backend test substitutes only the static shell; Nginx is verified separately.
    @app.get("/healthz")
    def frontend_health():
        return {"status": "alive"}

    @app.get("/{route:path}", response_class=HTMLResponse)
    def frontend_shell(route: str):
        return '<html><div id="root"></div></html>'

    with TestClient(app, base_url=ORIGIN) as client:
        original_request = client.request

        def frontend_root(method, url, **kwargs):
            if method == "GET" and url == "/":
                import httpx

                return httpx.Response(
                    200, text='<div id="root"></div>', headers={"content-type": "text/html"}
                )
            return original_request(method, url, **kwargs)

        monkeypatch.setattr(client, "request", frontend_root)
        results = verify(client, ORIGIN, role, role.lower(), PASSWORD)
    assert results[-1]["check"] == "Revoked session"
    assert results[-1]["status_code"] == 401


def test_cloud_demo_uses_existing_api_and_replays_without_duplicates(db, users, monkeypatch):
    monkeypatch.setattr("app.main.build_engine", lambda _: MagicMock())
    app = create_app(Settings(_env_file=None, app_env="production", public_origin=ORIGIN))
    app.dependency_overrides[get_db] = lambda: db
    seed_detection_rules(db)
    db.commit()
    with TestClient(app, base_url=ORIGIN) as client:
        client.headers.update({"Origin": ORIGIN, "X-CSRF-Guard": "1"})
        login = client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
        assert login.status_code == 200
        client.headers["Authorization"] = "Bearer " + login.json()["access_token"]
        result = populate(client, start_date=date(2026, 10, 11), count=1000)
        assert result["inserted"] == 1000
        assert result["unprocessed_events"] == 0
        assert result["external_lookups"] == 0
        assert result["detection"]["findings_created"] > 0
        with pytest.raises(RuntimeError, match="already contains"):
            populate(client, start_date=date(2026, 10, 11), count=1000)
        replay = populate(client, start_date=date(2026, 10, 11), count=1000, resume=True)
        assert replay["inserted"] == 0 and replay["duplicates"] == 1000
        assert replay["detection"]["findings_created"] == 0
        assert client.post("/api/auth/logout").status_code == 204


@pytest.mark.parametrize("unsafe", ["role", "live_provider", "existing_events", "disabled_rule"])
def test_cloud_demo_refuses_unsafe_initialization_without_mutation(unsafe):
    import httpx

    def handler(request):
        assert request.method == "GET"
        answers = {
            "/api/auth/me": {"role": "VIEWER" if unsafe == "role" else "ADMIN"},
            "/api/threats/providers/status": {
                "mode": "live" if unsafe == "live_provider" else "mock"
            },
            "/api/events": {"total": 1 if unsafe == "existing_events" else 0},
            "/api/detection-rules": [{"enabled": unsafe != "disabled_rule"} for _ in range(10)],
        }
        return httpx.Response(200, json=answers[request.url.path])

    with httpx.Client(base_url=ORIGIN, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RuntimeError):
            populate(client, start_date=date(2026, 10, 11), count=1000)
