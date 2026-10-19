from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.enums import UserRole
from app.database import get_db
from app.main import create_app
from app.models import User
from app.security.dependencies import get_current_user
from scripts.seed_detection_rules import seed_detection_rules
from tests.database_fixtures import isolated_schema


@pytest.fixture
def http(db, monkeypatch):
    monkeypatch.setattr("app.main.build_engine", lambda settings: MagicMock())
    app = create_app(Settings(_env_file=None, app_env="test"))
    app.dependency_overrides[get_db] = lambda: db
    # These retained tests exercise rule queries; authentication is covered in test_auth_api.
    app.dependency_overrides[get_current_user] = lambda: User(role=UserRole.VIEWER)
    with TestClient(app) as client:
        yield client


def test_status_rules_and_docs_use_real_database(http, db):
    assert seed_detection_rules(db) == 10
    response = http.get("/api/database/status")
    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "database": "postgresql",
        "connected": True,
        "schema_ready": True,
        "migration_revision": "0008_ai_analyses",
        "expected_revision": "0008_ai_analyses",
        "missing_tables": [],
    }
    rules = http.get("/api/detection-rules")
    assert rules.status_code == 200
    assert len(rules.json()) == 10
    assert rules.json()[0]["rule_id"] == "CS-001"
    assert rules.json()[0]["configuration"]["failed_attempt_threshold"] == 5
    page = http.get("/api/detection-rules?limit=2&offset=2")
    assert [rule["rule_id"] for rule in page.json()] == ["CS-003", "CS-004"]
    assert http.get("/api/detection-rules?limit=101").status_code == 422
    assert http.get("/docs").status_code == 200
    assert "/api/database/status" in http.get("/openapi.json").json()["paths"]


def test_missing_migration_returns_degraded_without_crashing(database_url, monkeypatch):
    monkeypatch.setattr("app.main.build_engine", lambda settings: MagicMock())
    with isolated_schema(database_url) as engine, Session(engine) as session:
        app = create_app(Settings(_env_file=None, app_env="test"))
        app.dependency_overrides[get_db] = lambda: session
        app.dependency_overrides[get_current_user] = lambda: User(role=UserRole.VIEWER)
        with TestClient(app) as http:
            response = http.get("/api/database/status")
            assert response.status_code == 503
            assert response.json()["connected"] is True
            assert len(response.json()["missing_tables"]) == 17
            assert http.get("/api/detection-rules").status_code == 503


def test_database_errors_do_not_expose_credentials(monkeypatch):
    monkeypatch.setattr("app.main.build_engine", lambda settings: MagicMock())
    session = MagicMock()
    error = OperationalError("query", {}, Exception("sensitive-database-password"))
    session.execute.side_effect = error
    session.scalars.side_effect = error
    app = create_app(Settings(_env_file=None, app_env="test"))
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_current_user] = lambda: User(role=UserRole.VIEWER)
    with TestClient(app) as http:
        for path in ("/api/database/status", "/api/detection-rules"):
            response = http.get(path)
            assert response.status_code == 503
            assert "sensitive-database-password" not in response.text


def test_development_routes_are_not_registered_in_production(monkeypatch):
    monkeypatch.setattr("app.main.build_engine", lambda settings: MagicMock())
    app = create_app(Settings(_env_file=None, app_env="production"))
    # Use a trusted production host; host rejection is tested separately.
    with TestClient(app, base_url="https://localhost") as http:
        assert http.get("/api/database/status").status_code == 404
        assert http.get("/api/detection-rules").status_code == 401
        assert (
            http.post("/api/auth/login", json={}, headers={"X-CSRF-Guard": "1"}).status_code == 422
        )
        assert http.get("/api/test/admin").status_code == 404
        assert http.get("/docs").status_code == 200
