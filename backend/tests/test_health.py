from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.config import Settings
from app.database import get_engine
from app.main import create_app


@pytest.fixture
def client():
    application = create_app(Settings(_env_file=None))
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    connection.execute.return_value.scalar_one.return_value = 1
    application.dependency_overrides[get_engine] = lambda: engine
    with TestClient(application) as test_client:
        yield test_client, engine


def test_readiness_executes_query_and_reports_connected(client):
    http, engine = client
    response = http.get("/api/system/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["services"]["database"]["status"] == "connected"
    assert response.headers["cache-control"] == "no-store"
    query = engine.connect.return_value.__enter__.return_value.execute.call_args.args[0]
    assert str(query) == "SELECT 1"


def test_database_outage_is_503_without_leaking_secrets(client):
    http, engine = client
    engine.connect.side_effect = OperationalError("SELECT 1", {}, Exception("sensitive-password"))
    response = http.get("/api/system/health")
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["services"]["database"]["status"] == "disconnected"
    assert "sensitive-password" not in response.text
    assert http.get("/api/system/live").json() == {"status": "alive"}


def test_docs_and_health_contract_are_available(client):
    http, _ = client
    assert http.get("/docs").status_code == 200
    schema = http.get("/openapi.json").json()
    assert "503" in schema["paths"]["/api/system/health"]["get"]["responses"]


def test_cors_only_allows_configured_origin(client):
    http, _ = client
    allowed = http.get("/api/system/live", headers={"Origin": "http://localhost:5173"})
    denied = http.get("/api/system/live", headers={"Origin": "https://untrusted.example"})
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-origin" not in denied.headers
