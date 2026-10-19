"""Cross-module authorization at the HTTP boundary."""

import pytest
from sqlalchemy import event as sql_event
from sqlalchemy import select

from app.models import User
from tests.test_event_ingestion import http as http
from tests.test_event_ingestion import settings as settings
from tests.test_event_ingestion import tokens as tokens
from tests.test_incident_api import incident as incident
from tests.test_incident_engine import scored as scored

WRITES = [
    ("POST", "/api/events/ingest/batch", {"events": [{}]}),
    ("POST", "/api/detection/run", {}),
    ("POST", "/api/risk/run", {}),
    ("POST", "/api/incidents/process", {}),
    ("PATCH", "/api/incidents/{case}/status", {"status": "INVESTIGATING"}),
    ("PATCH", "/api/incidents/{case}/assign", {"analyst_id": None}),
    ("POST", "/api/incidents/{case}/comments", {"comment": "Unauthorized note"}),
    ("PATCH", "/api/detection-rules/CS-001", {"enabled": False}),
    ("POST", "/api/threats/lookup", {"ip": "198.51.100.73"}),
    ("POST", "/api/threats/enrich/incidents", {}),
    ("POST", "/api/ai/incidents/{case}/analyze", {}),
    ("POST", "/api/ai/incidents/{case}/ask", {"question": "Explain the incident"}),
    ("POST", "/api/ai/overview/ask", {"question": "Show critical incidents today"}),
]


@pytest.mark.parametrize("method,path,payload", WRITES)
@pytest.mark.parametrize("role,expected", [(None, 401), ("VIEWER", 403)])
def test_forbidden_writes_never_reach_mutating_sql(
    http, tokens, incident, db, method, path, payload, role, expected
):
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.lstrip().split()[0].upper())

    connection = db.connection()
    sql_event.listen(connection, "before_cursor_execute", capture)
    try:
        response = http.request(
            method, path.format(case=incident), json=payload, headers=tokens[role] if role else {}
        )
    finally:
        sql_event.remove(connection, "before_cursor_execute", capture)
    assert response.status_code == expected, response.text
    assert not {"INSERT", "UPDATE", "DELETE"} & set(statements)
    assert "hashed_password" not in response.text


def test_database_role_change_immediately_overrides_old_jwt(http, tokens, db, incident):
    admin = db.scalar(select(User).where(User.username == "admin"))
    admin.role = "VIEWER"
    db.commit()
    headers = tokens["ADMIN"]
    assert http.post("/api/detection/run", headers=headers, json={}).status_code == 403
    assert http.get(f"/api/incidents/{incident}", headers=headers).status_code == 200
    admin.is_active = False
    db.commit()
    assert http.get(f"/api/incidents/{incident}", headers=headers).status_code == 401


@pytest.mark.parametrize("path", ["events", "detections", "risk", "incidents"])
def test_sql_like_username_is_a_literal_filter(http, tokens, incident, path):
    response = http.get(
        f"/api/{path}", headers=tokens["ANALYST"], params={"username": "employee' OR '1'='1"}
    )
    assert response.status_code == 200, response.text
    assert response.json()["items"] == [] and response.json()["total"] == 0
    assert http.get(f"/api/incidents/{incident}", headers=tokens["VIEWER"]).status_code == 200
