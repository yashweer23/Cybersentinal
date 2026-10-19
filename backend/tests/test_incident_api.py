from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from app.core.enums import UserRole
from app.models import (
    AuditLog,
    DetectionFinding,
    Incident,
    IncidentFinding,
    SecurityEvent,
    User,
)
from tests.test_incident_engine import case, count, run
from tests.test_incident_engine import http as http
from tests.test_incident_engine import scored as scored
from tests.test_incident_engine import settings as settings
from tests.test_incident_engine import tokens as tokens


@pytest.fixture
def incident(db, settings, scored):
    scored(70)
    run(db, settings)
    return case(db).incident_id


def test_reads_and_swagger_all_incident_operations(http, tokens, incident):
    headers = tokens["VIEWER"]
    base = "/api/incidents/" + incident
    for path in (
        "/api/incidents",
        "/api/incidents/stats",
        base,
        *[base + "/" + part for part in ("findings", "events", "timeline", "comments")],
    ):
        assert http.get(path).status_code == 401
        response = http.get(path, headers=headers)
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        assert "hashed_password" not in response.text and "ai_analysis" not in response.text
    detail = http.get(base, headers=headers).json()
    assert detail["findings"]["total"] == detail["evidence_total"] == 1
    assert detail["comments"]["total"] == 0
    assert detail["timeline"]["total"] >= 5
    paths = http.get("/openapi.json").json()["paths"]
    methods = [
        ("", "get"),
        ("/stats", "get"),
        ("/process", "post"),
        ("/{incident_id}", "get"),
        ("/{incident_id}/assign", "patch"),
        ("/{incident_id}/status", "patch"),
        ("/{incident_id}/comments", "post"),
        *[
            ("/{incident_id}/" + suffix, "get")
            for suffix in ("comments", "events", "findings", "timeline")
        ],
    ]
    for suffix, method in methods:
        operation = paths["/api/incidents" + suffix][method]
        assert operation["security"] == [{"BearerAuth": []}]
        assert "200" in operation["responses"] or "201" in operation["responses"]
    assert http.get("/docs").status_code == 200


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("post", "/process", {}),
        ("post", "/CASE/comments", {"comment": "Review"}),
        ("patch", "/CASE/status", {"status": "INVESTIGATING"}),
        ("patch", "/CASE/assign", {"analyst_id": None}),
    ],
)
def test_viewer_cannot_write(http, tokens, incident, method, path, body):
    url = "/api/incidents" + path.replace("CASE", incident)
    assert getattr(http, method)(url, json=body).status_code == 401
    assert getattr(http, method)(url, headers=tokens["VIEWER"], json=body).status_code == 403


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST"])
def test_investigation_status_assignment_notes_and_audit(http, tokens, db, incident, role):
    headers = tokens[role]
    base = "/api/incidents/" + incident
    target = db.scalar(select(User).where(User.role == UserRole.ANALYST))
    response = http.patch(base + "/assign", headers=headers, json={"analyst_id": str(target.id)})
    assert response.status_code == 200, response.text
    assert response.json()["assigned_analyst"]["username"] == "analyst"
    response = http.post(
        base + "/comments", headers=headers, json={"comment": " Reviewed evidence. "}
    )
    assert response.status_code == 201 and response.json()["comment"] == "Reviewed evidence."
    assert response.json()["author"]["role"] == role
    assert (
        http.patch(
            base + "/status",
            headers=headers,
            json={"status": "RESOLVED", "resolution_summary": "Done"},
        ).status_code
        == 409
    )
    assert (
        http.patch(base + "/status", headers=headers, json={"status": "INVESTIGATING"}).status_code
        == 200
    )
    assert (
        http.patch(base + "/status", headers=headers, json={"status": "RESOLVED"}).status_code
        == 422
    )
    resolved = http.patch(
        base + "/status",
        headers=headers,
        json={"status": "RESOLVED", "resolution_summary": "Verified activity and account owner."},
    )
    assert resolved.status_code == 200 and resolved.json()["resolved_at"]
    reopened = http.patch(
        base + "/status",
        headers=headers,
        json={"status": "INVESTIGATING", "reason": "Review new evidence."},
    )
    assert reopened.status_code == 200 and reopened.json()["resolved_at"] is None
    assert reopened.json()["resolution_summary"] is None
    actions = [a.action for a in db.scalars(select(AuditLog))]
    assert {
        "INCIDENT_ASSIGNED",
        "INCIDENT_COMMENT_ADDED",
        "INCIDENT_STATUS_CHANGED",
        "INCIDENT_RESOLVED",
        "INCIDENT_REOPENED",
        "INCIDENT_CREATED",
        "FINDING_ATTACHED_TO_INCIDENT",
    } <= set(actions)
    audit = db.scalar(select(AuditLog).where(AuditLog.action == "INCIDENT_REOPENED"))
    assert audit.old_value["resolution_summary"] == "Verified activity and account owner."
    timeline = http.get(base + "/timeline", headers=headers).json()
    keys = [(x["timestamp"], x["type"], x["reference_id"]) for x in timeline["items"]]
    assert keys == sorted(keys)
    assert {"SECURITY_EVENT", "DETECTION", "RISK_ASSESSMENT", "COMMENT", "AUDIT"} <= {
        x["type"] for x in timeline["items"]
    }
    notes = http.get(base + "/comments", headers=headers).json()
    assert notes["total"] == 1 and notes["items"][0]["author"]["username"] == role.lower()
    note_audit = db.scalar(select(AuditLog).where(AuditLog.action == "INCIDENT_COMMENT_ADDED"))
    assert "comment" not in note_audit.new_value and note_audit.user_id is not None
    unassigned = http.patch(base + "/assign", headers=headers, json={"analyst_id": None})
    assert unassigned.status_code == 200 and unassigned.json()["assigned_analyst"] is None


def test_false_positive_requires_reason_and_preserves_all_evidence(http, tokens, db, incident):
    base, headers = "/api/incidents/" + incident, tokens["ANALYST"]
    before = tuple(count(db, m) for m in (SecurityEvent, DetectionFinding, IncidentFinding))
    assert (
        http.patch(base + "/status", headers=headers, json={"status": "FALSE_POSITIVE"}).status_code
        == 422
    )
    response = http.patch(
        base + "/status",
        headers=headers,
        json={"status": "FALSE_POSITIVE", "reason": "Approved exercise"},
    )
    assert (
        response.status_code == 200 and response.json()["resolution_summary"] == "Approved exercise"
    )
    assert tuple(count(db, m) for m in (SecurityEvent, DetectionFinding, IncidentFinding)) == before
    assert (
        http.patch(
            base + "/status",
            headers=headers,
            json={"status": "RESOLVED", "resolution_summary": "No"},
        ).status_code
        == 409
    )
    assert (
        http.patch(base + "/status", headers=headers, json={"status": "INVESTIGATING"}).status_code
        == 200
    )


@pytest.mark.parametrize(
    "kind,expected",
    [("ADMIN", 200), ("ANALYST", 200), ("VIEWER", 422), ("inactive", 422), ("missing", 404)],
)
def test_assignee_validation(http, tokens, db, incident, kind, expected):
    if kind == "missing":
        identifier = uuid4()
    else:
        user = db.scalar(
            select(User).where(
                User.role == (UserRole.ANALYST if kind == "inactive" else UserRole(kind))
            )
        )
        identifier = user.id
        if kind == "inactive":
            user.is_active = False
            db.commit()
    response = http.patch(
        "/api/incidents/" + incident + "/assign",
        headers=tokens["ADMIN"],
        json={"analyst_id": str(identifier)},
    )
    assert response.status_code == expected, response.text


def test_closed_case_policy_and_optional_reopen(http, tokens, db, settings, scored):
    scored(60)
    run(db, settings)
    identifier = case(db).incident_id
    headers = tokens["ANALYST"]
    base = "/api/incidents/" + identifier
    assert (
        http.patch(base + "/status", headers=headers, json={"status": "INVESTIGATING"}).status_code
        == 200
    )
    assert (
        http.patch(
            base + "/status",
            headers=headers,
            json={"status": "RESOLVED", "resolution_summary": "Initial review complete"},
        ).status_code
        == 200
    )
    scored(80, minutes=2, created_at=datetime.now(UTC))
    assert run(db, settings).incidents_created == 1
    # Closing the new active case, then explicitly enabling timed reopen, permits a later finding.
    newer = db.scalar(select(Incident).where(Incident.incident_id != identifier))
    next_url = "/api/incidents/" + newer.incident_id
    http.patch(next_url + "/status", headers=headers, json={"status": "INVESTIGATING"})
    http.patch(
        next_url + "/status",
        headers=headers,
        json={"status": "RESOLVED", "resolution_summary": "Done"},
    )
    settings.incident_reopen_window_minutes = 10
    scored(90, minutes=3, created_at=datetime.now(UTC))
    result = run(db, settings, until_empty=True)
    assert (
        result.incidents_created == 0
        and result.correlated_findings == 1
        and count(db, Incident) == 2
    )
    assert (
        db.scalar(
            select(func.count()).select_from(Incident).where(Incident.status == "INVESTIGATING")
        )
        == 1
    )
    assert any(
        a.new_value.get("automatic")
        for a in db.scalars(select(AuditLog).where(AuditLog.action == "INCIDENT_REOPENED"))
    )


def test_list_filters_pagination_stats_and_processing(http, tokens, db, settings, scored):
    finding, _ = scored(90)
    scored(50, username="other", ip="203.0.113.4", device="other", minutes=70)
    headers = tokens["ANALYST"]
    response = http.post("/api/incidents/process", headers=headers, json={"until_empty": True})
    assert response.status_code == 200 and response.json()["incidents_created"] == 2
    rows = http.get("/api/incidents?limit=1", headers=headers).json()
    first = rows["items"][0]
    assert rows["total"] == 2 and first["risk_score"] == 90
    for params in (
        {"minimum_risk": 75},
        {"severity": "CRITICAL"},
        {"username": finding.username},
        {"source_ip": str(finding.source_ip)},
        {"start_time": finding.first_seen.isoformat(), "end_time": finding.last_seen.isoformat()},
    ):
        assert http.get("/api/incidents", headers=headers, params=params).json()["total"] == 1
    assert (
        http.get("/api/incidents?rule_id=CS-001&status=OPEN", headers=headers).json()["total"] == 2
    )
    assert (
        http.get("/api/incidents?offset=1&limit=1", headers=headers).json()["items"][0][
            "incident_id"
        ]
        != first["incident_id"]
    )
    admin = db.scalar(select(User).where(User.role == UserRole.ADMIN))
    http.patch(
        "/api/incidents/" + first["incident_id"] + "/assign",
        headers=headers,
        json={"analyst_id": str(admin.id)},
    )
    assert (
        http.get(
            "/api/incidents", headers=headers, params={"assigned_analyst": str(admin.id)}
        ).json()["total"]
        == 1
    )
    stats = http.get("/api/incidents/stats", headers=tokens["VIEWER"]).json()
    assert stats["total"] == stats["open"] == 2 and stats["unassigned_incidents"] == 1
    assert stats["average_risk_score"] == 70
    assert (
        http.post("/api/incidents/process", headers=headers, json={}).json()["incidents_created"]
        == 0
    )
    for suffix in ("", "/findings", "/events", "/timeline", "/comments"):
        assert http.get("/api/incidents/missing" + suffix, headers=headers).status_code == 404
    assert (
        http.post(
            "/api/incidents/process", headers=headers, json={"finding": "missing"}
        ).status_code
        == 404
    )
    assert (
        http.get("/api/incidents?minimum_risk=90&maximum_risk=10", headers=headers).status_code
        == 422
    )
    assert http.get("/api/incidents?limit=201", headers=headers).status_code == 422
    assert (
        http.post(
            "/api/incidents/" + first["incident_id"] + "/comments",
            headers=headers,
            json={"comment": " "},
        ).status_code
        == 422
    )


def test_empty_statistics_and_api_dry_run(http, tokens, db, scored):
    stats = http.get("/api/incidents/stats", headers=tokens["VIEWER"]).json()
    assert stats["total"] == stats["average_risk_score"] == 0
    scored(60)
    response = http.post("/api/incidents/process", headers=tokens["ADMIN"], json={"dry_run": True})
    assert response.status_code == 200 and response.json()["projected_incidents_created"] == 1
    assert count(db, Incident) == 0
