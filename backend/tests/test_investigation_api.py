"""Phase 12 projections reuse Phase 8 transactions, evidence, and role policy."""

import pytest
from sqlalchemy import select

from app.core.enums import UserRole
from app.models import SecurityEvent, User
from tests.test_incident_api import incident as incident
from tests.test_incident_engine import case, run, set_score
from tests.test_incident_engine import http as http
from tests.test_incident_engine import scored as scored
from tests.test_incident_engine import settings as settings
from tests.test_incident_engine import tokens as tokens


def test_assignment_directory_auth_roles_paging_and_projection(http, tokens, db):
    path = "/api/incidents/eligible-analysts"
    assert http.get(path).status_code == 401
    assert http.get(path, headers=tokens["VIEWER"]).status_code == 403
    for role in ("ADMIN", "ANALYST"):
        body = http.get(path, headers=tokens[role], params={"limit": 1}).json()
        assert body["total"] == 2 and len(body["items"]) == 1
        assert set(body["items"][0]) == {"id", "username", "full_name", "role", "is_active"}
        assert body["items"][0]["username"] == "admin"
        assert (
            http.get(path, headers=tokens[role], params={"offset": 1}).json()["items"][0][
                "username"
            ]
            == "analyst"
        )
    admin = db.scalar(select(User).where(User.role == UserRole.ADMIN))
    admin.is_active = False
    db.commit()
    headers = tokens["ANALYST"]
    assert http.get(path, headers=headers).json()["total"] == 1
    assert http.get(path, headers=headers, params={"q": "ANAL"}).json()["total"] == 1
    assert http.get(path, headers=headers, params={"q": "%"}).json()["total"] == 0
    assert http.get(path, headers=headers, params={"limit": 201}).status_code == 422


def test_detail_exposes_backend_transitions_and_stored_maximum_risk(
    http, tokens, scored, db, settings
):
    _, first = scored(60)
    finding, highest = scored(88, minutes=1, rule="CS-009")
    run(db, settings, until_empty=True)
    incident_id = case(db).incident_id
    path = "/api/incidents/" + incident_id
    detail = http.get(path, headers=tokens["ANALYST"]).json()
    assert detail["findings"]["total"] == 2
    assert detail["risk_assessment"]["assessment_id"] == highest.assessment_id
    assert detail["risk_assessment"]["finding_id"] == finding.finding_id
    assert detail["risk_assessment"]["breakdown"] == highest.breakdown
    assert detail["risk_assessment"]["risk_score"] == detail["risk_score"] == 88
    assert set(detail["allowed_transitions"]) == {"FALSE_POSITIVE", "INVESTIGATING"}
    assert http.get(path, headers=tokens["VIEWER"]).json()["allowed_transitions"] == []
    # A later reassessment is shown honestly; GET does not silently mutate stored incident risk.
    set_score(highest, 92)
    db.commit()
    detail = http.get(path, headers=tokens["ANALYST"]).json()
    assert detail["risk_assessment"]["risk_score"] == 92 and detail["risk_score"] == 88
    assert detail["findings"]["items"][0]["event_count"] == 1
    assert first.risk_score == 60


def test_incident_event_filters_ports_and_case_boundary(http, tokens, scored, db, settings):
    scored(70)
    scored(80, username="other", ip="203.0.113.4", device="other", minutes=90)
    run(db, settings, until_empty=True)
    incident_id = case(db).incident_id
    row = db.scalar(select(SecurityEvent).where(SecurityEvent.username == "employee014"))
    row.source_port, row.destination_port, row.service = 53210, 443, "authentication"
    db.commit()
    url = f"/api/incidents/{incident_id}/events"
    headers = tokens["VIEWER"]
    body = http.get(url, headers=headers).json()
    assert body["total"] == 1
    assert body["items"][0]["source_port"] == 53210
    assert body["items"][0]["destination_port"] == 443
    for key, value in {
        "source_ip": "198.51.100.44",
        "username": "employee014",
        "event_type": "LOGIN_FAILED",
        "service": "authentication",
        "status": "failed",
    }.items():
        assert http.get(url, headers=headers, params={key: value}).json()["total"] == 1
    for params in (
        {"username": "other"},
        {"event_type": "LOGIN_SUCCESS"},
        {"status": "success"},
        {"service": "unrelated"},
    ):
        assert http.get(url, headers=headers, params=params).json()["total"] == 0
    assert http.get(url, headers=headers, params={"offset": 1}).json()["items"] == []
    assert http.get(url, headers=headers, params={"source_ip": "bad"}).status_code == 422


def test_timeline_reverse_order_actor_resolution_and_refresh_audit(
    http, tokens, incident, settings
):
    url = f"/api/incidents/{incident}"
    headers = tokens["ANALYST"]
    http.patch(url + "/status", headers=headers, json={"status": "INVESTIGATING"})
    http.patch(
        url + "/status",
        headers=headers,
        json={"status": "RESOLVED", "resolution_summary": "Verified with account owner."},
    )
    http.post(
        "/api/threats/enrich/incidents",
        headers=headers,
        json={"incident_id": incident, "limit": 1, "force_refresh": True},
    )
    asc = http.get(url + "/timeline?limit=200", headers=headers).json()["items"]
    desc = http.get(url + "/timeline?limit=200&order=desc", headers=headers).json()["items"]
    assert desc == list(reversed(asc))
    resolution = next(item for item in desc if item["title"] == "INCIDENT_RESOLVED")
    assert resolution["actor_username"] == "analyst"
    assert resolution["details"]["previous_status"] == "INVESTIGATING"
    assert resolution["details"]["resolution_summary"] == "Verified with account owner."
    assert any(item["title"] == "INCIDENT_ENRICHMENT_TRIGGERED" for item in desc)
    event = next(item for item in asc if item["type"] == "SECURITY_EVENT")
    assert event["details"] == {"source_ip": "198.51.100.44", "username": "employee014"}
    assert http.get(url + "/timeline?order=random", headers=headers).status_code == 422


@pytest.mark.parametrize("suffix", ["", "/events", "/timeline", "/findings"])
def test_investigation_missing_case_and_auth(http, tokens, suffix):
    url = "/api/incidents/INC-MISSING" + suffix
    assert http.get(url).status_code == 401
    assert http.get(url, headers=tokens["VIEWER"]).status_code == 404
