import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select

from app.detection.engine import DetectionEngine
from app.incidents.engine import IncidentManagementService
from app.models import AuditLog, DetectionFinding, Incident, RiskAssessment, User
from app.risk.engine import RiskScoringEngine
from app.schemas.detection import DetectionRunRequest
from app.schemas.incident import IncidentRunRequest
from app.schemas.risk import RiskRunRequest
from app.threat_intelligence.service import ThreatIntelligenceService
from scripts.seed_detection_rules import seed_detection_rules
from tests.test_detection_rules import event
from tests.test_incident_engine import http as http
from tests.test_incident_engine import scored as scored
from tests.test_incident_engine import settings as settings
from tests.test_incident_engine import tokens as tokens
from tests.test_threat_providers import IP, KEY, abuse
from tests.test_threat_service import MOCK_IP


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST"])
def test_lookup_and_refresh_roles(http, tokens, role):
    path = "/api/threats/lookup"
    result = http.post(path, json={"ip": MOCK_IP}, headers=tokens[role])
    assert result.status_code == 200, result.text
    assert result.json()["simulation"] and not result.json()["cache_hit"]
    assert result.headers["cache-control"] == "no-store"
    assert http.post(path, json={"ip": MOCK_IP}, headers=tokens[role]).json()["cache_hit"]
    assert not http.post(
        path, json={"ip": MOCK_IP, "force_refresh": True}, headers=tokens[role]
    ).json()["cache_hit"]


@pytest.mark.parametrize(
    "path,body",
    [("/api/threats/lookup", {"ip": MOCK_IP}), ("/api/threats/enrich/incidents", {"limit": 1})],
)
def test_viewer_and_unauthenticated_cannot_write(http, tokens, path, body):
    assert http.post(path, json=body).status_code == 401
    assert http.post(path, json=body, headers=tokens["VIEWER"]).status_code == 403


@pytest.mark.parametrize("ip", ["bad", "8.8.8.8/24", "https://8.8.8.8", "fe80::1%eth0"])
def test_invalid_request_input_is_422(http, tokens, ip):
    assert (
        http.post("/api/threats/lookup", json={"ip": ip}, headers=tokens["ADMIN"]).status_code
        == 422
    )
    if "/" not in ip:
        assert http.get("/api/threats/ip/" + ip, headers=tokens["VIEWER"]).status_code == 422


def test_cached_read_routes_swagger_filters_and_missing_data(
    http, tokens, db, settings, scored, monkeypatch
):
    finding, _ = scored(70, ip=MOCK_IP)
    IncidentManagementService(db, settings).run()
    case = db.scalar(select(Incident))
    paths = [
        "/api/threats",
        "/api/threats/providers/status",
        "/api/threats/ip/" + MOCK_IP,
        f"/api/incidents/{case.incident_id}/threat-intelligence",
        f"/api/detections/{finding.finding_id}/threat-intelligence",
    ]
    for path in paths:
        assert http.get(path).status_code == 401
    assert http.get(paths[2], headers=tokens["VIEWER"]).status_code == 404
    response = http.post(
        "/api/threats/enrich/incidents", json={"limit": 10}, headers=tokens["ANALYST"]
    )
    assert response.status_code == 200, response.text
    assert response.json()["incidents_enriched"] == 1

    def forbidden(*args, **kwargs):
        pytest.fail("GET called lookup")

    monkeypatch.setattr(ThreatIntelligenceService, "lookup_ip", forbidden)
    for path in paths:
        result = http.get(path, headers=tokens["VIEWER"])
        assert result.status_code == 200, result.text
        assert KEY not in result.text
    page = http.get(
        "/api/threats?limit=1&reputation_level=MALICIOUS&provider=CyberSentinel%20Mock",
        headers=tokens["VIEWER"],
    ).json()
    assert page["total"] == 1 and len(page["items"]) == 1
    assert page["items"][0]["providers"][0]["raw_response"] == {}
    assert (
        http.get(paths[3] + "?limit=1&offset=1", headers=tokens["VIEWER"]).json()["indicators"]
        == []
    )
    assert http.get("/api/threats?mode=invalid", headers=tokens["VIEWER"]).status_code == 422
    schema = http.get("/openapi.json").json()["paths"]
    methods = [
        ("/api/threats/lookup", "post"),
        ("/api/threats", "get"),
        ("/api/threats/ip/{ip}", "get"),
        ("/api/threats/providers/status", "get"),
        ("/api/threats/enrich/incidents", "post"),
        ("/api/incidents/{incident_id}/threat-intelligence", "get"),
        ("/api/detections/{finding_id}/threat-intelligence", "get"),
    ]
    for path, method in methods:
        assert schema[path][method]["security"] == [{"BearerAuth": []}]
        assert "schema" in schema[path][method]["responses"]["200"]["content"]["application/json"]
    assert http.get("/docs").status_code == 200


def test_api_provider_failure_response_and_no_key_leak(http, tokens, settings, monkeypatch):
    settings.threat_intelligence_mock_mode = False
    settings.abuseipdb_api_key = SecretStr(KEY)
    settings.virustotal_enabled = settings.otx_enabled = False
    from app.routes import threats

    monkeypatch.setattr(
        threats,
        "service",
        lambda request, session: ThreatIntelligenceService(
            session,
            settings,
            transport=httpx.MockTransport(lambda r: httpx.Response(401, json={"error": KEY})),
        ),
    )
    result = http.post("/api/threats/lookup", json={"ip": IP}, headers=tokens["ADMIN"])
    assert result.status_code == 200 and result.json()["reputation_level"] == "UNKNOWN"
    assert result.json()["providers"][0]["lookup_status"] == "auth_error"
    assert KEY not in result.text


def test_explicit_cached_rescore_then_incident_refresh_preserves_original_until_requested(
    db, settings, http, tokens
):
    seed_detection_rules(db)
    db.add_all([event(seconds=i, source_ip=IP) for i in range(5)])
    db.commit()
    DetectionEngine(db, settings).run(DetectionRunRequest(until_empty=True))
    RiskScoringEngine(db, settings).run(RiskRunRequest(until_empty=True))
    IncidentManagementService(db, settings).run(IncidentRunRequest(until_empty=True))
    finding = db.scalar(select(DetectionFinding))
    assessment = db.scalar(select(RiskAssessment))
    case = db.scalar(select(Incident))
    case.status = "INVESTIGATING"
    analyst = db.scalar(select(User).where(User.username == "analyst"))
    case.assigned_analyst_id = analyst.id
    db.commit()
    old_hash, old_risk, old_id = (
        assessment.input_hash,
        assessment.risk_score,
        assessment.assessment_id,
    )
    case_id, assigned = case.incident_id, case.assigned_analyst_id
    settings.threat_intelligence_mock_mode = False
    settings.abuseipdb_api_key = SecretStr(KEY)
    settings.virustotal_enabled = settings.otx_enabled = False
    service = ThreatIntelligenceService(
        db,
        settings,
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=abuse(score=95))),
    )
    enriched = service.lookup_ip(IP)
    assert enriched.normalized_score == 95
    db.refresh(assessment)
    db.refresh(case)
    assert assessment.input_hash == old_hash and case.risk_score == old_risk
    # Default scoring continues to skip an existing score even after enrichment.
    assert RiskScoringEngine(db, settings).run().findings_evaluated == 0
    response = http.post(
        "/api/risk/run",
        headers=tokens["ANALYST"],
        json={"finding": finding.finding_id, "rescore": True, "reputation_source": "cached"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["assessments_updated"] == 1
    db.refresh(assessment)
    db.refresh(case)
    assert assessment.assessment_id == old_id and assessment.risk_score == old_risk + 10
    assert (
        assessment.breakdown["context"]["reputation_context"][0]["intelligence"]["mode"] == "live"
    )
    assert case.risk_score == old_risk
    result = IncidentManagementService(db, settings).run(IncidentRunRequest(until_empty=True))
    db.refresh(case)
    assert result.incidents_updated == 1 and case.risk_score == assessment.risk_score
    assert (
        case.incident_id == case_id
        and case.status.value == "INVESTIGATING"
        and case.assigned_analyst_id == assigned
    )
    audit = db.scalar(select(AuditLog).where(AuditLog.action == "RISK_SCORING_RUN_TRIGGERED"))
    assert audit.new_value["reputation_source"] == "cached"
