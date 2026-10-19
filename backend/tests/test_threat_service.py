from copy import deepcopy
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import func, select, text

from app.core.errors import ServiceError
from app.incidents.engine import IncidentManagementService
from app.models import (
    AuditLog,
    DetectionFinding,
    Incident,
    IncidentComment,
    IncidentEvidence,
    RiskAssessment,
    SecurityEvent,
    SystemMetric,
    ThreatIntelligence,
    ThreatIntelligenceResult,
    ThreatProviderState,
)
from app.schemas.incident import IncidentRunRequest
from app.services.incident_enrichment import read_related
from app.threat_intelligence.reputation import CachedReputationProvider
from app.threat_intelligence.schemas import EnrichRequest, ThreatQuery
from app.threat_intelligence.service import ThreatIntelligenceService
from scripts import run_threat_enrichment as cli
from tests.test_incident_engine import scored as scored
from tests.test_incident_engine import settings as settings
from tests.test_threat_providers import IP, KEY, abuse, config

MOCK_IP = "198.51.100.73"


def count(db, model):
    return db.scalar(select(func.count()).select_from(model))


def live_service(db, **changes):
    settings = config(threat_intelligence_mock_mode=False, **changes)
    settings.virustotal_enabled = settings.otx_enabled = False
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=abuse(request.url.params["ipAddress"]))

    return ThreatIntelligenceService(db, settings, transport=httpx.MockTransport(handler)), calls


def release_cooldown(db):
    for row in db.scalars(select(ThreatProviderState)):
        row.next_allowed_at = datetime.now(UTC) - timedelta(seconds=1)
        db.flush()
    db.commit()


def expire_bundle(db):
    old = datetime.now(UTC) - timedelta(seconds=1)
    for row in db.scalars(select(ThreatIntelligenceResult)):
        payload = deepcopy(row.payload)
        for provider in payload["providers"]:
            provider["expires_at"] = old.isoformat()
        row.payload = payload
        row.expires_at = old
        db.flush()
    db.commit()


def test_mock_cache_refresh_expiry_and_no_duplicate_identity(db, settings):
    service = ThreatIntelligenceService(db, settings)
    first = service.lookup_ip(MOCK_IP)
    assert not first.cache_hit and first.simulation and first.normalized_score == 92
    identity = db.scalar(select(ThreatIntelligence.id))
    cached = service.lookup_ip(MOCK_IP)
    assert cached.cache_hit and cached.provider_evaluations == 0 and cached.external_requests == 0
    assert cached.checked_at == first.checked_at
    fresh = service.refresh_ip(MOCK_IP)
    assert not fresh.cache_hit and fresh.checked_at > first.checked_at
    assert db.scalar(select(ThreatIntelligence.id)) == identity
    expire_bundle(db)
    assert service.get_cached_intelligence(MOCK_IP).stale
    assert not service.lookup_ip(MOCK_IP).cache_hit
    assert count(db, ThreatIntelligence) == count(db, ThreatIntelligenceResult) == 1
    assert "THREAT_INTELLIGENCE_REFRESHED" in set(db.scalars(select(AuditLog.action)))


def test_real_adapter_cache_forced_refresh_and_provider_throttle(db):
    service, calls = live_service(db)
    first = service.lookup_ip(IP)
    assert first.external_requests == 1 and first.normalized_score == 90 and not first.simulation
    assert service.lookup_ip(IP).cache_hit and len(calls) == 1
    release_cooldown(db)
    assert service.refresh_ip(IP).external_requests == 1 and len(calls) == 2
    blocked = service.lookup_ip("1.1.1.1", force_refresh=True)
    assert blocked.external_requests == 0 and blocked.reputation_level == "UNKNOWN"
    assert blocked.providers[0].lookup_status == "rate_limited"
    assert count(db, ThreatIntelligence) == 2
    release_cooldown(db)
    expire_bundle(db)
    assert service.lookup_ip(IP).external_requests == 1 and len(calls) == 3


def test_mode_separation_keys_do_not_enable_network_in_mock(db, settings):
    settings.abuseipdb_api_key = SecretStr(KEY)
    mock = ThreatIntelligenceService(db, settings)
    assert mock.lookup_ip(IP).simulation
    live, calls = live_service(db)
    assert live.get_cached_intelligence(IP) is None
    assert live.lookup_ip(IP).normalized_score == 90 and len(calls) == 1
    assert mock.get_cached_intelligence(IP).reputation_level == "UNKNOWN"
    assert count(db, ThreatIntelligence) == 1 and count(db, ThreatIntelligenceResult) == 2
    assert mock.get_cached_intelligence(IP, mode="live").simulation is False


def test_live_failure_persistence_unknown_and_retry_after_shared_across_ips(db):
    settings = config(threat_intelligence_mock_mode=False)
    settings.virustotal_enabled = settings.otx_enabled = False
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "900"}, json={"key": KEY})

    service = ThreatIntelligenceService(db, settings, transport=httpx.MockTransport(handler))
    result = service.lookup_ip(IP)
    assert result.normalized_score is result.malicious is None
    stored = db.scalar(select(ThreatIntelligence))
    assert stored.abuse_score is stored.confidence_score is stored.malicious is None
    assert service.lookup_ip(IP).cache_hit
    service.refresh_ip("1.1.1.1")
    assert len(calls) == 1
    state = db.get(ThreatProviderState, "AbuseIPDB")
    assert state.next_allowed_at > datetime.now(UTC) + timedelta(seconds=899)
    assert KEY not in service.get_cached_intelligence(IP).model_dump_json()


def test_credentials_rejected_no_repeated_attempts_until_key_change(db):
    service, calls = live_service(db)
    service.providers[0].transport = httpx.MockTransport(
        lambda r: httpx.Response(401, json={"secret": KEY})
    )
    first = service.lookup_ip(IP)
    assert first.providers[0].lookup_status == "auth_error"
    assert service.lookup_ip("1.1.1.1", force_refresh=True).external_requests == 0
    assert db.get(ThreatProviderState, "AbuseIPDB").next_allowed_at > datetime.now(UTC) + timedelta(
        hours=23
    )
    service.settings.abuseipdb_api_key = SecretStr("changed-test-key")
    # Rebuild adapters after configuration change, as application restart does.
    other = ThreatIntelligenceService(
        db,
        service.settings,
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=abuse())),
    )
    assert other.get_cached_intelligence(IP).configuration_changed
    assert other.lookup_ip(IP).external_requests == 1


def test_valid_provider_cache_survives_other_provider_failure_expiry(db):
    settings = config(threat_intelligence_mock_mode=False)
    settings.otx_enabled = False
    calls = []

    def handler(request):
        calls.append(request.url.host)
        if request.url.host == "api.abuseipdb.com":
            return httpx.Response(200, json=abuse())
        return httpx.Response(503)

    service = ThreatIntelligenceService(db, settings, transport=httpx.MockTransport(handler))
    first = service.lookup_ip(IP)
    assert first.reputation_level == "MALICIOUS" and first.partial
    row = db.scalar(select(ThreatIntelligenceResult))
    payload = deepcopy(row.payload)
    old = datetime.now(UTC) - timedelta(seconds=1)
    for p in payload["providers"]:
        if p["provider"] != "AbuseIPDB":
            p["expires_at"] = old.isoformat()
    row.payload = payload
    row.expires_at = old
    db.commit()
    release_cooldown(db)
    result = service.lookup_ip(IP)
    assert result.provider_cache_hits == 1 and calls.count("api.abuseipdb.com") == 1
    assert calls.count("www.virustotal.com") == 2


def test_cache_queries_filters_compact_payload_and_status(db, settings):
    service = ThreatIntelligenceService(db, settings)
    for ip in [MOCK_IP, "192.0.2.2", "192.168.1.1"]:
        service.lookup_ip(ip)
    page = service.list_cached(ThreatQuery(limit=1))
    assert page.total == 3 and len(page.items) == 1
    assert page.items[0].providers[0].raw_response == {}
    assert (
        service.list_cached(
            ThreatQuery(provider="CyberSentinel Mock", reputation_level="MALICIOUS")
        ).total
        == 1
    )
    assert service.list_cached(ThreatQuery(malicious=False)).total == 1
    assert service.list_cached(ThreatQuery(indicator=MOCK_IP)).items[0].normalized_score == 92
    assert service.list_cached(ThreatQuery(last_checked=datetime.now(UTC))).total == 0
    status = service.provider_status()
    assert status.simulation and sum(p.active for p in status.providers) == 1
    assert KEY not in status.model_dump_json()


def test_incident_multiple_ips_shared_findings_preserves_investigation(db, settings, scored):
    a, _ = scored(70, ip=MOCK_IP)
    b, _ = scored(60, ip="203.0.113.18", rule="CS-009")
    c, _ = scored(55, ip=MOCK_IP, username="another-account")
    IncidentManagementService(db, settings).run(IncidentRunRequest(until_empty=True))
    assert count(db, Incident) == 2
    for row in db.scalars(select(Incident)):
        row.status = "INVESTIGATING"
        db.add(IncidentComment(incident_id=row.id, comment="Retain investigation note"))
    db.commit()
    tables = [
        SecurityEvent,
        DetectionFinding,
        RiskAssessment,
        Incident,
        IncidentEvidence,
        IncidentComment,
    ]
    before = {
        m.__tablename__: db.execute(
            text(f"SELECT to_jsonb(t) FROM {m.__tablename__} t ORDER BY id")
        )
        .scalars()
        .all()
        for m in tables
    }
    audit_before = {
        row["id"]: row for row in db.scalars(text("SELECT to_jsonb(t) FROM audit_logs t"))
    }
    service = ThreatIntelligenceService(db, settings)
    result = service.enrich_pending(EnrichRequest(limit=10))
    assert result.unique_indicators == 2 and result.provider_evaluations == 2
    assert result.incidents_enriched == 2 and result.external_lookups == 0
    assert service.enrich_pending(EnrichRequest(limit=10)).cache_hits == 2
    case = db.scalar(select(Incident).where(Incident.username == "employee014"))
    info = read_related(service, case.incident_id, "incident")
    assert len(info.indicators) == 2 and not info.missing_indicators
    assert read_related(service, a.finding_id, "finding").indicators[0].simulation
    for model in tables:
        assert (
            before[model.__tablename__]
            == db.execute(text(f"SELECT to_jsonb(t) FROM {model.__tablename__} t ORDER BY id"))
            .scalars()
            .all()
        )
    assert "INCIDENT_ENRICHMENT_TRIGGERED" in set(db.scalars(select(AuditLog.action)))
    audit_after = {
        row["id"]: row for row in db.scalars(text("SELECT to_jsonb(t) FROM audit_logs t"))
    }
    assert all(audit_after[key] == value for key, value in audit_before.items())


def test_boundaries_missing_objects_and_readonly_get(db, settings, scored, monkeypatch):
    service = ThreatIntelligenceService(db, settings)
    assert service.get_cached_intelligence(MOCK_IP) is None and count(db, SystemMetric) == 0
    with pytest.raises(ServiceError, match="not found"):
        read_related(service, "missing", "incident")
    with pytest.raises(ServiceError, match="maximum"):
        service.enrich_pending(EnrichRequest(limit=51))
    finding, _ = scored(60, ip=MOCK_IP)
    IncidentManagementService(db, settings).run()
    before = count(db, ThreatIntelligence)
    info = read_related(service, finding.finding_id, "finding")
    assert info.missing_indicators == [MOCK_IP] and count(db, ThreatIntelligence) == before
    assert service.enrich_finding(finding.finding_id).indicators[0].normalized_score == 92
    settings.threat_intelligence_max_indicators = 1
    row = db.get(SecurityEvent, finding.primary_event_id)
    row.destination_ip = "192.0.2.44"
    db.commit()
    with pytest.raises(ServiceError, match="Too many"):
        service.enrich_pending(EnrichRequest(limit=1))


def test_cached_reputation_is_read_only_fresh_and_explicit(db, settings):
    service = ThreatIntelligenceService(db, settings)
    assert CachedReputationProvider(db, settings).lookup_ip(MOCK_IP) is None
    service.lookup_ip(MOCK_IP)
    value = CachedReputationProvider(db, settings).lookup_ip(MOCK_IP)
    assert value.score == 92 and value.synthetic and value.context["mode"] == "mock"
    assert count(db, ThreatIntelligence) == 1
    expire_bundle(db)
    assert CachedReputationProvider(db, settings).lookup_ip(MOCK_IP) is None


def test_cli_mock_options_and_production_guard(db, settings, monkeypatch, capsys):
    from contextlib import nullcontext
    from unittest.mock import MagicMock

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "build_engine", lambda s: MagicMock())
    monkeypatch.setattr(cli, "Session", lambda e: nullcontext(db))
    assert cli.main(["--ip", MOCK_IP, "--mock"]) == 0
    assert "SIMULATED DEMO DATA" in capsys.readouterr().out
    assert cli.main(["--all", "--limit", "10", "--mock"]) == 0
    settings.app_env = "production"
    assert cli.main(["--ip", MOCK_IP]) == 1
    with pytest.raises(SystemExit):
        cli.main(["--ip", "invalid"])


def test_lookup_persistence_failure_rolls_back_partial_cache(db, settings, monkeypatch):
    from app.threat_intelligence import cache

    service = ThreatIntelligenceService(db, settings)
    original = cache.persist

    def fail_after_write(*args):
        original(*args)
        raise RuntimeError("simulated write failure")

    monkeypatch.setattr(cache, "persist", fail_after_write)
    with pytest.raises(ServiceError, match="persistence unavailable"):
        service.lookup_ip(MOCK_IP)
    assert count(db, ThreatIntelligence) == count(db, ThreatIntelligenceResult) == 0
    assert count(db, AuditLog) == count(db, SystemMetric) == 0


def test_bulk_budget_is_resumable_without_inventing_results(db, settings, scored, monkeypatch):
    from app.services import incident_enrichment

    scored(70, ip=MOCK_IP)
    IncidentManagementService(db, settings).run()
    service = ThreatIntelligenceService(db, settings)
    clock = iter([0, 61, 62])
    monkeypatch.setattr(incident_enrichment, "perf_counter", lambda: next(clock))
    result = service.enrich_pending(EnrichRequest(limit=1))
    assert not result.complete and result.next_offset == 0
    assert result.unique_indicators == 1 and result.indicators_evaluated == 0
    assert result.incidents_enriched == result.external_lookups == 0
    assert count(db, ThreatIntelligenceResult) == 0
