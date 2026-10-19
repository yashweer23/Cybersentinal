"""Known controlled populations, join cardinality, half-open ranges and RBAC."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import event as sql_event
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError

from app.core.enums import IncidentStatus, SeverityLevel
from app.models import (
    Incident,
    IncidentEvidence,
    IncidentFinding,
    RiskAssessment,
    SecurityEvent,
    ThreatIntelligenceResult,
    User,
)
from app.schemas import dashboard as schemas
from app.services.analytics_service import PRESETS, resolve_scope
from app.services.dashboard_service import DashboardService
from app.threat_intelligence.service import ThreatIntelligenceService
from tests.test_event_ingestion import http as http
from tests.test_event_ingestion import settings as settings
from tests.test_event_ingestion import tokens as tokens
from tests.test_incident_engine import T, set_score
from tests.test_incident_engine import scored as scored

END = T + timedelta(hours=1)
PARAMS = {"start": T.isoformat(), "end": END.isoformat()}
QUERY = schemas.TimeRangeQuery(**PARAMS)
ENDPOINTS = {
    "overview": "overview",
    "events/timeline": "timeline",
    "events/types": "event_types",
    "events/recent": "recent_events",
    "events/updates": "updates",
    "incidents/severity": "severity",
    "incidents/status": "status",
    "incidents/recent": "recent_incidents",
    "threats/top-ips": "top_ips",
    "threats/summary": "threats",
    "users/targeted": "targeted_users",
    "detection/rules": "rules",
    "risk/distribution": "risk_distribution",
    "activity/summary": "activity",
    "system/health": "health",
}


@pytest.fixture
def population(db, scored):
    findings = [
        scored(score, ip=ip, username=user, minutes=minute, rule=rule)[0]
        for score, ip, user, minute, rule in [
            (90, "198.51.100.73", "employee014", 1, "CS-001"),
            (80, "198.51.100.73", "employee014", 2, "CS-009"),
            (70, "198.51.100.73", "employee014", 3, "CS-002"),
            (65, "192.0.2.44", "employee002", 4, "CS-001"),
            (40, "203.0.113.8", "employee003", 5, "CS-001"),
        ]
    ]
    for finding, kind, status in [
        (findings[3], "ACCESS_DENIED", "denied"),
        (findings[4], "LOGIN_SUCCESS", "success"),
    ]:
        row = db.get(SecurityEvent, finding.primary_event_id)
        row.event_type, row.status = kind, status
        db.flush()
    cases = []
    for index, (score, severity, status, finding) in enumerate(
        [
            (90, "CRITICAL", "OPEN", findings[0]),
            (65, "HIGH", "INVESTIGATING", findings[3]),
            (40, "MEDIUM", "FALSE_POSITIVE", findings[4]),
            (10, "LOW", "RESOLVED", None),
        ]
    ):
        case = Incident(
            incident_id=f"INC-CONTROLLED-{index}",
            title=f"Controlled case {index}",
            description="Controlled observed behavior",
            detection_rule_id=findings[0].detection_rule_id,
            risk_score=score,
            severity=severity,
            confidence=90,
            status=status,
            source_ip=finding.source_ip if finding else None,
            username=finding.username if finding else None,
            detected_at=T + timedelta(minutes=20 + index),
        )
        db.add(case)
        db.flush()
        cases.append(case)
    for index, finding in enumerate(findings):
        case = cases[0 if index < 3 else index - 2]
        db.add(
            IncidentFinding(
                incident_id=case.id,
                detection_finding_id=finding.id,
                relationship_reason="Controlled common account and source",
                correlation_data={},
            )
        )
        db.add(
            IncidentEvidence(
                incident_id=case.id,
                security_event_id=finding.primary_event_id,
                detection_finding_id=finding.id,
                evidence_type="EVENT_REFERENCE",
                description="Reference",
                evidence_data={},
            )
        )
        db.flush()
    # Historical/future algorithm versions must not inflate counts or replace current v1.
    historical = RiskAssessment(
        assessment_id="RISK-CONTROLLED-HISTORY",
        detection_finding_id=findings[0].id,
        score_version="v0",
        config_hash="0" * 64,
    )
    set_score(historical, 99)
    db.add(historical)
    for timestamp, kind, user, done in [
        (T, "LOGIN_SUCCESS", "normal-user", False),
        (T + timedelta(minutes=6), "API_REQUEST", "normal-user", True),
        (T + timedelta(minutes=7), "SENSITIVE_RECORD_ACCESS", "normal-user", True),
        (T + timedelta(minutes=8), "PRIVILEGE_CHANGE", "normal-user", True),
        (T + timedelta(minutes=9), "ACCESS_DENIED", "employee014", True),
        (T - timedelta(microseconds=1), "LOGIN_FAILED", "outside", False),
        (END, "LOGIN_FAILED", "outside", False),
    ]:
        db.add(
            SecurityEvent(
                event_id="EVT-" + uuid4().hex,
                timestamp=timestamp,
                source_ip="192.0.2.101",
                username=user,
                event_type=kind,
                status="observed",
                processed=done,
                raw_data={"private_payload": "MUST_NOT_APPEAR_IN_DASHBOARD"},
            )
        )
        db.flush()
    db.commit()
    return findings, cases


def test_controlled_overview_distributions_and_consistency(db, settings, population):
    service = DashboardService(db, settings)
    result = service.execute("overview", QUERY)
    assert result.model_dump(exclude={"scope"}) == {
        "total_events": 12,
        "events_in_range": 10,
        "total_incidents": 4,
        "active_incidents": 2,
        "critical_incidents": 1,
        "high_risk_incidents": 2,
        "total_findings": 5,
        "suspicious_ips": 3,
        "average_risk_score": 51.25,
        "unprocessed_events": 3,
        "latest_event_timestamp": END,
    }
    timeline = service.execute("timeline", QUERY)
    event_types = service.execute("event_types", QUERY)
    severity = service.execute("severity", QUERY)
    status = service.execute("status", QUERY)
    risk = service.execute("risk_distribution", QUERY)
    assert timeline.total == event_types.total == result.events_in_range
    assert sum(p.total for p in timeline.data) == 10
    assert severity.total == status.total == risk.total == result.total_incidents
    assert {p.severity: p.count for p in severity.distribution} == dict.fromkeys(SeverityLevel, 1)
    assert {p.status: p.count for p in status.distribution} == dict.fromkeys(IncidentStatus, 1)
    assert risk.average_risk_score == result.average_risk_score
    assert [(p.count, p.event_type) for p in event_types.distribution] == sorted(
        [(p.count, p.event_type) for p in event_types.distribution], key=lambda p: (-p[0], p[1])
    )
    activity = service.execute("activity", QUERY)
    assert activity.model_dump(exclude={"scope"}) == {
        "successful_logins": 2,
        "failed_logins": 3,
        "access_denials": 2,
        "api_requests": 1,
        "sensitive_record_accesses": 1,
        "privilege_changes": 1,
    }


def test_distinct_three_findings_one_case_and_current_risk(db, settings, population):
    service = DashboardService(db, settings)
    ips = service.execute("top_ips", schemas.TopIPQuery(**PARAMS))
    first = ips.items[0]
    assert (first.ip, first.incident_count, first.finding_count) == ("198.51.100.73", 1, 3)
    assert first.highest_risk_score == first.highest_finding_risk_score == 90
    assert first.intelligence_status == "missing" and first.reputation_level == "UNKNOWN"
    assert len(ips.items) == 3
    users = service.execute("targeted_users", schemas.RankedQuery(**PARAMS))
    assert users.items[0].model_dump() == {
        "username": "employee014",
        "failed_logins": 3,
        "access_denials": 1,
        "finding_count": 3,
        "incident_count": 1,
    }
    assert "outside" not in {u.username for u in users.items}
    assert len(service.execute("top_ips", schemas.TopIPQuery(**PARAMS, limit=1)).items) == 1


def test_linked_ip_and_account_associations_include_all_case_sources(db, settings, population):
    findings, cases = population
    # Two different source findings in one case; count the case once under each associated IP.
    findings[1].source_ip = "203.0.113.18"
    findings[1].username = "second-account"
    db.commit()
    result = DashboardService(db, settings).execute("top_ips", schemas.TopIPQuery(**PARAMS))
    values = {p.ip: p for p in result.items}
    assert values["198.51.100.73"].incident_count == values["203.0.113.18"].incident_count == 1
    assert values["203.0.113.18"].highest_risk_score == 90
    users = DashboardService(db, settings).execute("targeted_users", schemas.RankedQuery(**PARAMS))
    assert next(p for p in users.items if p.username == "second-account").incident_count == 1


def test_timeline_timezone_boundaries_and_zero_fill(db, settings, population):
    db.execute(text("SET LOCAL TIME ZONE 'Asia/Kolkata'"))
    query = schemas.TimeRangeQuery(
        start="2026-09-23T17:30:00+05:30", end="2026-09-23T18:30:00+05:30"
    )
    timeline = DashboardService(db, settings).execute("timeline", query)
    assert timeline.scope.start == T and timeline.scope.end == END
    assert timeline.interval == "minute" and len(timeline.data) == 60
    assert timeline.data[0].timestamp == T and timeline.data[0].total == 1
    assert timeline.data[-1].total == 0
    assert sum(p.login_failed for p in timeline.data) == 3
    assert [p.timestamp for p in timeline.data] == sorted(p.timestamp for p in timeline.data)
    assert all(p.timestamp.utcoffset() == timedelta(0) for p in timeline.data)
    partial = schemas.TimeRangeQuery(
        start=T + timedelta(seconds=30), end=T + timedelta(minutes=1, seconds=30)
    )
    points = DashboardService(db, settings).execute("timeline", partial)
    assert [p.total for p in points.data] == [0, 1]


@pytest.mark.parametrize(
    "hours,interval,seconds",
    [
        (1, "minute", 60),
        (6, "15_minutes", 900),
        (24, "hour", 3600),
        (168, "day", 86400),
        (720, "day", 86400),
    ],
)
def test_timeline_bucket_sizes_preserve_counts(db, settings, population, hours, interval, seconds):
    start = T.replace(hour=0)
    # Place the cohort inside each range; use midnight only for daily buckets.
    start = start if hours > 24 else T
    query = schemas.TimeRangeQuery(start=start, end=start + timedelta(hours=hours))
    service = DashboardService(db, settings)
    result = service.execute("timeline", query)
    assert result.interval == interval and result.bucket_seconds == seconds
    assert len(result.data) == hours * 3600 // seconds
    assert sum(p.total for p in result.data) == service.execute("overview", query).events_in_range
    assert all(
        b.timestamp - a.timestamp == timedelta(seconds=seconds)
        for a, b in zip(result.data, result.data[1:])
    )


def test_rule_stats_include_disabled_and_zero_match_rules(db, settings, population):
    population[0][0].rule.enabled = False
    db.commit()
    result = DashboardService(db, settings).execute("rules", QUERY)
    assert len(result.items) == 10 and sum(p.finding_count for p in result.items) == 5
    assert result.items[0].rule_id == "CS-001" and not result.items[0].enabled
    assert result.items[0].finding_count == 3
    assert result.items[-1].finding_count == 0 and result.items[-1].latest_finding_timestamp is None


def test_recent_summaries_order_limits_and_safe_analyst(db, settings, population, tokens):
    findings, cases = population
    cases[0].assigned_analyst_id = db.scalar(select(User.id).where(User.username == "analyst"))
    db.commit()
    service = DashboardService(db, settings)
    query = schemas.RecentQuery(**PARAMS, limit=3)
    events = service.execute("recent_events", query)
    expected = list(
        db.scalars(
            select(SecurityEvent.id)
            .where(SecurityEvent.timestamp >= T, SecurityEvent.timestamp < END)
            .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
            .limit(3)
        )
    )
    assert [p.id for p in events.items] == expected
    incidents = service.execute("recent_incidents", schemas.RecentQuery(**PARAMS, limit=4))
    assert [p.incident_id for p in incidents.items] == [c.incident_id for c in reversed(cases)]
    assert incidents.items[-1].assigned_analyst.username == "analyst"
    for output in [events, incidents]:
        assert "raw_data" not in output.model_dump_json()
        assert "hashed_password" not in output.model_dump_json()
        assert "MUST_NOT_APPEAR" not in output.model_dump_json()


@pytest.mark.parametrize("preset,seconds", list(PRESETS.items()))
def test_presets_resolve_at_actual_clock(settings, preset, seconds):
    now = datetime.now(UTC)
    scope = resolve_scope(schemas.TimeRangeQuery(range=preset), settings, now=now)
    assert scope.end == scope.as_of == now
    assert (scope.end - scope.start).total_seconds() == seconds


@pytest.mark.parametrize(
    "values",
    [
        {"range": "2h"},
        {"start": T.isoformat()},
        {"end": END.isoformat()},
        {"range": "24h", **PARAMS},
        {"start": END.isoformat(), "end": T.isoformat()},
        {"start": T.isoformat(), "end": T.isoformat()},
        {"start": "2026-09-23T12:00:00", "end": END.isoformat()},
        {"start": "1234567890", "end": END.isoformat()},
    ],
)
def test_invalid_time_models(values):
    with pytest.raises(ValidationError):
        schemas.TimeRangeQuery(**values)


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST", "VIEWER"])
def test_all_dashboard_routes_authenticated_and_empty_safe(http, tokens, role):
    for suffix in ENDPOINTS:
        path = "/api/dashboard/" + suffix
        assert http.get(path).status_code == 401
        response = http.get(path, headers=tokens[role])
        assert response.status_code == 200, (path, response.text)
        assert response.headers["cache-control"] == "no-store"
        assert "hashed_password" not in response.text and "api_key" not in response.text
    overview = http.get("/api/dashboard/overview", headers=tokens[role]).json()
    assert overview["total_events"] == overview["total_incidents"] == 0
    assert overview["average_risk_score"] is overview["latest_event_timestamp"] is None
    timeline = http.get("/api/dashboard/events/timeline", headers=tokens[role]).json()
    assert timeline["total"] == 0 and all(p["total"] == 0 for p in timeline["data"])
    health = http.get("/api/dashboard/system/health", headers=tokens[role]).json()
    assert health["detection_engine"]["status"] == "available_on_demand"
    assert health["ai_analyst"]["status"] == "FALLBACK"


@pytest.mark.parametrize(
    "suffix,params",
    [
        ("overview", {"range": "all"}),
        ("overview", {"start": T.isoformat()}),
        ("overview", {"start": T.isoformat(), "end": (T + timedelta(days=91)).isoformat()}),
        ("overview", {"start": "2026-09-23T12:00:00", "end": END.isoformat()}),
        ("overview", {"start": T.isoformat(), "end": T.isoformat()}),
        ("overview", {"range": "1h", **PARAMS}),
        ("events/recent", {"limit": 101}),
        ("events/recent", {"limit": 0}),
        ("threats/top-ips", {"limit": 21}),
        ("threats/summary", {"mode": "both"}),
        ("events/updates", {"after_id": -1}),
        ("events/updates", {"after_id": "nope"}),
        ("events/updates", {"after_id": 2**63}),
        ("events/updates", {"after_id": 999}),
    ],
)
def test_invalid_api_ranges_limits_and_cursor(http, tokens, suffix, params):
    response = http.get("/api/dashboard/" + suffix, params=params, headers=tokens["VIEWER"])
    assert response.status_code == 422, response.text


def test_readonly_all_endpoints_and_swagger(db, settings, http, tokens, population, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Dashboard triggered a write/processing/lookup service")

    for target in [
        "app.threat_intelligence.service.ThreatIntelligenceService.lookup_ip",
        "app.detection.engine.DetectionEngine.run",
        "app.risk.engine.RiskScoringEngine.run",
        "app.incidents.engine.IncidentManagementService.run",
        "app.services.event_ingestion.EventIngestionService.ingest_batch",
    ]:
        monkeypatch.setattr(target, forbidden)
    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    connection = db.connection()
    sql_event.listen(connection, "before_cursor_execute", record)
    try:
        for suffix in ENDPOINTS:
            params = {} if suffix in {"events/updates", "system/health"} else PARAMS
            response = http.get("/api/dashboard/" + suffix, params=params, headers=tokens["VIEWER"])
            assert response.status_code == 200, (suffix, response.text)
    finally:
        sql_event.remove(connection, "before_cursor_execute", record)
    assert statements and all(s.lstrip().upper().startswith(("SELECT", "WITH")) for s in statements)
    schema = http.get("/openapi.json").json()
    for suffix in ENDPOINTS:
        route = schema["paths"]["/api/dashboard/" + suffix]
        assert set(route) == {"get"}
        assert route["get"]["security"] == [{"BearerAuth": []}]
        assert "schema" in route["get"]["responses"]["200"]["content"]["application/json"]
    assert http.get("/docs").status_code == 200


def test_cache_only_summary_modes_unknown_expired_and_top_ip(db, settings, population):
    service = ThreatIntelligenceService(db, settings)
    service.lookup_ip("198.51.100.73")
    service.lookup_ip("192.0.2.44")
    service.lookup_ip("192.0.2.9")
    service.lookup_ip("192.168.1.1")
    service.lookup_ip("198.51.100.73")
    now = datetime.now(UTC)
    expired = db.scalar(
        select(ThreatIntelligenceResult).where(
            ThreatIntelligenceResult.payload["indicator"].astext == "192.0.2.44"
        )
    )
    expired.expires_at = now - timedelta(seconds=1)
    db.commit()
    query = schemas.ThreatScopeQuery(start=T - timedelta(days=1), end=now + timedelta(seconds=1))
    dashboard = DashboardService(db, settings)
    result = dashboard.execute("threats", query)
    assert result.simulation and result.mode == "mock"
    assert (
        result.cached_indicators,
        result.malicious_indicators,
        result.no_adverse_signal_indicators,
        result.unknown_indicators,
    ) == (4, 1, 1, 2)
    assert result.expired_indicators == result.cache_hits == 1
    assert (
        sum(
            [
                result.malicious_indicators,
                result.suspicious_indicators,
                result.no_adverse_signal_indicators,
                result.unknown_indicators,
            ]
        )
        == result.cached_indicators
    )
    live = dashboard.execute("threats", query.model_copy(update={"mode": "live"}))
    assert live.cached_indicators == 0 and not live.simulation
    ips = dashboard.execute("top_ips", schemas.TopIPQuery(start=query.start, end=query.end))
    states = {p.ip: (p.reputation_level, p.intelligence_status) for p in ips.items}
    assert states["198.51.100.73"] == ("MALICIOUS", "fresh")
    assert states["192.0.2.44"] == ("UNKNOWN", "expired")
    settings.threat_intelligence_enabled = False
    changed = dashboard.execute("threats", query)
    assert changed.incompatible_indicators == changed.unknown_indicators == 4


def test_errors_and_slow_queries_are_logged_without_payloads(http, tokens, monkeypatch, caplog):
    def fail(*args):
        raise OperationalError("query", {}, Exception("NEVER-EXPOSE-THIS-SECRET"))

    monkeypatch.setattr("app.repositories.dashboard_repository.DashboardRepository.overview", fail)
    clock = iter([100.0, 101.0])
    monkeypatch.setattr("app.services.dashboard_service.perf_counter", lambda: next(clock))
    response = http.get("/api/dashboard/overview", headers=tokens["VIEWER"])
    assert response.status_code == 503 and "NEVER-EXPOSE" not in response.text
    assert "Dashboard query failed operation=overview" in caplog.text
    assert "Slow dashboard query operation=overview duration_ms=1000.000" in caplog.text
    assert "NEVER-EXPOSE" not in caplog.text


def test_event_previews_include_nullable_destination(db, settings, population):
    event = db.scalars(select(SecurityEvent).where(SecurityEvent.timestamp == T)).first()
    event.destination_ip = "2001:db8::12"
    db.flush()
    service = DashboardService(db, settings)
    recent = service.execute("recent_events", schemas.RecentQuery(**PARAMS, limit=100))
    preview = next(row for row in recent.items if row.id == event.id)
    assert preview.destination_ip == "2001:db8::12"
    assert any(row.destination_ip is None for row in recent.items)
    updates = service.execute("updates", schemas.UpdatesQuery(after_id=0, limit=100))
    assert next(row for row in updates.items if row.id == event.id).destination_ip == "2001:db8::12"
