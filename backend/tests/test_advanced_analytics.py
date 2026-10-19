"""Controlled SQL totals, timing definitions, join cardinality, permissions and exports."""

import csv
import io
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event as sql_event
from sqlalchemy import select, text

from app.models import (
    AuditLog,
    Incident,
    IncidentComment,
    IncidentEvidence,
    IncidentFinding,
    RiskAssessment,
    SecurityEvent,
    User,
)
from app.schemas import analytics as schema
from app.services.reporting_service import csv_cell
from app.services.security_analytics import SecurityAnalyticsService
from tests.test_event_ingestion import http as http
from tests.test_event_ingestion import settings as settings
from tests.test_event_ingestion import tokens as tokens
from tests.test_incident_engine import T, set_score
from tests.test_incident_engine import scored as scored

PARAMS = {"start": T.isoformat(), "end": (T + timedelta(days=1)).isoformat()}
QUERY = schema.AnalyticsQuery(**PARAMS)
ENDPOINTS = [
    "overview",
    "events/trend",
    "incidents/trend",
    "detections/rules",
    "risk/trend",
    "risk/histogram",
    "entities/high-risk",
    "incidents/backlog",
    "incidents/status-history",
    "threat-intelligence",
    "categories",
    "geography",
    "ai/usage",
    "detections/evaluation",
]


def make_case(db, finding, number=0, **fields):
    values = dict(
        incident_id=f"INC-ANALYTICS-{number}",
        title="Controlled case",
        description="Evidence",
        detection_rule_id=finding.detection_rule_id,
        risk_score=80,
        severity="CRITICAL",
        confidence=90,
        status="OPEN",
        source_ip=finding.source_ip,
        username=finding.username,
        created_at=T,
        detected_at=T,
        first_seen=T,
        last_seen=T,
    )
    values.update(fields)
    row = Incident(**values)
    db.add(row)
    db.flush()
    return row


def audit(db, case, minutes, status, previous="OPEN", action="INCIDENT_STATUS_CHANGED", **extra):
    data = {"status": status, **extra}
    db.add(
        AuditLog(
            entity_type="incident",
            entity_id=str(case.id),
            action=action,
            timestamp=T + timedelta(minutes=minutes),
            old_value={"status": previous},
            new_value=data,
        )
    )


@pytest.fixture
def population(db, scored, tokens):
    findings = [scored(score, minutes=index)[0] for index, score in enumerate([70, 80, 90])]
    admin = db.scalar(select(User).where(User.username == "admin"))
    cases = [
        make_case(db, findings[0], 0, assigned_analyst_id=admin.id),
        make_case(
            db,
            findings[0],
            1,
            status="RESOLVED",
            risk_score=60,
            severity="HIGH",
            resolved_at=T + timedelta(hours=2),
            assigned_analyst_id=admin.id,
        ),
        make_case(
            db,
            findings[0],
            2,
            status="FALSE_POSITIVE",
            risk_score=30,
            severity="MEDIUM",
            resolved_at=T + timedelta(hours=1),
        ),
        make_case(db, findings[0], 3, status="INVESTIGATING", risk_score=10, severity="LOW"),
    ]
    for finding in findings:
        db.add(
            IncidentFinding(
                incident_id=cases[0].id,
                detection_finding_id=finding.id,
                relationship_reason="Controlled association",
                correlation_data={},
            )
        )
        db.add(
            IncidentEvidence(
                incident_id=cases[0].id,
                security_event_id=finding.primary_event_id,
                detection_finding_id=finding.id,
                evidence_type="EVENT_REFERENCE",
                description="Reference",
                evidence_data={},
            )
        )
        event = db.get(SecurityEvent, finding.primary_event_id)
        event.service = "authentication"
        event.country = "India"
    audit(db, cases[1], 10, "INVESTIGATING")
    audit(db, cases[1], 20, "INVESTIGATING")
    audit(db, cases[1], 120, "RESOLVED", "INVESTIGATING")
    audit(db, cases[1], 120, "RESOLVED", "INVESTIGATING", action="INCIDENT_RESOLVED")
    audit(db, cases[2], 60, "FALSE_POSITIVE")
    audit(db, cases[3], 30, "INVESTIGATING")
    # Assignment alone is not an acknowledgement under this metric's chosen definition.
    audit(db, cases[0], 5, "OPEN", action="INCIDENT_ASSIGNED")
    db.commit()
    return findings, cases


def service(db, settings):
    return SecurityAnalyticsService(db, settings)


def test_known_totals_mtta_mttr_and_false_positive_rate(db, settings, population):
    result = service(db, settings).execute("overview", QUERY)
    assert (result.incidents_created, result.detection_findings, result.total_events) == (4, 3, 3)
    assert result.average_risk_score == 45 and result.median_risk_score == 45
    assert result.resolution_rate == 25 and result.false_positive_rate == 50
    assert result.acknowledged_incidents == 2 and result.mean_time_to_acknowledge_seconds == 1200
    assert result.measured_resolutions == 1 and result.mean_time_to_resolve_seconds == 7200
    assert result.p90_resolution_seconds == 7200
    assert result.unique_suspicious_ips == result.unique_targeted_users == 1


def test_mandatory_one_incident_three_findings_two_assessments_each(db, settings, scored, tokens):
    findings = []
    for i, score in enumerate([50, 70, 90]):
        finding, current = scored(score, minutes=i)
        findings.append(finding)
        historic = RiskAssessment(
            assessment_id="RISK-HIST-" + uuid4().hex,
            detection_finding_id=finding.id,
            score_version="v0",
            config_hash="0" * 64,
        )
        set_score(historic, 100)
        db.add(historic)
    row = make_case(db, findings[0])
    author = db.scalar(select(User).where(User.username == "analyst"))
    for index in range(4):
        db.add(IncidentComment(incident_id=row.id, user_id=author.id, comment=f"Note {index}"))
    for finding in findings:
        db.add(
            IncidentFinding(
                incident_id=row.id,
                detection_finding_id=finding.id,
                relationship_reason="One case",
                correlation_data={},
            )
        )
    db.commit()
    overview = service(db, settings).execute("overview", QUERY)
    assert overview.incidents_created == 1 and overview.detection_findings == 3
    rule = service(db, settings).execute("rules", QUERY).items[0]
    assert rule.incidents == 1 and rule.findings == 3 and rule.average_risk == 70
    histogram = service(db, settings).execute(
        "histogram", schema.RiskQuery(**PARAMS, population="findings")
    )
    assert histogram.total == 3 and sum(b.count for b in histogram.data) == 3
    top = (
        service(db, settings)
        .execute("entities", schema.EntityQuery(**PARAMS, kind="source_ip"))
        .items[0]
    )
    assert top.incident_count == 1 and top.finding_count == 3 and top.highest_risk == 90


def test_rule_metrics_categories_and_entity_deduplication(db, settings, population):
    svc = service(db, settings)
    rule = svc.execute("rules", QUERY).items[0]
    assert (rule.findings, rule.incidents, rule.critical_incidents, rule.false_positives) == (
        3,
        4,
        1,
        1,
    )
    assert rule.false_positive_rate == 50 and rule.average_risk == 80
    assert len(svc.execute("rules", QUERY).items) == 10
    for kind in ["username", "source_ip", "service", "device"]:
        data = svc.execute("entities", schema.EntityQuery(**PARAMS, kind=kind))
        assert data.items[0].finding_count == 3
        assert data.items[0].incident_count == (1 if kind in ["service", "device"] else 4)
        assert data.items[0].suspicious_event_count == 3
    recurring = svc.execute(
        "entities", schema.EntityQuery(**PARAMS, kind="source_ip", recurring_only=True)
    )
    assert len(recurring.items) == 1
    cats = svc.execute("categories", QUERY)
    assert next(c for c in cats.items if c.category == "Authentication Abuse").incidents == 4
    geo = svc.execute("geography", QUERY)
    assert (
        geo.items[0].country == "India"
        and geo.items[0].finding_count == 3
        and geo.items[0].incident_count == 1
    )


def test_time_boundaries_timezone_and_event_filters(db, settings, population):
    for time in [T - timedelta(microseconds=1), T + timedelta(days=1)]:
        db.add(
            SecurityEvent(
                event_id="EVT-" + uuid4().hex,
                timestamp=time,
                event_type="LOGIN_FAILED",
                status="failed",
                source_ip="198.51.100.44",
                raw_data={},
            )
        )
    db.commit()
    db.execute(text("SET LOCAL TIME ZONE 'Asia/Kolkata'"))
    query = schema.EventTrendQuery(
        start="2026-09-23T17:30:00+05:30", end="2026-09-24T17:30:00+05:30", service="authentication"
    )
    result = service(db, settings).execute("events", query)
    assert result.total == 3 and result.scope.start == T and len(result.data) == 24
    assert (
        service(db, settings)
        .execute("events", query.model_copy(update={"event_type": "API_REQUEST"}))
        .total
        == 0
    )
    assert (
        service(db, settings)
        .execute("events", query.model_copy(update={"source_ip": "203.0.113.4"}))
        .total
        == 0
    )


def test_current_risk_histogram_percentiles_and_resolution_transition_counts(
    db, settings, population
):
    svc = service(db, settings)
    trend = svc.execute("risk_trend", schema.RiskQuery(**PARAMS))
    point = next(p for p in trend.data if p.count)
    assert (
        point.count,
        point.average_risk,
        point.median_risk,
        point.maximum_risk,
        point.critical_count,
    ) == (4, 45, 45, 80, 1)
    hist = svc.execute("histogram", schema.RiskQuery(**PARAMS))
    assert hist.total == 4
    changes = svc.execute("incidents", QUERY)
    assert sum(p.created for p in changes.data) == 4
    assert sum(p.resolved for p in changes.data) == 1  # auxiliary audit is ignored
    assert sum(p.false_positive for p in changes.data) == 1


def test_backlog_and_workload_are_current_creation_cohorts(db, settings, population):
    svc = service(db, settings)
    backlog = svc.execute("backlog", QUERY)
    assert backlog.open_count == backlog.investigating_count == backlog.critical_unresolved == 1
    assert sum(b.count for b in backlog.age_distribution) == 2
    assert backlog.oldest.incident_id in {"INC-ANALYTICS-0", "INC-ANALYTICS-3"}
    workload = svc.execute("workload", QUERY)
    admin = next(p for p in workload.items if p.username == "admin")
    assert (admin.assigned, admin.open, admin.resolved, admin.average_resolution_seconds) == (
        2,
        1,
        1,
        7200,
    )
    assert workload.unassigned == 2 and workload.assigned_to_ineligible == 0
    assert [p.username for p in workload.items] == ["admin", "analyst"]


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST", "VIEWER"])
def test_empty_apis_authentication_rbac_and_swagger(http, tokens, role):
    for endpoint in ENDPOINTS:
        path = "/api/analytics/" + endpoint
        assert http.get(path).status_code == 401
        response = http.get(path, headers=tokens[role], params={"range": "90d"})
        assert response.status_code == 200, (path, response.text)
        assert response.headers["cache-control"] == "no-store"
        assert not any(k in response.text for k in ["hashed_password", "api_key", "raw_data"])
    response = http.get("/api/analytics/analysts/workload", headers=tokens[role])
    assert response.status_code == (200 if role == "ADMIN" else 403)
    overview = http.get("/api/analytics/overview", headers=tokens[role]).json()
    assert overview["incidents_created"] == 0
    assert overview["mean_time_to_resolve_seconds"] is overview["false_positive_rate"] is None
    paths = http.get("/openapi.json").json()["paths"]
    assert all("/api/analytics/" + e in paths for e in ENDPOINTS)


@pytest.mark.parametrize(
    "params",
    [
        {"range": "all"},
        {"start": T.isoformat()},
        {"start": T.isoformat(), "end": T.isoformat()},
        {"start": "2026-09-23T12:00:00", "end": PARAMS["end"]},
        {"range": "7d", **PARAMS},
        {"start": T.isoformat(), "end": (T + timedelta(days=91)).isoformat()},
    ],
)
def test_invalid_ranges(http, tokens, params):
    assert (
        http.get("/api/analytics/overview", headers=tokens["VIEWER"], params=params).status_code
        == 422
    )


def test_invalid_event_ip_and_export_bounds(http, tokens):
    assert (
        http.get(
            "/api/analytics/events/trend", headers=tokens["VIEWER"], params={"source_ip": "bad"}
        ).status_code
        == 422
    )
    for extra in [{"limit": 5001}, {"limit": 0}, {"offset": -1}, {"format": "pdf"}]:
        assert (
            http.get("/api/reports/incidents", headers=tokens["ADMIN"], params=extra).status_code
            == 422
        )


def test_csv_projection_pagination_scope_and_formula_protection(http, tokens, population, db):
    population[1][0].title = '  =HYPERLINK("https://example.invalid","x,y")\nnext'
    db.commit()
    params = {**PARAMS, "format": "csv", "limit": 2}
    response = http.get("/api/reports/incidents", headers=tokens["ANALYST"], params=params)
    assert response.status_code == 200 and response.headers["x-export-has-more"] == "true"
    parsed = list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))
    assert (
        len(parsed) == 2
        and "hashed_password" not in response.text
        and "description" not in parsed[0]
    )
    allrows = http.get(
        "/api/reports/incidents", headers=tokens["ADMIN"], params={**params, "limit": 10}
    )
    parsed = list(csv.DictReader(io.StringIO(allrows.content.decode("utf-8-sig"))))
    title = next(r["title"] for r in parsed if r["incident_id"] == "INC-ANALYTICS-0")
    assert title.startswith("'  =") and "\nnext" in title
    empty = http.get(
        "/api/reports/incidents",
        headers=tokens["ADMIN"],
        params={
            "format": "csv",
            "start": (T - timedelta(days=2)).isoformat(),
            "end": (T - timedelta(days=1)).isoformat(),
        },
    )
    assert len(list(csv.DictReader(io.StringIO(empty.content.decode("utf-8-sig"))))) == 0


@pytest.mark.parametrize(
    "value",
    ["=2+2", "+cmd", "-formula", "@SUM(A1)", "\t=evil", "\r\n=evil", "\ufeff@evil", "\u200b=evil"],
)
def test_csv_injection(value):
    assert str(csv_cell(value)).startswith("'")
    assert csv_cell(-4) == -4 and csv_cell('ordinary,quoted"text') == 'ordinary,quoted"text'


def test_report_types_json_csv_and_roles(http, tokens, population):
    for kind in [
        "security-summary",
        "incidents",
        "detection-findings",
        "risk-assessments",
        "threat-indicators",
        "analyst-workload",
        "detection-rules",
    ]:
        path = "/api/reports/" + kind
        assert http.get(path).status_code == 401
        assert http.get(path, headers=tokens["VIEWER"]).status_code == 403
        for role in ["ADMIN", "ANALYST"]:
            response = http.get(path, headers=tokens[role], params=PARAMS)
            if kind == "analyst-workload" and role == "ANALYST":
                assert response.status_code == 403
                continue
            assert response.status_code == 200, (kind, response.text)
            assert response.json()["columns"] and response.headers["cache-control"] == "no-store"
            csv_response = http.get(path, headers=tokens[role], params={**PARAMS, "format": "csv"})
            assert (
                csv_response.status_code == 200
                and "attachment" in csv_response.headers["content-disposition"]
            )
    summary = http.get(
        "/api/reports/security-summary", headers=tokens["ADMIN"], params=PARAMS
    ).json()
    assert summary["sections"]["overview"]["incidents_created"] == 4


def test_analytics_and_reporting_issue_no_mutating_sql(
    db, settings, population, http, tokens, monkeypatch
):
    def forbidden(*a, **kw):
        pytest.fail("Analytics invoked processing/external service")

    monkeypatch.setattr(
        "app.threat_intelligence.service.ThreatIntelligenceService.lookup_ip", forbidden
    )
    monkeypatch.setattr("app.ai.service.AIAnalystService.analyze_incident", forbidden)
    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    conn = db.connection()
    sql_event.listen(conn, "before_cursor_execute", record)
    try:
        for endpoint in ENDPOINTS + ["analysts/workload"]:
            response = http.get(
                "/api/analytics/" + endpoint, headers=tokens["ADMIN"], params=PARAMS
            )
            assert response.status_code == 200, response.text
        assert (
            http.get(
                "/api/reports/security-summary", headers=tokens["ADMIN"], params=PARAMS
            ).status_code
            == 200
        )
    finally:
        sql_event.remove(conn, "before_cursor_execute", record)
    assert statements and all(s.lstrip().upper().startswith(("SELECT", "WITH")) for s in statements)


def test_recorded_status_history_reopen_and_missing_audit_exclusion(db, settings, population):
    _, cases = population
    for row in cases[:3]:
        audit(db, row, 0, "OPEN", action="INCIDENT_CREATED")
    # RESOLVED then reopened; current timing should no longer count this case toward MTTR.
    audit(db, cases[1], 180, "INVESTIGATING", "RESOLVED")
    cases[1].status = "INVESTIGATING"
    cases[1].resolved_at = None
    db.commit()
    result = service(db, settings).execute("status_history", QUERY)
    assert result.tracked_cases == 3 and result.excluded_cases == 1
    assert (result.data[0].open, result.data[0].investigating) == (2, 1)
    assert (result.data[2].resolved, result.data[2].false_positive) == (1, 1)
    assert (result.data[3].investigating, result.data[3].resolved, result.data[3].unresolved) == (
        1,
        0,
        2,
    )
    overview = service(db, settings).execute("overview", QUERY)
    assert overview.mean_time_to_resolve_seconds is None and overview.measured_resolutions == 0


def test_invalid_resolution_timing_and_automatic_ack_not_inferred(db, settings, scored):
    finding, _ = scored(80)
    case = make_case(
        db,
        finding,
        created_at=T + timedelta(hours=1),
        status="RESOLVED",
        resolved_at=T + timedelta(minutes=30),
    )
    audit(db, case, 70, "INVESTIGATING", automatic=True)
    db.commit()
    result = service(db, settings).execute("overview", QUERY)
    assert result.resolved_incidents == 1 and result.measured_resolutions == 0
    assert result.mean_time_to_resolve_seconds is result.mean_time_to_acknowledge_seconds is None


def test_histogram_upper_endpoint_and_unscored_findings(db, settings, scored):
    finding, assessment = scored(100)
    make_case(db, finding, risk_score=100)
    db.commit()
    svc = service(db, settings)
    assert svc.execute("histogram", schema.RiskQuery(**PARAMS)).data[-1].count == 1
    assert (
        svc.execute("histogram", schema.RiskQuery(**PARAMS, population="findings")).data[-1].count
        == 1
    )
    db.delete(assessment)
    db.commit()
    assert svc.execute("histogram", schema.RiskQuery(**PARAMS, population="findings")).total == 0


def test_synthetic_evaluation_uses_only_labelled_dataset(db, settings, scored):
    first, _ = scored(60)
    second, _ = scored(60, minutes=1)
    event = db.get(SecurityEvent, first.primary_event_id)
    event.raw_data = {
        "simulation": {"scenario": "brute_force", "scenario_id": "SIM-A", "generator_version": "1"}
    }
    missing = SecurityEvent(
        event_id="EVT-MISSED",
        timestamp=T + timedelta(minutes=10),
        event_type="LOGIN_FAILED",
        source_ip="192.0.2.88",
        status="failed",
        raw_data={
            "simulation": {
                "scenario": "password_spray",
                "scenario_id": "SIM-B",
                "generator_version": "1",
            }
        },
    )
    db.add(missing)
    db.commit()
    result = service(db, settings).execute("evaluation", QUERY)
    assert (
        result.expected_scenarios,
        result.detected_scenarios,
        result.missed_scenarios,
        result.findings_evaluated,
    ) == (2, 1, 1, 1)
    assert result.scenario_recall == 0.5 and result.finding_label_agreement == 1
    assert result.precision is None


def test_intelligence_modes_actual_metrics_and_ai_usage(db, settings, scored):
    from app.models import SystemMetric, ThreatIntelligenceResult
    from app.threat_intelligence.service import ThreatIntelligenceService

    intel = ThreatIntelligenceService(db, settings, mock=True)
    intel.lookup_ip("198.51.100.73")
    intel.lookup_ip("198.51.100.73")
    row = db.scalar(select(ThreatIntelligenceResult))
    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db.add(
        SystemMetric(
            metric_name="ai_analysis_failures", metric_value=2, unit="count", metric_metadata={}
        )
    )
    db.add(
        SystemMetric(
            metric_name="ai_analysis_duration_ms", metric_value=123, unit="ms", metric_metadata={}
        )
    )
    db.commit()
    query = schema.AnalyticsQuery(range="24h")
    result = service(db, settings).execute("intelligence", query)
    mock, live = result.modes
    assert (
        mock.simulation and mock.indicators_checked == 1 and mock.unknown == 1 and mock.expired == 1
    )
    assert mock.cache_hits == 1 and mock.lookups == 2 and len(mock.provider_usage) > 0
    assert live.indicators_checked == 0 and not live.simulation
    from app.schemas.reports import ReportQuery
    from app.services.reporting_service import ReportingService

    exported = ReportingService(db, settings).generate(
        "threat-indicators", ReportQuery(range="24h")
    )
    assert exported.rows[0]["reputation_level"] == "UNKNOWN"
    assert exported.rows[0]["normalized_score"] is None
    assert exported.rows[0]["cache_status"] == "expired"
    row.expires_at = datetime.now(UTC) + timedelta(hours=1)
    row.policy_hash = "0" * 64
    db.commit()
    exported = ReportingService(db, settings).generate(
        "threat-indicators", ReportQuery(range="24h")
    )
    assert exported.rows[0]["reputation_level"] == "UNKNOWN"
    assert exported.rows[0]["cache_status"] == "incompatible"
    ai = service(db, settings).execute("ai", query)
    assert ai.analysis_failures == 2 and ai.average_response_ms == 123 and ai.stale_analyses is None


def test_workload_and_report_paging_is_bounded(http, tokens, population):
    response = http.get(
        "/api/analytics/analysts/workload", headers=tokens["ADMIN"], params={**PARAMS, "limit": 1}
    )
    assert response.status_code == 200, response.text
    assert len(response.json()["items"]) == 1 and response.json()["has_more"]
    response = http.get(
        "/api/reports/analyst-workload",
        headers=tokens["ADMIN"],
        params={**PARAMS, "limit": 1, "offset": 1},
    )
    assert response.status_code == 200 and response.json()["rows"][0]["username"] == "analyst"
    assert not response.json()["has_more"]
