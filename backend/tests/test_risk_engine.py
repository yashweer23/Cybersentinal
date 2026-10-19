from contextlib import nullcontext
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from sqlalchemy import event as sa_event
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError

from app.core.errors import ServiceError
from app.detection.engine import DetectionEngine
from app.detection.reputation import Reputation
from app.models import (
    AuditLog,
    DetectionFinding,
    Incident,
    IncidentComment,
    IncidentEvidence,
    RiskAssessment,
    SecurityEvent,
    SystemMetric,
)
from app.repositories import risk_repository as repository
from app.risk.config import RiskScoringConfig
from app.risk.engine import RiskScoringEngine
from app.schemas.detection import DetectionRunRequest
from app.schemas.risk import RiskRunRequest
from scripts.seed_detection_rules import seed_detection_rules
from tests import test_event_ingestion as ingestion_fixtures
from tests.test_detection_rules import event

settings = ingestion_fixtures.settings
http = ingestion_fixtures.http
tokens = ingestion_fixtures.tokens


def count(db, model):
    return db.scalar(select(func.count()).select_from(model))


@pytest.fixture
def findings(db, settings):
    seed_detection_rules(db)
    db.add_all([event(seconds=i, username=name) for name in ("first", "second") for i in range(5)])
    db.commit()
    result = DetectionEngine(db, settings).run(DetectionRunRequest(until_empty=True))
    assert result.findings_created == 2
    return list(
        db.scalars(
            select(DetectionFinding).order_by(DetectionFinding.created_at, DetectionFinding.id)
        )
    )


def run(db, settings, **options):
    return RiskScoringEngine(db, settings).run(RiskRunRequest(**options))


def test_persistence_breakdown_relationship_and_preserved_source(db, settings, findings):
    original = {f.id: deepcopy(f.evidence_data) for f in findings}
    events = {e.id: (deepcopy(e.raw_data), e.processed) for e in db.scalars(select(SecurityEvent))}
    result = run(db, settings, until_empty=True, batch_size=1)
    assert result.assessments_created == result.findings_evaluated == 2
    assert result.batches == 2 and result.remaining_unscored == 0 and result.complete
    for row in db.scalars(select(RiskAssessment)):
        assert row.finding.id in original and row.score_version == "v1"
        assert len(row.input_hash) == len(row.config_hash) == 64
        assert row.breakdown["severity"]["reason"] and 0 <= row.risk_score <= 100
    assert {f.id: f.evidence_data for f in db.scalars(select(DetectionFinding))} == original
    assert {e.id: (e.raw_data, e.processed) for e in db.scalars(select(SecurityEvent))} == events
    assert count(db, Incident) == count(db, IncidentEvidence) == count(db, IncidentComment) == 0


def test_repeat_and_unchanged_rescore_are_idempotent(db, settings, findings):
    run(db, settings, until_empty=True)
    rows = list(db.scalars(select(RiskAssessment)))
    identities = [(r.assessment_id, r.input_hash, r.calculated_at) for r in rows]
    repeat = run(db, settings, until_empty=True)
    assert (
        repeat.already_scored == 2 and repeat.findings_evaluated == repeat.assessments_created == 0
    )
    replay = run(db, settings, rescore=True, until_empty=True)
    assert (
        replay.unchanged_assessments == 2
        and replay.assessments_created == replay.assessments_updated == 0
    )
    assert [
        (r.assessment_id, r.input_hash, r.calculated_at) for r in db.scalars(select(RiskAssessment))
    ] == identities


def test_rescore_new_success_context_updates_same_assessment(db, settings, findings):
    run(db, settings, until_empty=True)
    target = findings[0]
    row = db.scalar(select(RiskAssessment).where(RiskAssessment.detection_finding_id == target.id))
    identifier, before, old_hash = row.assessment_id, row.risk_score, row.input_hash
    db.add(event("LOGIN_SUCCESS", seconds=10, username=target.username))
    db.commit()
    assert run(db, settings).findings_evaluated == 0
    result = run(db, settings, finding=target.finding_id, rescore=True)
    assert result.assessments_updated == 1 and count(db, RiskAssessment) == 2
    db.refresh(row)
    assert (
        row.assessment_id == identifier
        and row.risk_score == before + settings.risk_scoring.success_bonus
    )
    assert row.input_hash != old_hash
    assert row.breakdown["context"]["successful_authentication_count"] == 1


def test_rescore_configuration_is_explicit_and_snapshot_preserved(db, settings, findings):
    run(db, settings, until_empty=True)
    settings.risk_scoring = RiskScoringConfig(account_points={"first": 15, "second": 15})
    assert run(db, settings).already_scored == 2
    result = run(db, settings, rescore=True, until_empty=True)
    assert result.assessments_updated == 2
    assert all(r.asset_sensitivity_score == 15 for r in db.scalars(select(RiskAssessment)))


def test_dry_run_reads_all_batches_without_any_writes(db, settings, findings):
    before = count(db, SystemMetric), count(db, AuditLog)
    result = run(db, settings, dry_run=True, until_empty=True, batch_size=1)
    assert result.findings_evaluated == 2 and result.assessments_created == 0
    assert result.complete and len(result.previews) == 2
    assert count(db, RiskAssessment) == 0
    assert (count(db, SystemMetric), count(db, AuditLog)) == before
    run(db, settings, until_empty=True)
    original = {r.id: r.input_hash for r in db.scalars(select(RiskAssessment))}
    settings.risk_scoring = RiskScoringConfig(account_points={"first": 15})
    run(db, settings, dry_run=True, rescore=True, until_empty=True)
    assert {r.id: r.input_hash for r in db.scalars(select(RiskAssessment))} == original


def test_missing_reference_and_malformed_evidence_skip_only_bad_findings(db, settings, findings):
    target = findings[0]
    target.evidence_event_ids = target.evidence_event_ids + ["EVT-missing"]
    db.commit()
    result = run(db, settings, until_empty=True, batch_size=1)
    assert result.assessments_created == 1 and result.invalid_findings == 1 and not result.complete
    assert result.remaining_unscored == 1 and "missing" in result.skipped[0]["reason"]
    target.evidence_event_ids = target.evidence_event_ids[:-1]
    target.evidence_data = {"attempt_count": "malformed"}
    db.commit()
    assert run(db, settings).invalid_findings == 1


def test_batch_failure_rolls_back_assessments_metrics_and_audit(
    db, settings, findings, monkeypatch
):
    before = count(db, SystemMetric)
    original = repository.persist

    def fail(session, values, **kwargs):
        original(session, values, **kwargs)
        session.execute(text("SELECT 1 / 0"))

    monkeypatch.setattr(repository, "persist", fail)
    with pytest.raises(ServiceError) as caught:
        run(db, settings)
    assert caught.value.result.assessments_created == 0
    assert count(db, RiskAssessment) == 0 and count(db, SystemMetric) == before


def test_prior_committed_batch_survives_next_failure(db, settings, findings, monkeypatch):
    original, calls = repository.persist, 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("private-password")
        return original(*args, **kwargs)

    monkeypatch.setattr(repository, "persist", fail_second)
    with pytest.raises(ServiceError) as caught:
        run(db, settings, batch_size=1, until_empty=True)
    assert (
        caught.value.result.assessments_created == 1
        and "private-password" not in caught.value.detail
    )
    assert count(db, RiskAssessment) == 1


def test_lock_busy_and_bounded_run(db, settings, findings, monkeypatch):
    monkeypatch.setattr(repository, "acquire_lock", lambda session: False)
    with pytest.raises(ServiceError) as caught:
        run(db, settings)
    assert caught.value.status_code == 409
    monkeypatch.undo()
    result = run(db, settings, batch_size=1)
    assert not result.complete and result.remaining_unscored == 1
    assert run(db, settings, until_empty=True).assessments_created == 1


@pytest.mark.parametrize(
    "assignment",
    [
        "risk_score=-1",
        "risk_score=101",
        "confidence_score=16",
        "severity_score=26",
        "behavioural_score=21",
        "frequency_score=16",
        "asset_sensitivity_score=16",
        "reputation_score=11",
        "risk_level='LOW'",
        "breakdown='{}'::jsonb",
        "risk_score=risk_score+1",
        "config_hash='invalid'",
        "breakdown=jsonb_set(breakdown,'{confidence,reason}','null'::jsonb)",
        "breakdown=jsonb_set(breakdown,'{confidence,reason}','\"\"'::jsonb)",
        "breakdown=jsonb_set(breakdown,'{confidence,points}','0'::jsonb)",
    ],
)
def test_database_constraints(db, settings, findings, assignment):
    run(db, settings, until_empty=True)
    with pytest.raises(IntegrityError), db.begin_nested():
        db.execute(text(f"UPDATE risk_assessments SET {assignment}"))


def test_unique_version_and_foreign_key_preserve_assessed_finding(db, settings, findings):
    run(db, settings, until_empty=True)
    with pytest.raises(IntegrityError), db.begin_nested():
        db.execute(text("DELETE FROM detection_findings"))
    row = db.scalar(select(RiskAssessment))
    values = {
        c.name: getattr(row, c.name)
        for c in RiskAssessment.__table__.columns
        if c.name not in {"id", "assessment_id"}
    }
    with pytest.raises(IntegrityError), db.begin_nested():
        db.add(RiskAssessment(assessment_id="duplicate-fixture", **values))
        db.flush()
    values["score_version"] = "v0-fixture"
    db.add(RiskAssessment(assessment_id="older-version-fixture", **values))
    db.commit()
    assert count(db, RiskAssessment) == 3 and repository.stats(db).total_assessments == 2


def test_batched_event_queries_not_one_query_per_evidence_event(db, settings, findings):
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT") and "FROM security_events" in statement:
            statements.append(statement)

    connection = db.connection()
    sa_event.listen(connection, "before_cursor_execute", capture)
    try:
        run(db, settings, until_empty=True)
    finally:
        sa_event.remove(connection, "before_cursor_execute", capture)
    # Ten retained events are retrieved once; one additional query loads successful-auth context.
    assert len(statements) == 2


def test_expired_reputation_skipped_and_provider_failure_rolls_back(db, settings, findings):
    provider = MagicMock()
    provider.lookup_ip.return_value = Reputation(
        99, "fixture", True, datetime.now(UTC) - timedelta(seconds=1)
    )
    result = RiskScoringEngine(db, settings, provider).run(RiskRunRequest(until_empty=True))
    assert result.assessments_created == 2
    assert all(r.reputation_score == 0 for r in db.scalars(select(RiskAssessment)))
    provider.lookup_ip.side_effect = RuntimeError("provider-secret")
    with pytest.raises(ServiceError):
        RiskScoringEngine(db, settings, provider).run(RiskRunRequest(rescore=True))


def test_api_rbac_filters_pagination_stats_docs_and_audit(http, tokens, db, findings):
    assert http.get("/api/risk").status_code == 401
    assert http.post("/api/risk/run", headers=tokens["VIEWER"], json={}).status_code == 403
    for role in ("ADMIN", "ANALYST"):
        result = http.post(
            "/api/risk/run", headers=tokens[role], json={"until_empty": True, "batch_size": 1}
        )
        assert result.status_code == 200
    rows = http.get("/api/risk?limit=1", headers=tokens["VIEWER"]).json()
    assert rows["total"] == 2 and len(rows["items"]) == 1
    row = rows["items"][0]
    fetched = http.get("/api/risk/" + row["assessment_id"], headers=tokens["VIEWER"])
    assert fetched.status_code == 200 and fetched.json()["breakdown"] == row["breakdown"]
    for query in (
        "rule_id=CS-001",
        "source_ip=198.51.100.44",
        f"risk_level={row['risk_level']}",
        f"minimum_score={row['risk_score']}&maximum_score={row['risk_score']}",
    ):
        assert http.get("/api/risk?" + query, headers=tokens["VIEWER"]).json()["total"] == 2
    assert http.get("/api/risk?username=first", headers=tokens["VIEWER"]).json()["total"] == 1
    assert (
        http.get("/api/risk?offset=1&limit=1", headers=tokens["VIEWER"]).json()["items"][0][
            "assessment_id"
        ]
        != row["assessment_id"]
    )
    stats = http.get("/api/risk/stats", headers=tokens["VIEWER"]).json()
    assert stats["total_assessments"] == 2 and sum(stats["by_level"].values()) == 2
    assert http.get("/api/risk/missing", headers=tokens["ADMIN"]).status_code == 404
    assert (
        http.get("/api/risk?minimum_score=90&maximum_score=20", headers=tokens["ADMIN"]).status_code
        == 422
    )
    assert (
        http.get(
            "/api/risk?start_time=2026-10-01T00:00:00Z&end_time=2026-09-01T00:00:00Z",
            headers=tokens["ADMIN"],
        ).status_code
        == 422
    )
    audits = list(
        db.scalars(select(AuditLog).where(AuditLog.action == "RISK_SCORING_RUN_TRIGGERED"))
    )
    assert len(audits) == 2
    assert sorted(a.new_value["assessments_created"] for a in audits) == [0, 2]
    assert http.get("/api/risk", headers=tokens["VIEWER"]).headers["cache-control"] == "no-store"
    paths = http.get("/openapi.json").json()["paths"]
    for path, method in [
        ("/api/risk/run", "post"),
        ("/api/risk", "get"),
        ("/api/risk/stats", "get"),
        ("/api/risk/{assessment_id}", "get"),
    ]:
        assert paths[path][method]["security"] == [{"BearerAuth": []}]
    assert http.get("/docs").status_code == 200


def test_empty_api_run_audits_but_dry_run_never_writes(http, tokens, db):
    result = http.post("/api/risk/run", headers=tokens["ADMIN"], json={"dry_run": True})
    assert result.status_code == 200 and count(db, AuditLog) == 0
    result = http.post("/api/risk/run", headers=tokens["ANALYST"], json={})
    assert result.status_code == 200 and count(db, AuditLog) == 1
    assert result.json()["average_score"] == 0


def test_cli_options_and_environment_guard(db, settings, findings, monkeypatch, capsys):
    from scripts import run_risk_scoring as cli

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "build_engine", lambda _: MagicMock())
    monkeypatch.setattr(cli, "Session", lambda _: nullcontext(db))
    assert cli.main(["--dry-run", "--until-empty", "--batch-size", "1"]) == 0
    assert (
        "Potential scores and breakdowns" in capsys.readouterr().out
        and count(db, RiskAssessment) == 0
    )
    assert cli.main(["--rule", "CS-001", "--until-empty"]) == 0
    assert cli.main(["--finding", findings[0].finding_id, "--rescore"]) == 0
    assert "Unchanged assessments: 1" in capsys.readouterr().out
    settings.app_env = "production"
    assert cli.main([]) == 1


def test_oversized_auth_context_does_not_partially_score(db, settings, findings, monkeypatch):
    db.add_all([event("LOGIN_SUCCESS", seconds=10 + i, username="first") for i in range(4)])
    db.commit()
    monkeypatch.setattr(settings, "risk_max_context_events", 2)
    with pytest.raises(ServiceError, match="context limit"):
        run(db, settings)
    assert count(db, RiskAssessment) == 0


def test_highest_score_first_and_calculation_date_filter(http, tokens, db, settings, findings):
    settings.risk_scoring = RiskScoringConfig(account_points={"first": 15})
    run(db, settings, until_empty=True)
    rows = http.get("/api/risk", headers=tokens["VIEWER"]).json()["items"]
    assert rows[0]["username"] == "first" and rows[0]["risk_score"] > rows[1]["risk_score"]
    params = {
        "finding_id": rows[0]["finding_id"],
        "start_time": rows[0]["calculated_at"],
        "end_time": rows[0]["calculated_at"],
    }
    assert http.get("/api/risk", params=params, headers=tokens["VIEWER"]).json()["total"] == 1


def test_empty_statistics_and_missing_run_target(http, tokens):
    response = http.get("/api/risk/stats", headers=tokens["VIEWER"])
    assert response.json()["total_assessments"] == response.json()["highest_score"] == 0
    response = http.post("/api/risk/run", headers=tokens["ANALYST"], json={"finding": "missing"})
    assert response.status_code == 404 and response.json()["assessments_created"] == 0


def test_context_projection_does_not_load_large_unrelated_raw_payloads(db, settings, findings):
    payload = {
        "unrelated_payload": "x" * 100000,
        "endpoint": "/admin/users",
        "sensitive": True,
        "resource": {"malformed": "object"},
    }
    db.execute(update(SecurityEvent).values(raw_data=payload))
    db.commit()
    rows, successes = repository.evidence_context(
        db, findings, settings.risk_scoring, 100, datetime.now(UTC)
    )
    assert len(rows) == 10 and not successes
    for row in rows.values():
        assert row.raw_data == {
            "endpoint": "/admin/users",
            "sensitive": True,
            "resource": None,
            "path": None,
        }
    assert run(db, settings, until_empty=True).assessments_created == 2
    assert db.scalar(select(SecurityEvent.raw_data)) == payload
