import hashlib
from contextlib import nullcontext
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import event as sa_event
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from app.core.errors import ServiceError
from app.incidents.engine import IncidentManagementService
from app.models import (
    AuditLog,
    DetectionFinding,
    DetectionRule,
    Incident,
    IncidentEvidence,
    IncidentFinding,
    IncidentProcessing,
    RiskAssessment,
    SecurityEvent,
    SystemMetric,
)
from app.repositories import incident_repository as repository
from app.risk.components import risk_level
from app.schemas.incident import IncidentRunRequest
from scripts.seed_detection_rules import seed_detection_rules
from tests import test_event_ingestion as fixtures

settings, http, tokens = fixtures.settings, fixtures.http, fixtures.tokens
T = datetime(2026, 9, 23, 12, tzinfo=UTC)
CAPS = [
    ("severity_score", "severity", 25),
    ("confidence_score", "confidence", 15),
    ("behavioural_score", "behavioural_intensity", 20),
    ("frequency_score", "event_frequency", 15),
    ("asset_sensitivity_score", "asset_sensitivity", 15),
    ("reputation_score", "reputation", 10),
]


def set_score(assessment, score):
    remaining, breakdown = score, {}
    for column, key, cap in CAPS:
        points = min(cap, remaining)
        remaining -= points
        setattr(assessment, column, points)
        breakdown[key] = {"points": points, "max": cap, "reason": "Controlled database fixture"}
    assessment.risk_score, assessment.risk_level = score, risk_level(score)
    assessment.breakdown = breakdown
    assessment.input_hash = hashlib.sha256(
        f"{assessment.assessment_id}:{score}".encode()
    ).hexdigest()
    assessment.calculated_at = datetime.now(UTC)


@pytest.fixture
def scored(db):
    seed_detection_rules(db)

    def make(
        score=60,
        *,
        username="employee014",
        ip="198.51.100.44",
        device="device14",
        minutes=0,
        rule="CS-001",
        created_at=None,
    ):
        event = SecurityEvent(
            event_id=f"EVT-{uuid4().hex}",
            timestamp=T + timedelta(minutes=minutes),
            source_ip=ip,
            username=username,
            device=device,
            event_type="LOGIN_FAILED",
            status="failed",
            processed=True,
            raw_data={"simulation": {"scenario": "benign"}, "untouched": True},
        )
        db.add(event)
        db.flush()
        detection_rule = db.scalar(select(DetectionRule).where(DetectionRule.rule_id == rule))
        finding = DetectionFinding(
            finding_id=f"FIND-{uuid4().hex}",
            detection_rule_id=detection_rule.id,
            title=detection_rule.name,
            description="Observed behavior",
            severity=detection_rule.severity,
            confidence=90,
            source_ip=ip,
            username=username,
            primary_event_id=event.id,
            evidence_event_ids=[event.event_id],
            evidence_data={"attempt_count": 5},
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            event_count=1,
            entity_key=f"{ip}:{username}",
            fingerprint=hashlib.sha256(event.event_id.encode()).hexdigest(),
        )
        if created_at:
            finding.created_at = created_at
        db.add(finding)
        db.flush()
        assessment = RiskAssessment(
            assessment_id=f"RISK-{uuid4().hex}",
            detection_finding_id=finding.id,
            score_version="v1",
            config_hash="0" * 64,
        )
        set_score(assessment, score)
        db.add(assessment)
        db.commit()
        return finding, assessment

    return make


def run(db, settings, **options):
    return IncidentManagementService(db, settings).run(IncidentRunRequest(**options))


def count(db, model):
    return db.scalar(select(func.count()).select_from(model))


def case(db):
    return db.scalar(select(Incident))


@pytest.mark.parametrize("score,expected", [(49, 0), (50, 1), (75, 1), (90, 1)])
def test_promotion_boundaries(db, settings, scored, score, expected):
    scored(score)
    result = run(db, settings, until_empty=True)
    assert result.incidents_created == expected and count(db, Incident) == expected
    assert result.complete and result.remaining == 0
    if expected:
        assert case(db).risk_score == score and case(db).severity == risk_level(score)
    assert run(db, settings, until_empty=True).findings_evaluated == 0


def test_correlation_evidence_idempotency_and_source_preservation(db, settings, scored):
    first, _ = scored(60)
    second, _ = scored(90, minutes=5, rule="CS-008")
    before = {e.id: (deepcopy(e.raw_data), e.processed) for e in db.scalars(select(SecurityEvent))}
    original = {f.id: deepcopy(f.evidence_data) for f in db.scalars(select(DetectionFinding))}
    result = run(db, settings, until_empty=True, batch_size=1)
    assert result.incidents_created == 1 and result.findings_attached == 2
    assert result.correlated_findings == 1 and result.complete
    row = case(db)
    assert row.risk_score == 90 and row.severity.value == "CRITICAL" and row.confidence == 90
    assert row.first_seen == first.first_seen and row.last_seen == second.last_seen
    assert count(db, IncidentEvidence) == 2
    assert all(e.detection_finding_id for e in db.scalars(select(IncidentEvidence)))
    assert {e.id: (e.raw_data, e.processed) for e in db.scalars(select(SecurityEvent))} == before
    assert {f.id: f.evidence_data for f in db.scalars(select(DetectionFinding))} == original
    metrics, audits = count(db, SystemMetric), count(db, AuditLog)
    repeat = run(db, settings, until_empty=True)
    assert repeat.findings_evaluated == repeat.incidents_created == 0
    assert (count(db, SystemMetric), count(db, AuditLog)) == (metrics, audits)


def test_unrelated_and_distant_findings_are_separate(db, settings, scored):
    scored()
    scored(username="other", ip="203.0.113.4", device="other")
    scored(minutes=61)
    assert run(db, settings, until_empty=True).incidents_created == 3


def test_new_related_low_finding_attaches_without_lowering_risk(db, settings, scored):
    scored(90)
    run(db, settings)
    identifier = case(db).incident_id
    finding, _ = scored(30, minutes=4, rule="CS-009")
    result = run(db, settings)
    assert result.findings_attached == 1 and result.incidents_created == 0
    assert case(db).incident_id == identifier and case(db).risk_score == 90
    assert case(db).last_seen == finding.last_seen


def test_deferred_finding_revisited_after_new_incident_context(db, settings, scored):
    scored(40, minutes=0)
    assert run(db, settings).findings_skipped == 1
    scored(60, minutes=4)
    result = run(db, settings, until_empty=True, batch_size=1)
    assert result.findings_attached == 2 and result.incidents_created == 1 and result.complete
    assert count(db, IncidentProcessing) == 2


def test_changed_scores_refresh_same_incident_and_can_promote_deferred(db, settings, scored):
    _, high = scored(90)
    _, lower = scored(60, minutes=2)
    low_finding, low = scored(30, username="separate", device="separate")
    run(db, settings, until_empty=True)
    original = case(db).incident_id
    set_score(high, 50)
    set_score(low, 70)
    db.commit()
    result = run(db, settings, until_empty=True)
    assert result.incidents_created == 1
    assert (
        db.scalar(select(Incident).where(Incident.incident_id == original)).risk_score
        == lower.risk_score
    )
    assert repository.linked_incident(db, low_finding.id).risk_score == 70


def test_policy_override_revisits_deferred_without_duplicate_links(db, settings, scored):
    scored(40)
    run(db, settings)
    result = run(db, settings, minimum_risk=40, until_empty=True)
    assert result.incidents_created == 1 and count(db, IncidentFinding) == 1
    assert run(db, settings, minimum_risk=40).findings_evaluated == 0


def test_read_only_dry_run_correlates_across_batches(db, settings, scored):
    scored(60)
    scored(80, minutes=5)
    scored(30, username="separate")
    before = {
        m: count(db, m)
        for m in (
            Incident,
            IncidentFinding,
            IncidentProcessing,
            IncidentEvidence,
            AuditLog,
            SystemMetric,
        )
    }
    sql = []
    connection = db.connection()

    def capture(conn, cursor, statement, parameters, context, executemany):
        sql.append(statement.lstrip().split()[0].upper())

    sa_event.listen(connection, "before_cursor_execute", capture)
    try:
        dry = run(db, settings, until_empty=True, dry_run=True, batch_size=1)
    finally:
        sa_event.remove(connection, "before_cursor_execute", capture)
    assert dry.projected_incidents_created == 1 and dry.projected_findings_attached == 2
    assert dry.incidents_created == dry.findings_attached == 0 and dry.complete
    assert not {"INSERT", "UPDATE", "DELETE"} & set(sql)
    assert {m: count(db, m) for m in before} == before
    real = run(db, settings, until_empty=True, batch_size=1)
    assert real.incidents_created == dry.projected_incidents_created
    assert real.findings_attached == dry.projected_findings_attached


def test_bad_evidence_is_not_marked_evaluated(db, settings, scored):
    bad, _ = scored()
    scored(username="other", device="other")
    bad.evidence_event_ids = ["missing"]
    db.commit()
    result = run(db, settings, until_empty=True, batch_size=1)
    assert result.invalid_findings == 1 and result.incidents_created == 1 and not result.complete
    assert db.get(IncidentProcessing, bad.id) is None


def test_failure_rolls_back_current_batch_and_preserves_prior_commit(
    db, settings, scored, monkeypatch
):
    scored()
    scored(username="other", device="other")
    original, calls = repository.save_link, 0

    def fail(*args, **kwargs):
        nonlocal calls
        calls += 1
        original(*args, **kwargs)
        if calls == 2:
            raise RuntimeError("private-database-password")

    monkeypatch.setattr(repository, "save_link", fail)
    with pytest.raises(ServiceError) as caught:
        run(db, settings, until_empty=True, batch_size=1)
    assert (
        caught.value.result.incidents_created == 1
        and "private-database-password" not in caught.value.detail
    )
    assert count(db, Incident) == count(db, IncidentFinding) == count(db, IncidentProcessing) == 1


def test_lock_busy_bounded_batches_and_candidate_limit(db, settings, scored, monkeypatch):
    scored()
    scored(minutes=2)
    monkeypatch.setattr(repository, "acquire_lock", lambda session: False)
    with pytest.raises(ServiceError) as caught:
        run(db, settings)
    assert caught.value.status_code == 409 and count(db, Incident) == 0
    monkeypatch.undo()
    assert not run(db, settings, batch_size=1).complete
    assert run(db, settings, until_empty=True).complete
    scored(minutes=3)
    settings.incident_max_candidates = 1
    with pytest.raises(ServiceError) as caught:
        run(db, settings)
    assert caught.value.status_code == 422 and count(db, IncidentFinding) == 2


def test_unique_link_constraints_and_no_evidence_deletion(db, settings, scored):
    finding, _ = scored()
    run(db, settings)
    link = db.scalar(select(IncidentFinding))
    with pytest.raises(IntegrityError), db.begin_nested():
        db.add(
            IncidentFinding(
                incident_id=link.incident_id,
                detection_finding_id=finding.id,
                relationship_reason="duplicate",
                correlation_data={},
            )
        )
        db.flush()
    with pytest.raises(IntegrityError), db.begin_nested():
        db.execute(text("DELETE FROM detection_findings"))
    with pytest.raises(IntegrityError), db.begin_nested():
        db.execute(text("DELETE FROM incidents"))


def test_cli_options_and_guard(db, settings, scored, monkeypatch, capsys):
    from scripts import run_incident_processing as cli

    finding, _ = scored(40)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "build_engine", lambda _: MagicMock())
    monkeypatch.setattr(cli, "Session", lambda _: nullcontext(db))
    assert (
        cli.main(["--until-empty", "--minimum-risk", "40", "--dry-run", "--batch-size", "1"]) == 0
    )
    assert "Projected incidents: 1" in capsys.readouterr().out and count(db, Incident) == 0
    assert cli.main(["--finding", finding.finding_id, "--minimum-risk", "40"]) == 0
    settings.app_env = "production"
    assert cli.main([]) == 1


def test_dry_plan_revisits_deferred_finding_when_new_case_is_projected(db, settings, scored):
    scored(40)
    run(db, settings)
    scored(60, minutes=4)
    result = run(db, settings, until_empty=True, dry_run=True, batch_size=1)
    assert result.projected_incidents_created == 1 and result.projected_findings_attached == 2
    assert result.complete and count(db, Incident) == 0
    real = run(db, settings, until_empty=True, batch_size=1)
    assert real.findings_attached == result.projected_findings_attached


def test_batch_deduplicates_shared_evidence_without_losing_finding_links(db, settings, scored):
    first, _ = scored(60)
    second, _ = scored(80, minutes=1, rule="CS-008")
    second.primary_event_id = first.primary_event_id
    second.evidence_event_ids = first.evidence_event_ids
    db.commit()
    result = run(db, settings, until_empty=True)
    assert result.findings_attached == 2 and count(db, IncidentFinding) == 2
    assert count(db, IncidentEvidence) == 1


def test_missing_account_does_not_bridge_different_known_accounts(db, settings, scored):
    scored(60, username=None)
    scored(70, username="alice", minutes=1)
    scored(80, username="bob", minutes=2)
    dry = run(db, settings, until_empty=True, dry_run=True)
    assert dry.projected_incidents_created == 2 and dry.projected_findings_attached == 3
    actual = run(db, settings, until_empty=True)
    assert actual.incidents_created == 2 and actual.correlated_findings == 1
    assert {row.username for row in db.scalars(select(Incident))} == {"alice", "bob"}
