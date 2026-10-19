from copy import deepcopy
from unittest.mock import MagicMock

import pytest
from sqlalchemy import func, select, text, update

from app.core.errors import ServiceError
from app.detection.engine import DetectionEngine
from app.models import (
    AuditLog,
    DetectionFinding,
    DetectionRule,
    Incident,
    IncidentEvidence,
    SecurityEvent,
    SystemMetric,
)
from app.repositories import detection_repository as repository
from app.schemas.detection import DetectionRunRequest
from scripts.seed_detection_rules import seed_detection_rules
from tests import test_event_ingestion as ingestion_fixtures
from tests.test_detection_rules import event

http = ingestion_fixtures.http
settings = ingestion_fixtures.settings
tokens = ingestion_fixtures.tokens


@pytest.fixture
def seeded(db):
    seed_detection_rules(db)
    db.commit()


def run(db, settings, **options):
    return DetectionEngine(db, settings).run(DetectionRunRequest(**options))


def store(db, rows):
    db.add_all(rows)
    db.commit()


def count(db, model):
    return db.scalar(select(func.count()).select_from(model))


def test_persistence_processed_replay_valid_evidence_and_no_incidents(db, settings, seeded):
    rows = [event(seconds=i) for i in range(5)]
    store(db, rows)
    first = run(db, settings, until_empty=True, batch_size=2)
    assert (
        first.events_processed == 5 and first.findings_created == 1 and first.rules_executed == 10
    )
    finding = db.scalar(select(DetectionFinding))
    assert finding.event_count == 5 and finding.confidence == 75
    assert set(finding.evidence_event_ids) == {e.event_id for e in rows}
    assert len(finding.fingerprint) == 64
    assert all(e.processed for e in db.scalars(select(SecurityEvent)))
    repeat = run(db, settings, until_empty=True)
    assert repeat.events_evaluated == 0 and repeat.findings_created == 0
    replay = run(db, settings, until_empty=True, replay=True)
    assert replay.findings_created == 0 and replay.duplicate_findings == 1
    assert (
        count(db, DetectionFinding) == 1 and count(db, Incident) == count(db, IncidentEvidence) == 0
    )


def test_historical_processed_events_contribute_when_fifth_arrives(db, settings, seeded):
    store(db, [event(seconds=i * 10) for i in range(4)])
    assert run(db, settings).findings_created == 0
    store(db, [event(seconds=40)])
    result = run(db, settings)
    assert result.events_processed == 1 and result.findings_created == 1
    assert db.scalar(select(DetectionFinding)).event_count == 5


def test_late_event_rechecks_already_processed_future_anchor(db, settings, seeded):
    store(db, [event(seconds=i * 10) for i in (0, 1, 3, 4)])
    run(db, settings)
    store(db, [event(seconds=20)])
    assert run(db, settings).findings_created == 1
    assert db.scalar(select(DetectionFinding)).last_seen.second == 40


def test_dry_run_and_selected_rule_do_not_mark_processed(db, settings, seeded):
    store(db, [event(seconds=i) for i in range(5)])
    result = run(db, settings, dry_run=True, until_empty=True, batch_size=2)
    assert result.events_evaluated == 5 and result.events_processed == result.findings_created == 0
    assert result.findings_matched == 1 and result.findings_preview
    assert count(db, DetectionFinding) == count(db, SystemMetric) == 0
    assert repository.pending_count(db) == 5
    result = run(db, settings, rule="CS-001", until_empty=True, batch_size=2)
    assert (
        result.findings_created == 1
        and result.events_processed == 0
        and result.events_evaluated == 5
    )
    assert repository.pending_count(db) == 5
    assert run(db, settings, until_empty=True).duplicate_findings == 1


def test_disabled_rule_and_config_change(db, settings, seeded):
    row = db.scalar(select(DetectionRule).where(DetectionRule.rule_id == "CS-001"))
    row.enabled = False
    store(db, [event(seconds=i) for i in range(5)])
    first = run(db, settings)
    assert first.findings_created == 0 and first.rules_executed == 9
    row.enabled = True
    row.configuration = {"failed_attempt_threshold": 6, "window_seconds": 120}
    db.commit()
    assert run(db, settings, replay=True).findings_created == 0


def test_full_batch_rolls_back_rule_failure(db, settings, seeded, monkeypatch):
    store(db, [event(seconds=i) for i in range(5)])
    monkeypatch.setattr(
        "app.detection.rules.BruteForce.evaluate",
        MagicMock(side_effect=RuntimeError("private-secret")),
    )
    with pytest.raises(ServiceError) as caught:
        run(db, settings)
    assert "private-secret" not in caught.value.detail
    assert (
        repository.pending_count(db) == 5
        and count(db, DetectionFinding) == count(db, SystemMetric) == 0
    )


def test_persistence_failure_rolls_back_flags_and_findings(db, settings, seeded, monkeypatch):
    store(db, [event(seconds=i) for i in range(5)])

    def fail(session, batch):
        session.execute(text("SELECT 1 / 0"))

    monkeypatch.setattr(repository, "mark_processed", fail)
    with pytest.raises(ServiceError):
        run(db, settings)
    assert repository.pending_count(db) == 5 and count(db, DetectionFinding) == 0


def test_context_limit_fails_closed(db, settings, seeded, monkeypatch):
    store(db, [event(seconds=i) for i in range(5)])
    monkeypatch.setattr(settings, "detection_max_context_events", 3)
    with pytest.raises(ServiceError, match="context exceeds"):
        run(db, settings)
    assert repository.pending_count(db) == 5


def test_evidence_capped_raw_unchanged_multiple_rules(db, settings, seeded, monkeypatch):
    rows = [event(seconds=i, source_ip="192.0.2.44") for i in range(5)]
    original = {e.event_id: deepcopy(e.raw_data) for e in rows}
    store(db, rows)
    monkeypatch.setattr(settings, "detection_evidence_limit", 2)
    result = run(db, settings)
    assert result.findings_created == 6
    findings = db.scalars(select(DetectionFinding)).all()
    assert all(len(f.evidence_event_ids) <= 2 for f in findings)
    brute = next(f for f in findings if f.rule.rule_id == "CS-001")
    assert brute.evidence_data["evidence_truncated"] and brute.event_count == 5
    assert {e.event_id: e.raw_data for e in db.scalars(select(SecurityEvent))} == original


def test_unknown_enabled_rule_or_bad_config_stops_processing(db, settings, seeded):
    row = db.scalar(select(DetectionRule).where(DetectionRule.rule_id == "CS-001"))
    row.configuration = {"failed_attempt_threshold": -1}
    store(db, [event()])
    with pytest.raises(ServiceError):
        run(db, settings)
    assert repository.pending_count(db) == 1


def test_lock_conflict_and_bounded_runs(db, settings, seeded, monkeypatch):
    store(db, [event(seconds=i) for i in range(5)])
    monkeypatch.setattr(repository, "acquire_lock", lambda session: False)
    with pytest.raises(ServiceError) as error:
        run(db, settings)
    assert error.value.status_code == 409
    monkeypatch.undo()
    result = run(db, settings, batch_size=2)
    assert result.events_processed == 2 and not result.complete and result.unprocessed_events == 3


def test_findings_database_constraints_and_unique_fingerprint(db, settings, seeded):
    store(db, [event(seconds=i) for i in range(5)])
    run(db, settings)
    assert run(db, settings, replay=True).duplicate_findings == 1
    with pytest.raises(Exception), db.begin_nested():
        db.execute(text("UPDATE detection_findings SET confidence=101"))
    with pytest.raises(Exception), db.begin_nested():
        db.execute(
            text(
                "DELETE FROM security_events WHERE id IN "
                "(SELECT primary_event_id FROM detection_findings)"
            )
        )


def test_detection_api_rbac_config_audit_and_docs(http, tokens, db, seeded):
    for role in ("VIEWER", "ANALYST", "ADMIN"):
        headers = tokens[role]
        assert http.get("/api/detections", headers=headers).status_code == 200
        assert http.get("/api/detection/stats", headers=headers).status_code == 200
        assert http.get("/api/detection-rules", headers=headers).status_code == 200
    assert http.post("/api/detection/run", headers=tokens["VIEWER"], json={}).status_code == 403
    assert http.get("/api/detections").status_code == 401
    for role in ("VIEWER", "ANALYST"):
        assert (
            http.patch(
                "/api/detection-rules/CS-001", headers=tokens[role], json={"enabled": False}
            ).status_code
            == 403
        )
    response = http.patch(
        "/api/detection-rules/CS-001",
        headers=tokens["ADMIN"],
        json={"configuration": {"failed_attempt_threshold": 7}},
    )
    assert response.status_code == 200 and response.json()["configuration"]["window_seconds"] == 120
    assert (
        http.patch(
            "/api/detection-rules/CS-001",
            headers=tokens["ADMIN"],
            json={"configuration": {"window_seconds": -2}},
        ).status_code
        == 422
    )
    store(db, [event(seconds=i) for i in range(7)])
    result = http.post(
        "/api/detection/run", headers=tokens["ANALYST"], json={"until_empty": True}
    ).json()
    assert result["findings_created"] == 1 and result["events_processed"] == 7
    rows = http.get(
        "/api/detections?rule_id=CS-001&severity=HIGH&limit=1", headers=tokens["VIEWER"]
    ).json()
    assert rows["total"] == 1 and len(rows["items"]) == 1
    finding = http.get(
        "/api/detections/" + rows["items"][0]["finding_id"], headers=tokens["VIEWER"]
    ).json()
    assert finding["rule"]["rule_id"] == "CS-001" and finding["event_count"] == 7
    assert "risk_score" not in finding
    assert http.get("/api/detections/missing", headers=tokens["ADMIN"]).status_code == 404
    assert http.get("/api/detections?limit=501", headers=tokens["ADMIN"]).status_code == 422
    assert (
        http.get(
            "/api/detections?start_time=2026-10-01T00:00:00Z&end_time=2026-09-01T00:00:00Z",
            headers=tokens["ADMIN"],
        ).status_code
        == 422
    )
    actions = list(db.scalars(select(AuditLog.action)))
    assert actions.count("DETECTION_RUN_TRIGGERED") == actions.count("DETECTION_RULE_UPDATED") == 1
    paths = http.get("/openapi.json").json()["paths"]
    for path in (
        "/api/detection/run",
        "/api/detections",
        "/api/detections/{finding_id}",
        "/api/detection/stats",
        "/api/detection-rules",
        "/api/detection-rules/{rule_id}",
    ):
        assert path in paths
    assert http.get("/docs").status_code == 200


def test_cli_modes_and_evaluation_entrypoints(db, settings, seeded, monkeypatch, capsys):
    from contextlib import nullcontext

    from scripts import evaluate_detections, run_detection

    store(
        db,
        [
            event(
                seconds=i,
                raw_data={
                    "simulation": {"scenario": "brute_force", "scenario_id": "fixture-episode"}
                },
            )
            for i in range(5)
        ],
    )
    for module in (run_detection, evaluate_detections):
        monkeypatch.setattr(module, "get_settings", lambda: settings)
        monkeypatch.setattr(module, "build_engine", lambda _: MagicMock())
        monkeypatch.setattr(module, "Session", lambda _: nullcontext(db))
    assert run_detection.main(["--dry-run", "--until-empty", "--batch-size", "2"]) == 0
    assert count(db, DetectionFinding) == 0
    assert "Potential findings" in capsys.readouterr().out
    assert run_detection.main(["--until-empty"]) == 0
    assert count(db, DetectionFinding) == 1
    assert run_detection.main(["--replay", "--until-empty"]) == 0
    assert "Duplicate findings: 1" in capsys.readouterr().out
    assert evaluate_detections.main([]) == 0
    assert '"scenario_recall": 1.0' in capsys.readouterr().out


def test_no_labels_and_incorrect_labels_have_identical_matches(db, settings, seeded):
    rows = [event(seconds=i) for i in range(5)]
    store(db, rows)
    first = run(db, settings, dry_run=True)
    db.execute(
        update(SecurityEvent).values(
            raw_data={"simulation": {"scenario": "normal_activity", "scenario_id": "wrong"}}
        )
    )
    db.commit()
    second = run(db, settings, dry_run=True)
    assert first.findings_preview == second.findings_preview
    assert first.rule_matches == second.rule_matches


def test_api_empty_run_is_audited_and_dry_run_is_read_only(http, tokens, db, seeded):
    response = http.post("/api/detection/run", headers=tokens["ADMIN"], json={"dry_run": True})
    assert response.status_code == 200
    assert count(db, AuditLog) == 0
    response = http.post("/api/detection/run", headers=tokens["ADMIN"], json={})
    assert response.status_code == 200 and response.json()["events_processed"] == 0
    assert count(db, AuditLog) == 1


def test_missing_evidence_cannot_be_persisted(db, settings, seeded):
    from app.detection.base import DetectionMatch
    from app.detection.configuration import validate_configuration
    from app.detection.engine import finding_values

    row = event()
    store(db, [row])
    definition = db.scalar(select(DetectionRule).where(DetectionRule.rule_id == "CS-001"))
    match = DetectionMatch("CS-001", "Fixture", "Fixture", ("user",), row, [row], {})
    value = finding_values(
        match, definition.id, definition.severity, validate_configuration("CS-001", {}), 100
    )
    value["evidence_event_ids"].append("EVT-does-not-exist")
    with pytest.raises(ValueError, match="missing security events"):
        repository.persist_findings(db, [value])
    assert count(db, DetectionFinding) == 0


def test_previous_committed_batch_survives_later_failure(db, settings, seeded, monkeypatch):
    store(db, [event(seconds=i) for i in range(6)])
    from app.detection.rules.brute_force import BruteForce

    original = BruteForce.evaluate
    calls = 0

    def evaluate_or_fail(self, *args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("forced second batch failure")
        return original(self, *args)

    monkeypatch.setattr(BruteForce, "evaluate", evaluate_or_fail)
    with pytest.raises(ServiceError) as error:
        run(db, settings, batch_size=5, until_empty=True)
    assert error.value.result.events_processed == 5
    assert repository.pending_count(db) == 1 and count(db, DetectionFinding) == 1
    monkeypatch.undo()
    assert run(db, settings, until_empty=True).events_processed == 1


def test_batch_size_does_not_change_logical_fingerprints(db, settings, seeded):
    store(db, [event(seconds=i) for i in range(30)] + [event(seconds=600 + i) for i in range(6)])
    first = run(db, settings, until_empty=True, batch_size=2, dry_run=True)
    second = run(db, settings, until_empty=True, batch_size=100, dry_run=True)
    assert {f["fingerprint"] for f in first.findings_preview} == {
        f["fingerprint"] for f in second.findings_preview
    }
    assert first.findings_matched == second.findings_matched == 2
