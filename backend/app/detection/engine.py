"""Deterministic orchestration: bounded contexts, atomic batches, immutable findings."""

import json
import logging
from datetime import UTC, datetime
from time import perf_counter
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.core.errors import ServiceError
from app.detection.configuration import validate_configuration
from app.detection.rules import RULE_TYPES
from app.detection.utils.fingerprints import fingerprint
from app.models import DetectionRule, SystemMetric
from app.repositories import detection_repository as repository
from app.schemas.detection import DetectionRunRequest, DetectionRunResponse
from app.services.audit_service import record_audit

logger = logging.getLogger(__name__)


def finding_values(match, rule_id, severity, config, evidence_limit):
    events = sorted(
        {event.event_id: event for event in match.events}.values(),
        key=lambda e: (e.timestamp, str(e.id)),
    )
    if not events or match.anchor not in events:
        raise ValueError("A finding needs its primary event in the evidence")
    selected = (
        events if len(events) <= evidence_limit else events[: evidence_limit - 1] + [match.anchor]
    )
    ids = list(dict.fromkeys(e.event_id for e in selected))
    key = fingerprint(match.rule_id, match.entity, match.anchor.event_id)
    evidence = {
        **match.evidence,
        "event_ids": ids,
        "evidence_truncated": len(ids) < len(events),
        "evidence_total": len(events),
        "first_event_time": events[0].timestamp.isoformat(),
        "last_event_time": events[-1].timestamp.isoformat(),
        "duration_seconds": (events[-1].timestamp - events[0].timestamp).total_seconds(),
        "configuration": config.model_dump(mode="json"),
        "detector_version": "1",
        "source_ips": sorted({str(e.source_ip) for e in events})[:20],
        "confidence_basis": "Rule evidence strength, not probability of compromise or risk",
    }
    json.dumps(evidence, allow_nan=False)
    return dict(
        finding_id=f"FIND-{match.anchor.timestamp:%Y%m%d}-{uuid4().hex.upper()}",
        detection_rule_id=rule_id,
        title=match.title,
        description=match.description,
        severity=severity,
        confidence=match.confidence,
        source_ip=match.anchor.source_ip,
        username=match.anchor.username,
        primary_event_id=match.anchor.id,
        evidence_event_ids=ids,
        evidence_data=evidence,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        event_count=len(events),
        entity_key=json.dumps(list(match.entity), separators=(",", ":"), ensure_ascii=False),
        fingerprint=key,
    )


class DetectionEngine:
    def __init__(self, session, settings):
        self.session, self.settings = session, settings

    def run(self, options=None, *, actor_id=None, ip_address=None):
        options = options or DetectionRunRequest()
        size = options.batch_size or self.settings.detection_batch_size
        result = DetectionRunResponse(
            run_id=uuid4(),
            dry_run=options.dry_run,
            selected_rule=options.rule,
            replay=options.replay,
        )
        started, cutoff, cursor, plan = perf_counter(), datetime.now(UTC), None, None
        rule_in_progress = None
        try:
            for batch_number in range(
                self.settings.detection_max_batches if options.until_empty else 1
            ):
                batch_started = perf_counter()
                if not repository.acquire_lock(self.session):
                    raise ServiceError(
                        409, "Another detection batch or rule update is running; retry shortly"
                    )
                if plan is None:
                    definitions = list(
                        self.session.scalars(select(DetectionRule).order_by(DetectionRule.rule_id))
                    )
                    if not definitions:
                        raise ServiceError(
                            422, "No detection rules are seeded; run seed_detection_rules first"
                        )
                    if options.rule and not any(
                        r.rule_id == options.rule and r.enabled for r in definitions
                    ):
                        raise ServiceError(422, "Selected rule is missing or disabled")
                    plan = []
                    for definition in definitions:
                        if not definition.enabled or (
                            options.rule and definition.rule_id != options.rule
                        ):
                            continue
                        rule_in_progress = definition.rule_id
                        config = validate_configuration(
                            definition.rule_id, definition.configuration
                        )
                        plan.append(
                            (
                                definition.id,
                                definition.rule_id,
                                definition.severity,
                                config,
                                RULE_TYPES[definition.rule_id](),
                            )
                        )
                    result.rule_matches = {key: 0 for _, key, _, _, _ in plan}
                batch = repository.fetch_batch(self.session, size, cutoff, cursor, options.replay)
                if not batch:
                    if batch_number == 0 and actor_id is not None and not options.dry_run:
                        record_audit(
                            self.session,
                            "DETECTION_RUN_TRIGGERED",
                            actor_id=actor_id,
                            entity_type="detection_run",
                            entity_id=str(result.run_id),
                            ip_address=ip_address,
                            new_value=options.model_dump(mode="json"),
                        )
                        self.session.commit()
                    else:
                        self.session.rollback()
                    break
                cursor = (batch[-1].timestamp, batch[-1].id)
                values, batch_counts = {}, {}
                for rule_uuid, key, severity, config, rule in plan:
                    rule_in_progress = key
                    context, candidates = repository.load_context(
                        self.session,
                        rule,
                        config,
                        batch,
                        self.settings.detection_max_context_events,
                        recheck_processed=not options.replay,
                    )
                    matches = list(rule.evaluate(context, candidates, config))
                    batch_counts[key] = len(matches)
                    for match in matches:
                        value = finding_values(
                            match,
                            rule_uuid,
                            severity,
                            config,
                            self.settings.detection_evidence_limit,
                        )
                        values[value["fingerprint"]] = value
                created, marked = 0, 0
                rule_in_progress = "persistence"
                if not options.dry_run:
                    created = repository.persist_findings(self.session, list(values.values()))
                    # A selected-rule pass has not evaluated every enabled rule.
                    if options.rule is None:
                        marked = sum(not e.processed for e in batch)
                        repository.mark_processed(self.session, batch)
                    for name, value, unit in (
                        ("detection_events_processed", marked, "events"),
                        ("detection_findings_created", created, "findings"),
                        ("detection_duration_ms", (perf_counter() - batch_started) * 1000, "ms"),
                    ):
                        self.session.add(
                            SystemMetric(
                                metric_name=name,
                                metric_value=value,
                                unit=unit,
                                metric_metadata={
                                    "run_id": str(result.run_id),
                                    "batch": batch_number + 1,
                                    "events_evaluated": len(batch),
                                },
                            )
                        )
                    if actor_id is not None and batch_number == 0:
                        record_audit(
                            self.session,
                            "DETECTION_RUN_TRIGGERED",
                            actor_id=actor_id,
                            entity_type="detection_run",
                            entity_id=str(result.run_id),
                            ip_address=ip_address,
                            new_value=options.model_dump(mode="json"),
                        )
                    self.session.commit()
                else:
                    self.session.rollback()
                result.events_evaluated += len(batch)
                result.events_processed += marked
                result.findings_created += created
                result.findings_matched += len(values)
                result.duplicate_findings += 0 if options.dry_run else len(values) - created
                result.batches += 1
                result.rules_executed = len(plan)
                for key, count in batch_counts.items():
                    result.rule_matches[key] += count
                for value in list(values.values())[: max(0, 20 - len(result.findings_preview))]:
                    result.findings_preview.append(
                        {
                            "title": value["title"],
                            "fingerprint": value["fingerprint"],
                            "confidence": value["confidence"],
                            "severity": value["severity"].value,
                            "event_ids": value["evidence_event_ids"],
                        }
                    )
                logger.info(
                    "Detection batch completed run=%s evaluated=%d created=%d",
                    result.run_id,
                    len(batch),
                    created,
                )
            # A finite run does not chase incoming data forever. Expose unfinished snapshot work.
            if cursor and repository.fetch_batch(
                self.session, 1, cutoff, cursor, options.replay, claim=False
            ):
                result.complete = False
            result.unprocessed_events = repository.pending_count(self.session)
            self.session.rollback()
        except Exception as exc:
            try:
                self.session.rollback()
            except SQLAlchemyError:
                pass
            logger.warning(
                "Detection batch failed rule=%s error=%s", rule_in_progress, type(exc).__name__
            )
            result.complete = False
            result.error = (
                exc.detail
                if isinstance(exc, ServiceError)
                else (
                    f"Detection batch failed at {rule_in_progress or 'startup'}; "
                    "check configuration and database, then retry"
                )
            )
            # Attach confirmed earlier progress; callers do not claim the failed batch committed.
            exc_result = ServiceError(
                exc.status_code if isinstance(exc, ServiceError) else 503, result.error
            )
            result.duration_ms = round((perf_counter() - started) * 1000, 3)
            exc_result.result = result
            raise exc_result from None
        result.duration_ms = round((perf_counter() - started) * 1000, 3)
        return result
