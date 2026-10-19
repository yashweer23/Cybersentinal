"""Scored findings become cases through bounded, transactional incident processing."""

import logging
from datetime import UTC, datetime
from time import perf_counter
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.core.enums import IncidentStatus
from app.core.errors import ServiceError
from app.incidents.correlation import Case, Context, Policy, choose_case
from app.incidents.workflow import change_status
from app.models import DetectionFinding, Incident, IncidentFinding, RiskAssessment, SystemMetric
from app.repositories import incident_repository as repository
from app.repositories.risk_repository import acquire_lock as acquire_risk_lock
from app.risk.components import risk_level
from app.risk.config import SCORE_VERSION
from app.schemas.incident import (
    IncidentDecision,
    IncidentRunRequest,
    IncidentRunResponse,
    StatusRequest,
)
from app.services.audit_service import record_audit

logger = logging.getLogger(__name__)


def validated_evidence(finding, available):
    identifiers = finding.evidence_event_ids
    if not isinstance(identifiers, list) or not 1 <= len(identifiers) <= 200:
        raise ValueError("Invalid retained evidence list")
    if any(not isinstance(key, str) or key not in available for key in identifiers):
        raise ValueError("Retained evidence references a missing event")
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("Retained evidence has duplicate identifiers")
    rows = [available[key] for key in identifiers]
    primary = next((row for row in rows if row.id == finding.primary_event_id), None)
    if primary is None:
        raise ValueError("Primary event is missing from retained evidence")
    return rows, Context.from_finding(finding, primary.device)


class IncidentManagementService:
    def __init__(self, session, settings):
        self.session, self.settings = session, settings

    def run(self, options=None, *, actor_id=None, ip_address=None):
        options = options or IncidentRunRequest()
        policy = Policy.from_settings(self.settings, options.minimum_risk)
        result = IncidentRunResponse(
            run_id=uuid4(), policy_hash=policy.fingerprint, dry_run=options.dry_run
        )
        start, cutoff, cursor = perf_counter(), datetime.now(UTC), None
        virtual, touched, created_ids, updated_ids, invalid_ids = {}, {}, set(), set(), set()
        try:
            for batch_number in range(
                self.settings.incident_max_batches if options.until_empty else 1
            ):
                batch_start = perf_counter()
                # Fixed lock order: stabilize v1 scores, then serialize case/workflow mutations.
                if not acquire_risk_lock(self.session) or not repository.acquire_lock(self.session):
                    raise ServiceError(
                        409, "Another risk or incident operation is running; retry shortly"
                    )
                if batch_number == 0 and options.finding:
                    if (
                        self.session.scalar(
                            select(DetectionFinding.id).where(
                                DetectionFinding.finding_id == options.finding
                            )
                        )
                        is None
                    ):
                        raise ServiceError(404, "Detection finding not found")
                    if (
                        self.session.scalar(
                            select(RiskAssessment.id)
                            .join(DetectionFinding)
                            .where(
                                DetectionFinding.finding_id == options.finding,
                                RiskAssessment.score_version == SCORE_VERSION,
                            )
                        )
                        is None
                    ):
                        raise ServiceError(422, "Score this finding before incident processing")
                revision = repository.context_revision(self.session)
                if options.dry_run and virtual:
                    # Simulated case changes must also revisit previously deferred findings.
                    revision = cutoff
                batch = repository.fetch_batch(
                    self.session,
                    options,
                    policy,
                    cutoff,
                    revision,
                    options.batch_size or self.settings.incident_batch_size,
                    cursor,
                    excluded=invalid_ids,
                )
                if not batch and cursor and options.until_empty and not options.dry_run:
                    # Later attachments can make a previously deferred finding correlatable.
                    cursor = None
                    batch = repository.fetch_batch(
                        self.session,
                        options,
                        policy,
                        cutoff,
                        revision,
                        options.batch_size or self.settings.incident_batch_size,
                        excluded=invalid_ids,
                    )
                if not batch:
                    break
                last = batch[-1].finding
                cursor = (
                    0 if batch[-1].risk_score >= policy.minimum_risk else 1,
                    last.first_seen,
                    last.id,
                )
                available = repository.evidence_events(self.session, batch)
                proposed = result.model_copy(deep=True)
                states, batch_touched, batch_created, batch_updated = [], {}, set(), set()
                for assessment in batch:
                    finding = assessment.finding
                    proposed.findings_evaluated += 1
                    proposed.eligible_findings += assessment.risk_score >= policy.minimum_risk
                    try:
                        events, context = validated_evidence(finding, available)
                    except ValueError as exc:
                        invalid_ids.add(finding.id)
                        proposed.invalid_findings += 1
                        if len(proposed.skipped) < 20:
                            proposed.skipped.append(
                                {"finding_id": finding.finding_id, "reason": str(exc)}
                            )
                        logger.warning(
                            "Incident evidence skipped finding=%s reason=%s",
                            finding.finding_id,
                            exc,
                        )
                        continue
                    existing = repository.linked_incident(self.session, finding.id)
                    correlation = {}
                    if existing:
                        decision, reason = (
                            "REFRESH",
                            "Recompute the existing case from current linked assessments.",
                        )
                        selected = Case.from_row(existing)
                    else:
                        cases = repository.candidates(
                            self.session, context, policy, self.settings.incident_max_candidates
                        )
                        # A dry plan holds slim case contexts in memory, with no SQL mutations.
                        for key, value in virtual.items():
                            if key in cases:
                                known = {member.finding_id for member in value.members}
                                value.members.extend(
                                    m for m in cases[key].members if m.finding_id not in known
                                )
                            cases[key] = value
                        selected, correlation = choose_case(context, cases.values(), policy, cutoff)
                        if selected:
                            decision = "ATTACH"
                            reason = "Shared identity within the configured full-case time window."
                            proposed.correlated_findings += 1
                        elif assessment.risk_score >= policy.minimum_risk:
                            decision, reason = (
                                "CREATE",
                                "Current risk meets the promotion threshold; no qualifying case.",
                            )
                            identifier = uuid4()
                            selected = Case(
                                identifier,
                                f"INC-{cutoff:%Y%m%d}-{identifier.hex.upper()}",
                                finding.first_seen,
                                finding.last_seen,
                                IncidentStatus.OPEN,
                                None,
                                cutoff,
                                assessment.risk_score,
                                username=finding.username,
                            )
                        else:
                            decision, reason = (
                                "DEFER",
                                "Below promotion threshold and no qualifying case.",
                            )
                            proposed.findings_skipped += 1
                    if selected:
                        if options.dry_run:
                            if decision == "CREATE":
                                proposed.projected_incidents_created += 1
                            if decision in {"CREATE", "ATTACH"}:
                                proposed.projected_findings_attached += 1
                                selected.username = selected.username or finding.username
                                selected.members.append(context)
                                selected.first_seen = min(selected.first_seen, context.first_seen)
                                selected.last_seen = max(selected.last_seen, context.last_seen)
                                selected.risk_score = max(
                                    selected.risk_score, assessment.risk_score
                                )
                            if decision == "REFRESH":
                                selected.risk_score = self.session.scalar(
                                    select(func.max(RiskAssessment.risk_score))
                                    .join(
                                        IncidentFinding,
                                        IncidentFinding.detection_finding_id
                                        == RiskAssessment.detection_finding_id,
                                    )
                                    .where(
                                        IncidentFinding.incident_id == selected.id,
                                        RiskAssessment.score_version == SCORE_VERSION,
                                    )
                                )
                            if selected.status == IncidentStatus.RESOLVED and decision == "ATTACH":
                                selected.status = IncidentStatus.INVESTIGATING
                            virtual[selected.id] = selected
                            if len(virtual) > self.settings.incident_max_candidates:
                                raise ServiceError(
                                    422, "Dry-run case limit exceeded; narrow the run"
                                )
                            batch_touched[selected.id] = risk_level(selected.risk_score).value
                        else:
                            case = existing or self.session.get(Incident, selected.id)
                            if decision == "CREATE":
                                case = Incident(
                                    id=selected.id,
                                    incident_id=selected.incident_id,
                                    title=(
                                        finding.title
                                        + (
                                            f" — {finding.username}"
                                            if finding.username
                                            else f" — {finding.source_ip}"
                                            if finding.source_ip
                                            else ""
                                        )
                                    )[:255],
                                    description="Scored finding awaiting case aggregation.",
                                    detection_rule_id=finding.detection_rule_id,
                                    source_ip=finding.source_ip,
                                    username=finding.username,
                                    risk_score=assessment.risk_score,
                                    severity=assessment.risk_level,
                                    confidence=finding.confidence,
                                    status=IncidentStatus.OPEN,
                                    first_seen=finding.first_seen,
                                    last_seen=finding.last_seen,
                                    detected_at=cutoff,
                                    risk_score_version=SCORE_VERSION,
                                )
                                self.session.add(case)
                                self.session.flush()
                                batch_created.add(case.id)
                            elif case.status == IncidentStatus.RESOLVED and decision == "ATTACH":
                                change_status(
                                    self.session,
                                    case,
                                    StatusRequest(
                                        status=IncidentStatus.INVESTIGATING,
                                        reason=(
                                            "New related finding within the configured "
                                            "automatic reopen window."
                                        ),
                                    ),
                                    actor_id=actor_id,
                                    ip_address=ip_address,
                                    automatic=True,
                                )
                            old_context = {
                                "risk_score": case.risk_score,
                                "severity": case.severity.value,
                                "first_seen": case.first_seen.isoformat(),
                                "last_seen": case.last_seen.isoformat(),
                            }
                            if decision in {"CREATE", "ATTACH"}:
                                case.username = case.username or finding.username
                                repository.save_link(
                                    self.session,
                                    case,
                                    finding,
                                    events,
                                    reason,
                                    correlation or {"minimum_risk": policy.minimum_risk},
                                )
                                proposed.findings_attached += 1
                                record_audit(
                                    self.session,
                                    "FINDING_ATTACHED_TO_INCIDENT",
                                    actor_id=actor_id,
                                    entity_type="incident",
                                    entity_id=str(case.id),
                                    ip_address=ip_address,
                                    new_value={
                                        "finding_id": finding.finding_id,
                                        "reason": reason,
                                        "correlation": correlation,
                                        "policy_hash": policy.fingerprint,
                                    },
                                )
                            repository.refresh_incident(self.session, case)
                            new_context = {
                                "risk_score": case.risk_score,
                                "severity": case.severity.value,
                                "first_seen": case.first_seen.isoformat(),
                                "last_seen": case.last_seen.isoformat(),
                            }
                            record_audit(
                                self.session,
                                "INCIDENT_CREATED"
                                if decision == "CREATE"
                                else "INCIDENT_CONTEXT_UPDATED",
                                actor_id=actor_id,
                                entity_type="incident",
                                entity_id=str(case.id),
                                old_value=None if decision == "CREATE" else old_context,
                                new_value=new_context,
                                ip_address=ip_address,
                            )
                            if decision != "CREATE":
                                batch_updated.add(case.id)
                            batch_touched[case.id] = case.severity.value
                    if len(proposed.decisions) < 20:
                        proposed.decisions.append(
                            IncidentDecision(
                                finding_id=finding.finding_id,
                                decision=decision,
                                incident_id=selected.incident_id if selected else None,
                                reason=reason,
                                correlation=correlation or {},
                            )
                        )
                    states.append(
                        {
                            "detection_finding_id": finding.id,
                            "risk_input_hash": assessment.input_hash,
                            "policy_hash": policy.fingerprint,
                            "outcome": "LINKED" if selected else "DEFERRED",
                            "evaluated_at": cutoff,
                        }
                    )
                proposed.batches += 1
                if not options.dry_run:
                    revision = repository.context_revision(self.session)
                    for state in states:
                        state["context_updated_at"] = revision
                    repository.save_states(self.session, states)
                    for name, value, unit in (
                        ("incidents_created", len(batch_created), "incidents"),
                        ("incidents_updated", len(batch_updated), "incidents"),
                        (
                            "incident_processing_duration_ms",
                            (perf_counter() - batch_start) * 1000,
                            "ms",
                        ),
                    ):
                        self.session.add(
                            SystemMetric(
                                metric_name=name,
                                metric_value=value,
                                unit=unit,
                                metric_metadata={
                                    "run_id": str(result.run_id),
                                    "batch": batch_number + 1,
                                    "policy_hash": policy.fingerprint,
                                },
                            )
                        )
                    if actor_id is not None:
                        record_audit(
                            self.session,
                            "INCIDENT_PROCESSING_BATCH",
                            actor_id=actor_id,
                            entity_type="incident_run",
                            entity_id=str(result.run_id),
                            new_value={
                                "batch": batch_number + 1,
                                "findings_evaluated": len(batch),
                                "incidents_created": len(batch_created),
                            },
                            ip_address=ip_address,
                        )
                    self.session.commit()
                created_ids.update(batch_created)
                updated_ids.update(batch_updated)
                touched.update(batch_touched)
                result = proposed
                result.incidents_created = len(created_ids)
                result.incidents_updated = len(updated_ids - created_ids)
            revision = repository.context_revision(self.session)
            if options.dry_run:
                if virtual:
                    revision = cutoff
                result.remaining = max(
                    0,
                    repository.pending_count(self.session, options, policy, cutoff, revision)
                    - result.findings_evaluated,
                )
            else:
                result.remaining = repository.pending_count(
                    self.session, options, policy, cutoff, revision
                )
            result.complete = result.remaining == 0 and result.invalid_findings == 0
            self.session.rollback()
        except Exception as exc:
            try:
                self.session.rollback()
            except SQLAlchemyError:
                pass
            logger.warning("Incident batch failed error=%s", type(exc).__name__)
            result.complete = False
            result.error = (
                exc.detail
                if isinstance(exc, ServiceError)
                else "Incident processing failed; check database and configuration"
            )
            result.duration_ms = round((perf_counter() - start) * 1000, 3)
            error = ServiceError(
                exc.status_code if isinstance(exc, ServiceError) else 503, result.error
            )
            error.result = result
            raise error from None
        for level in touched.values():
            result.by_severity[level] += 1
        result.duration_ms = round((perf_counter() - start) * 1000, 3)
        return result
