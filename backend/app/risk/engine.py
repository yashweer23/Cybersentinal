"""Atomic bounded risk batches; source events and findings are never updated."""

import logging
from datetime import UTC, datetime
from time import perf_counter
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError

from app.core.errors import ServiceError
from app.detection.reputation import LocalSyntheticReputationProvider
from app.models import AuditLog, DetectionFinding, DetectionRule, SystemMetric
from app.repositories import risk_repository as repository
from app.risk.calculator import InvalidEvidence, calculate
from app.risk.config import RiskScoringConfig
from app.schemas.risk import RiskRunRequest, RiskRunResponse
from app.services.audit_service import record_audit

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    def __init__(self, session, settings, provider=None):
        self.session, self.settings = session, settings
        # Copy and revalidate even when a caller has mutated a nested configuration mapping.
        self.config = RiskScoringConfig.model_validate(settings.risk_scoring.model_dump())
        self.provider = provider or LocalSyntheticReputationProvider()

    def run(self, options=None, *, actor_id=None, ip_address=None):
        options = options or RiskRunRequest()
        provider = self.provider
        if options.reputation_source == "cached":
            from app.threat_intelligence.reputation import CachedReputationProvider

            provider = CachedReputationProvider(self.session, self.settings)
        started, cutoff, cursor = perf_counter(), datetime.now(UTC), None
        result = RiskRunResponse(
            run_id=uuid4(),
            config_hash=self.config.fingerprint,
            dry_run=options.dry_run,
            rescore=options.rescore,
        )
        score_sum, scored_count, audited = 0, 0, False

        def audit(summary):
            nonlocal audited
            if actor_id is None or options.dry_run:
                return
            values = {
                "findings_evaluated": summary.findings_evaluated,
                "assessments_created": summary.assessments_created,
                "assessments_updated": summary.assessments_updated,
                "unchanged_assessments": summary.unchanged_assessments,
                "invalid_findings": summary.invalid_findings,
                "already_scored": summary.already_scored,
                "rescore": options.rescore,
                "reputation_source": options.reputation_source,
                "score_version": summary.score_version,
                "config_hash": summary.config_hash,
                "rule": options.rule,
                "finding": options.finding,
            }
            if not audited:
                record_audit(
                    self.session,
                    "RISK_SCORING_RUN_TRIGGERED",
                    actor_id=actor_id,
                    entity_type="risk_run",
                    entity_id=str(result.run_id),
                    new_value=values,
                    ip_address=ip_address,
                )
            else:
                self.session.execute(
                    update(AuditLog)
                    .where(
                        AuditLog.entity_type == "risk_run",
                        AuditLog.entity_id == str(result.run_id),
                        AuditLog.action == "RISK_SCORING_RUN_TRIGGERED",
                    )
                    .values(new_value=values)
                )

        try:
            for batch_number in range(self.settings.risk_max_batches if options.until_empty else 1):
                batch_started = perf_counter()
                if not repository.acquire_lock(self.session):
                    raise ServiceError(409, "Another risk scoring batch is running; retry shortly")
                if batch_number == 0:
                    if (
                        options.finding
                        and self.session.scalar(
                            select(DetectionFinding.id).where(
                                DetectionFinding.finding_id == options.finding
                            )
                        )
                        is None
                    ):
                        raise ServiceError(404, "Detection finding not found")
                    if (
                        options.rule
                        and self.session.scalar(
                            select(DetectionRule.id).where(DetectionRule.rule_id == options.rule)
                        )
                        is None
                    ):
                        raise ServiceError(404, "Detection rule not found")
                    result.already_scored = (
                        0
                        if options.rescore
                        else repository.count_findings(self.session, options, cutoff, scored=True)
                    )
                batch = repository.fetch_batch(
                    self.session,
                    options,
                    cutoff,
                    options.batch_size or self.settings.risk_batch_size,
                    cursor,
                )
                if not batch:
                    if not options.dry_run and not audited and actor_id is not None:
                        audit(result)
                        self.session.commit()
                        audited = True
                    else:
                        self.session.rollback()
                    break
                cursor = (batch[-1].created_at, batch[-1].id)
                events, successes = repository.evidence_context(
                    self.session, batch, self.config, self.settings.risk_max_context_events, cutoff
                )
                reputation_cache = {}
                prior = repository.existing_assessments(self.session, batch)
                ips = {str(event.source_ip) for event in events.values()}
                ips.update(str(f.source_ip) for f in batch if f.source_ip)
                for ip in sorted(ips):
                    if ip in reputation_cache:
                        continue
                    reputation = provider.lookup_ip(ip)
                    reputation_cache[ip] = None
                    if reputation and (
                        reputation.expires_at is None or reputation.expires_at > cutoff
                    ):
                        if type(reputation.score) is not int or not 0 <= reputation.score <= 100:
                            raise ValueError("Invalid reputation-provider score")
                        reputation_cache[ip] = {
                            "ip": ip,
                            "score": reputation.score,
                            "source": reputation.source,
                            "synthetic": reputation.synthetic,
                        }
                        if reputation.context is not None:
                            reputation_cache[ip]["intelligence"] = reputation.context
                reputations = {
                    ip: value for ip, value in reputation_cache.items() if value is not None
                }
                proposed = result.model_copy(deep=True)
                values, batch_scores = [], []
                for finding in batch:
                    proposed.findings_evaluated += 1
                    try:
                        ids = finding.evidence_event_ids
                        evidence = (
                            [events[key] for key in ids if isinstance(key, str) and key in events]
                            if isinstance(ids, list) and len(ids) <= 200
                            else []
                        )
                        value = calculate(
                            finding,
                            evidence,
                            successes,
                            reputations,
                            self.config,
                            reputation_source=options.reputation_source,
                        )
                    except InvalidEvidence as exc:
                        logger.warning(
                            "Risk finding skipped finding=%s reason=%s", finding.finding_id, exc
                        )
                        proposed.invalid_findings += 1
                        if len(proposed.skipped) < 20:
                            proposed.skipped.append(
                                {"finding_id": finding.finding_id, "reason": str(exc)}
                            )
                        continue
                    batch_scores.append(value["risk_score"])
                    proposed.by_level[value["risk_level"].value] += 1
                    if len(proposed.previews) < 20:
                        proposed.previews.append(
                            {
                                "finding_id": finding.finding_id,
                                "risk_score": value["risk_score"],
                                "risk_level": value["risk_level"].value,
                                "breakdown": value["breakdown"],
                            }
                        )
                    existing = prior.get(finding.id)
                    if existing is not None and existing.input_hash == value["input_hash"]:
                        proposed.unchanged_assessments += 1
                        continue
                    value.update(
                        detection_finding_id=finding.id,
                        calculated_at=cutoff,
                        assessment_id=f"RISK-{cutoff:%Y%m%d}-{uuid4().hex.upper()}",
                    )
                    values.append(value)
                    if not options.dry_run:
                        if existing is None:
                            proposed.assessments_created += 1
                        else:
                            proposed.assessments_updated += 1
                proposed.batches += 1
                if not options.dry_run:
                    if values and repository.persist(
                        self.session, values, rescore=options.rescore
                    ) != len(values):
                        raise ServiceError(409, "Concurrent risk write detected; retry the batch")
                    for name, value, unit in (
                        ("risk_findings_scored", len(batch_scores), "findings"),
                        (
                            "risk_average_score",
                            sum(batch_scores) / len(batch_scores) if batch_scores else 0,
                            "points",
                        ),
                        ("risk_scoring_duration_ms", (perf_counter() - batch_started) * 1000, "ms"),
                    ):
                        self.session.add(
                            SystemMetric(
                                metric_name=name,
                                metric_value=value,
                                unit=unit,
                                metric_metadata={
                                    "run_id": str(result.run_id),
                                    "batch": batch_number + 1,
                                    "score_version": result.score_version,
                                    "assessments_written": len(values),
                                },
                            )
                        )
                    audit(proposed)
                    self.session.commit()
                    audited = audited or actor_id is not None
                else:
                    self.session.rollback()
                result = proposed
                score_sum += sum(batch_scores)
                scored_count += len(batch_scores)
            result.complete = not bool(
                repository.fetch_batch(self.session, options, cutoff, 1, cursor)
            )
            result.remaining_unscored = repository.count_findings(
                self.session, options, cutoff, scored=False
            )
            # Invalid rows were visited but remain unscored; a completed pass is not full success.
            if result.invalid_findings:
                result.complete = False
            self.session.rollback()
        except Exception as exc:
            try:
                self.session.rollback()
            except SQLAlchemyError:
                pass
            logger.warning("Risk batch failed error=%s", type(exc).__name__)
            result.complete = False
            result.error = (
                exc.detail
                if isinstance(exc, ServiceError)
                else "Risk batch failed; check database and scoring configuration"
            )
            result.duration_ms = round((perf_counter() - started) * 1000, 3)
            result.average_score = round(score_sum / scored_count, 2) if scored_count else 0
            error = ServiceError(
                exc.status_code if isinstance(exc, ServiceError) else 503, result.error
            )
            error.result = result
            raise error from None
        result.duration_ms = round((perf_counter() - started) * 1000, 3)
        result.average_score = round(score_sum / scored_count, 2) if scored_count else 0
        return result
