"""Analysis history owns its transactions; incident evidence remains read-only."""

from datetime import UTC, datetime, timedelta
from math import ceil
from time import perf_counter
from uuid import uuid4

from sqlalchemy import func, select, text

from app.ai.catalog import EvidenceCatalog
from app.ai.context_builder import CONTEXT_VERSION, AIContextBuilder, digest
from app.ai.overview import overview
from app.ai.prompts import PROMPT_VERSION
from app.ai.providers.fallback import FallbackAnalyst
from app.ai.providers.llm_provider import LLMProvider
from app.ai.questions import answer_question
from app.ai.schemas import AIStatus, AnalysisRead, AnalysisResponse, HistoryPage
from app.ai.validation import validate_plan
from app.core.errors import ServiceError
from app.models import AIAnalysis, SystemMetric
from app.services.audit_service import record_audit


def configuration_hash(settings):
    return digest(
        {
            "prompt": PROMPT_VERSION,
            "context": CONTEXT_VERSION,
            "provider": settings.ai_provider,
            "model": settings.ai_model,
            "configured": LLMProvider(settings).is_configured(),
            "enabled": settings.ai_analyst_enabled,
            "events": settings.ai_max_context_events,
            "findings": settings.ai_max_context_findings,
            "tokens": settings.ai_max_response_tokens,
        }
    )


def ai_status(settings, session=None):
    configured = LLMProvider(settings).is_configured()
    if not settings.ai_analyst_enabled:
        return AIStatus(
            enabled=False,
            configured=configured,
            mode="DISABLED",
            status="DISABLED",
            provider="none",
            note="Generation is disabled; saved analysis remains readable.",
        )
    if not configured:
        return AIStatus(
            enabled=True,
            configured=False,
            mode="FALLBACK",
            status="FALLBACK",
            provider="deterministic",
            note=(
                "Evidence-grounded deterministic analysis is available; "
                "no external AI call is required."
            ),
        )
    status, note = (
        "CONFIGURED",
        (
            "Provider is configured but not probed. Readiness is "
            "established only by a validated response."
        ),
    )
    if session is not None:
        latest = session.scalar(
            select(AIAnalysis)
            .where(
                AIAnalysis.config_hash == configuration_hash(settings),
                AIAnalysis.generated_at >= datetime.now(UTC) - timedelta(hours=24),
            )
            .order_by(AIAnalysis.generated_at.desc(), AIAnalysis.id)
            .limit(1)
        )
        if latest:
            status = "READY" if latest.analysis_mode == "AI" else "FALLBACK"
            note = (
                (
                    "Last saved request within 24 hours returned validated "
                    "AI output; this is not a live provider probe."
                )
                if status == "READY"
                else (
                    "Last provider request used deterministic fallback. Check "
                    "configuration or retry later."
                )
            )
    return AIStatus(
        enabled=True,
        configured=True,
        mode="FALLBACK" if status == "FALLBACK" else "AI",
        status=status,
        provider="openai",
        model=settings.ai_model,
        note=note,
    )


class AIAnalystService:
    def __init__(self, session, settings, provider=None):
        self.session, self.settings = session, settings
        self.provider = provider or (
            LLMProvider(settings) if LLMProvider(settings).is_configured() else FallbackAnalyst()
        )
        self.builder = AIContextBuilder(session, settings)

    def _enabled(self):
        if not self.settings.ai_analyst_enabled:
            raise ServiceError(
                503, "AI analyst generation is disabled; saved analyses remain available"
            )

    def _latest(self, context):
        return self.session.scalar(
            select(AIAnalysis)
            .where(AIAnalysis.incident_id == context.incident_pk)
            .order_by(AIAnalysis.generated_at.desc(), AIAnalysis.id)
            .limit(1)
        )

    def _response(self, row, context, latest_id, cached=False):
        expired = bool(
            row.response.get("retry_at")
            and datetime.fromisoformat(row.response["retry_at"]) <= datetime.now(UTC)
        )
        stale = (
            row.context_hash != context.context_hash
            or row.config_hash != configuration_hash(self.settings)
            or expired
        )
        content = {
            key: value
            for key, value in row.response.items()
            if key not in {"retry_at", "provider_retry_at"}
        }
        return AnalysisResponse(
            **content,
            analysis_id=row.analysis_id,
            incident_id=context.incident_id,
            analysis_mode=row.analysis_mode,
            provider=row.provider,
            model=row.model,
            generated_at=row.generated_at,
            generated_by_user_id=str(row.generated_by_user_id)
            if row.generated_by_user_id
            else None,
            context_hash=row.context_hash,
            is_current=row.id == latest_id and not stale,
            stale=stale,
            cached=cached,
        )

    def read(self, identifier):
        context = self.builder.build(identifier)
        row = self._latest(context)
        return AnalysisRead(analysis=self._response(row, context, row.id) if row else None)

    def history(self, identifier, limit=10, offset=0):
        context = self.builder.build(identifier)
        latest = self._latest(context)
        clause = AIAnalysis.incident_id == context.incident_pk
        total = self.session.scalar(select(func.count()).select_from(AIAnalysis).where(clause))
        rows = self.session.scalars(
            select(AIAnalysis)
            .where(clause)
            .order_by(AIAnalysis.generated_at.desc(), AIAnalysis.id)
            .limit(limit)
            .offset(offset)
        )
        return HistoryPage(
            items=[self._response(row, context, latest.id) for row in rows],
            total=total,
            limit=limit,
            offset=offset,
        )

    def _audit(self, action, identifier, actor_id, ip, **values):
        record_audit(
            self.session,
            action,
            actor_id=actor_id,
            entity_type="ai_analysis",
            entity_id=identifier,
            new_value=values,
            ip_address=ip,
        )

    def _metric(self, name, value=1, unit="count", **metadata):
        self.session.add(
            SystemMetric(metric_name=name, metric_value=value, unit=unit, metric_metadata=metadata)
        )

    def analyze_incident(self, identifier, force_refresh=False, actor_id=None, ip=None):
        self._enabled()
        started = perf_counter()
        # Serialize generation for one incident; do not lock or mutate the incident itself.
        lock_key = int(digest(["ai", identifier])[:15], 16)
        if not self.session.scalar(
            text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": lock_key}
        ):
            raise ServiceError(409, "Analysis for this incident is already running")
        context = self.builder.build(identifier)
        self._audit("AI_ANALYSIS_REQUESTED", identifier, actor_id, ip, force_refresh=force_refresh)
        self._metric("ai_analysis_requests")
        previous = self._latest(context)
        if previous and self.settings.ai_analysis_cache_enabled and not force_refresh:
            result = self._response(previous, context, previous.id, cached=True)
            if result.is_current:
                self._metric("ai_analysis_cache_hits")
                self.session.commit()
                return result.model_copy(
                    update={
                        "context_build_ms": context.build_ms,
                        "provider_duration_ms": 0,
                        "duration_ms": round((perf_counter() - started) * 1000, 3),
                    }
                )
        catalog = EvidenceCatalog(context)
        # Provider Retry-After applies across cases and explicit regeneration too.
        # Store only the deadline, never response bodies or credentials.
        cooldown = self.session.scalar(
            select(AIAnalysis.response["provider_retry_at"].as_string())
            .where(
                AIAnalysis.config_hash == configuration_hash(self.settings),
                AIAnalysis.response["provider_retry_at"].as_string()
                > datetime.now(UTC).isoformat(),
            )
            .order_by(AIAnalysis.response["provider_retry_at"].as_string().desc())
            .limit(1)
        )
        if cooldown:
            generated = FallbackAnalyst().generate(catalog)
            generated.failure = "provider_cooldown"
            generated.retry_after_seconds = max(
                1, ceil((datetime.fromisoformat(cooldown) - datetime.now(UTC)).total_seconds())
            )
        else:
            generated = self.provider.generate(catalog)
        # Validate even adapters supplied by future providers; never trust provider implementations.
        try:
            plan = validate_plan(generated.plan, catalog)
        except (ValueError, TypeError):
            duration = generated.duration_ms
            generated = FallbackAnalyst().generate(catalog)
            generated.failure, generated.duration_ms = "invalid_output", duration
            plan = generated.plan
        content = catalog.render(plan).model_dump(mode="json")
        content.update(
            fallback_reason=generated.failure,
            context_build_ms=context.build_ms,
            provider_duration_ms=generated.duration_ms,
            duration_ms=round((perf_counter() - started) * 1000, 3),
        )
        if generated.failure:
            retry_seconds = max(
                self.settings.ai_fallback_cache_seconds, generated.retry_after_seconds or 0
            )
            content["retry_at"] = (datetime.now(UTC) + timedelta(seconds=retry_seconds)).isoformat()
            if generated.retry_after_seconds:
                content["provider_retry_at"] = (
                    cooldown
                    or (
                        datetime.now(UTC) + timedelta(seconds=generated.retry_after_seconds)
                    ).isoformat()
                )
            self._audit(
                "AI_ANALYSIS_FAILED",
                identifier,
                actor_id,
                ip,
                outcome=generated.failure,
                analysis_mode="FALLBACK",
            )
            self._metric("ai_analysis_failures", outcome=generated.failure)
        row = AIAnalysis(
            analysis_id=f"AI-{datetime.now(UTC):%Y%m%d}-{uuid4().hex.upper()}",
            incident_id=context.incident_pk,
            provider=generated.provider,
            model=generated.model,
            analysis_mode=generated.mode,
            context_version=CONTEXT_VERSION,
            context_hash=context.context_hash,
            config_hash=configuration_hash(self.settings),
            response=content,
            generated_by_user_id=actor_id,
        )
        self.session.add(row)
        self.session.flush()
        self._audit(
            "AI_ANALYSIS_REGENERATED" if force_refresh else "AI_ANALYSIS_GENERATED",
            identifier,
            actor_id,
            ip,
            analysis_id=row.analysis_id,
            analysis_mode=row.analysis_mode,
            outcome="saved",
        )
        self._metric("ai_analysis_success" if row.analysis_mode == "AI" else "ai_analysis_fallback")
        self._metric(
            "ai_analysis_duration_ms",
            round((perf_counter() - started) * 1000, 3),
            "ms",
            analysis_mode=row.analysis_mode,
        )
        # Recheck after external latency. A changed snapshot is saved as history but clearly stale.
        current = self.builder.build(identifier)
        response = self._response(row, current, row.id)
        self.session.commit()
        return response.model_copy(
            update={"duration_ms": round((perf_counter() - started) * 1000, 3)}
        )

    def answer_incident_question(self, identifier, question, actor_id=None, ip=None):
        self._enabled()
        started = perf_counter()
        context = self.builder.build(identifier)
        result = answer_question(question, EvidenceCatalog(context))
        self._audit(
            "AI_QUESTION_ASKED",
            identifier,
            actor_id,
            ip,
            analysis_mode="FALLBACK",
            outcome=result.confidence,
        )
        self._metric("ai_question_requests")
        self.session.commit()
        return result.model_copy(
            update={"duration_ms": round((perf_counter() - started) * 1000, 3)}
        )

    def answer_overview(self, question, actor_id=None, ip=None):
        self._enabled()
        result = overview(self.session, question)
        self._audit(
            "AI_QUESTION_ASKED",
            "overview",
            actor_id,
            ip,
            analysis_mode="FALLBACK",
            outcome=result.query,
        )
        self._metric("ai_overview_requests")
        self.session.commit()
        return result
