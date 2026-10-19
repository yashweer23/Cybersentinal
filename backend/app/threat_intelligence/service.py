"""Explicit lookups only. GETs and risk scoring never initiate provider requests."""

import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from time import perf_counter

from sqlalchemy import text

from app.core.errors import ServiceError
from app.models import SystemMetric, ThreatProviderState
from app.services.audit_service import record_audit
from app.threat_intelligence import cache
from app.threat_intelligence.aggregator import FAILURES, aggregate
from app.threat_intelligence.providers.abuseipdb import AbuseIPDBProvider
from app.threat_intelligence.providers.mock_provider import MockProvider
from app.threat_intelligence.providers.otx import OTXProvider
from app.threat_intelligence.providers.virustotal import VirusTotalProvider
from app.threat_intelligence.schemas import ProviderStatusResponse, ThreatPage
from app.threat_intelligence.utils.ip_validation import validate_ip

logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    def __init__(self, session, settings, *, mock=None, transport=None):
        self.session, self.settings = session, settings
        self.mode = (
            "mock" if (settings.threat_intelligence_mock_mode if mock is None else mock) else "live"
        )
        self.providers = (
            [MockProvider(settings)]
            if self.mode == "mock"
            else [
                cls(settings, transport=transport)
                for cls in (AbuseIPDBProvider, VirusTotalProvider, OTXProvider)
            ]
        )

    def policy_hash(self, mode=None):
        fields = {
            key: value
            for key, value in self.settings.model_dump(mode="json").items()
            if key.startswith("threat_intelligence_")
            or key in {"abuseipdb_enabled", "virustotal_enabled", "otx_enabled"}
        }
        fields["mode"], fields["normalization"] = mode or self.mode, "ti-v1"
        fields.pop("threat_intelligence_mock_mode", None)
        if fields["mode"] == "live":
            fields["credential_versions"] = [
                hashlib.sha256(
                    getattr(self.settings, k).get_secret_value().strip().encode()
                ).hexdigest()
                for k in ("abuseipdb_api_key", "virustotal_api_key", "otx_api_key")
            ]
        return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()

    def get_cached_intelligence(self, ip, *, mode=None, compact=False):
        target = validate_ip(ip)
        mode = mode or self.mode
        row = cache.snapshot(self.session, target.ip, mode)
        return cache.response(row, self.policy_hash(mode), compact=compact) if row else None

    def list_cached(self, filters):
        mode = filters.mode or self.mode
        rows, total = cache.list_cached(self.session, filters, mode)
        return ThreatPage(
            items=[cache.response(r, self.policy_hash(mode), compact=True) for r in rows],
            total=total,
            limit=filters.limit,
            offset=filters.offset,
        )

    def _provider_lookup(self, provider, target):
        now = datetime.now(UTC)
        if (
            self.mode == "mock"
            or not target.external_allowed
            or not provider.enabled
            or not provider.is_configured()
            or not self.settings.threat_intelligence_enabled
        ):
            return provider.lookup_ip(target.ip)
        credential = hashlib.sha256(provider.key.encode()).hexdigest()
        state = self.session.get(ThreatProviderState, provider.name, populate_existing=True)
        if state and state.credential_hash == credential and state.next_allowed_at > now:
            return provider.result(
                target.ip,
                "auth_error" if state.last_status == "auth_error" else "rate_limited",
                "Provider cooldown active; force refresh does not bypass it",
                retry_at=state.next_allowed_at,
            )
        result = provider.lookup_ip(target.ip)
        interval = getattr(
            self.settings,
            "threat_intelligence_"
            + {"AbuseIPDB": "abuseipdb", "VirusTotal": "virustotal", "AlienVault OTX": "otx"}[
                provider.name
            ]
            + "_interval_seconds",
        )
        next_allowed = datetime.now(UTC) + timedelta(seconds=interval)
        if result.lookup_status in FAILURES:
            next_allowed = max(next_allowed, result.expires_at)
        if result.lookup_status == "auth_error":
            next_allowed = max(next_allowed, now + timedelta(hours=24))
        if result.retry_at:
            next_allowed = max(next_allowed, result.retry_at)
        if state is None:
            state = ThreatProviderState(provider=provider.name)
            self.session.add(state)
        state.credential_hash, state.next_allowed_at, state.last_status = (
            credential,
            next_allowed,
            result.lookup_status,
        )
        return result

    def lookup_ip(self, ip, *, force_refresh=False, actor_id=None, ip_address=None, record=True):
        started = perf_counter()
        target = validate_ip(ip)
        policy = self.policy_hash()
        try:
            # A single DB-wide writer serializes lookups across API workers/CLIs. No Redis needed.
            # Nonblocking acquisition prevents requests queueing behind external timeouts.
            if not self.session.scalar(text("SELECT pg_try_advisory_xact_lock(112953, 9)")):
                raise ServiceError(409, "Another intelligence lookup is running; retry shortly")
            row = cache.snapshot(self.session, target.ip, self.mode)
            now = datetime.now(UTC)
            valid_policy = row is not None and row.policy_hash == policy
            if valid_policy and row.expires_at > now and not force_refresh:
                result = cache.response(row, policy)
            else:
                previous = (
                    {p.provider: p for p in cache.response(row, policy).providers}
                    if valid_policy
                    else {}
                )
                providers, hits, evaluations, requests = [], 0, 0, 0
                for provider in self.providers:
                    old = previous.get(provider.name)
                    if old and old.expires_at > now and not force_refresh:
                        providers.append(old)
                        hits += 1
                        continue
                    before = provider.requests
                    providers.append(self._provider_lookup(provider, target))
                    requests += provider.requests - before
                    evaluations += 1
                result = aggregate(target.ip, self.mode, providers)
                result.external_requests, result.provider_evaluations = requests, evaluations
                result.provider_cache_hits = hits
                cache.persist(self.session, result, policy)
            result.duration_ms = round((perf_counter() - started) * 1000, 3)
            if record:
                action = (
                    "THREAT_INTELLIGENCE_REFRESHED" if force_refresh else "THREAT_LOOKUP_PERFORMED"
                )
                record_audit(
                    self.session,
                    action,
                    actor_id=actor_id,
                    entity_type="threat_indicator",
                    entity_id=target.ip,
                    ip_address=ip_address,
                    new_value={
                        "mode": self.mode,
                        "cache_hit": result.cache_hit,
                        "reputation_level": result.reputation_level,
                        "external_requests": result.external_requests,
                        "lookup_status": result.lookup_status,
                    },
                )
                self.metrics(
                    {
                        "threat_lookup_count": 1,
                        "threat_cache_hits": int(result.cache_hit),
                        "threat_provider_errors": sum(
                            p.lookup_status in FAILURES for p in result.providers
                        ),
                        "threat_enrichment_duration_ms": result.duration_ms,
                    }
                )
            self.session.commit()
            logger.info(
                "Threat lookup mode=%s cache_hit=%s status=%s requests=%s",
                self.mode,
                result.cache_hit,
                result.lookup_status,
                result.external_requests,
            )
            return result
        except Exception as exc:
            self.session.rollback()
            if isinstance(exc, (ServiceError, ValueError)):
                raise
            logger.warning("Threat lookup failed error=%s", type(exc).__name__)
            raise ServiceError(
                503, "Threat-intelligence persistence unavailable; retry safely"
            ) from None

    def refresh_ip(self, ip, **kwargs):
        return self.lookup_ip(ip, force_refresh=True, **kwargs)

    def metrics(self, values):
        for name, value in values.items():
            self.session.add(
                SystemMetric(
                    metric_name=name,
                    metric_value=value,
                    unit="ms" if name.endswith("_ms") else "count",
                    metric_metadata={"mode": self.mode},
                )
            )

    def provider_status(self):
        values = []
        for cls in (AbuseIPDBProvider, VirusTotalProvider, OTXProvider):
            provider = cls(self.settings)
            state = self.session.get(ThreatProviderState, provider.name)
            credential = hashlib.sha256(provider.key.encode()).hexdigest()
            current = state is not None and state.credential_hash == credential
            values.append(
                dict(
                    name=provider.name,
                    configured=provider.is_configured(),
                    enabled=provider.enabled,
                    active=self.settings.threat_intelligence_enabled
                    and self.mode == "live"
                    and provider.enabled
                    and provider.is_configured(),
                    next_allowed_at=state.next_allowed_at if current else None,
                    last_status=state.last_status if current else None,
                )
            )
        values.append(
            dict(
                name="CyberSentinel Mock",
                configured=True,
                enabled=self.mode == "mock",
                active=self.mode == "mock" and self.settings.threat_intelligence_enabled,
            )
        )
        return ProviderStatusResponse(
            enabled=self.settings.threat_intelligence_enabled,
            mode=self.mode,
            simulation=self.mode == "mock",
            providers=values,
        )

    def enrich_incident(self, incident_id, **kwargs):
        from app.services.incident_enrichment import enrich_incidents
        from app.threat_intelligence.schemas import EnrichRequest

        return enrich_incidents(
            self,
            EnrichRequest(
                incident_id=incident_id, limit=1, force_refresh=kwargs.pop("force_refresh", False)
            ),
            **kwargs,
        )

    def enrich_pending(self, options, **kwargs):
        from app.services.incident_enrichment import enrich_incidents

        return enrich_incidents(self, options, **kwargs)

    def enrich_finding(self, finding_id, **kwargs):
        from app.services.incident_enrichment import indicator_query, read_related

        values = list(
            self.session.scalars(
                indicator_query(self.session, finding_id, "finding").limit(
                    self.settings.threat_intelligence_max_indicators + 1
                )
            )
        )
        if len(values) > self.settings.threat_intelligence_max_indicators:
            raise ServiceError(422, "Finding has too many indicators for one enrichment request")
        for value in values:
            self.lookup_ip(str(value), **kwargs)
        return read_related(self, finding_id, "finding")
