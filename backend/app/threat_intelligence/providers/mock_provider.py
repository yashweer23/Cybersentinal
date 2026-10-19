from datetime import UTC, datetime, timedelta

from app.detection.reputation import LocalSyntheticReputationProvider
from app.threat_intelligence.schemas import ProviderResult
from app.threat_intelligence.utils.ip_validation import validate_ip


class MockProvider:
    name = "CyberSentinel Mock"

    def __init__(self, settings):
        self.settings = settings
        self.provider = LocalSyntheticReputationProvider()
        self.requests = 0

    def is_configured(self):
        return True

    @property
    def enabled(self):
        return self.settings.threat_intelligence_enabled

    def lookup_ip(self, ip):
        target, now = validate_ip(ip), datetime.now(UTC)
        rep = self.provider.lookup_ip(target.ip)
        status, level, score = "unknown", "UNKNOWN", None
        explanation = (
            "Mock mode has no reputation assertion for this public IP; no external request made."
        )
        if not self.enabled:
            status, explanation = "disabled", "Threat intelligence disabled"
        elif target.documentation:
            status = "success"
            level, score = ("MALICIOUS", rep.score) if rep else ("NO_ADVERSE_SIGNALS", 0)
            explanation = (
                "Synthetic documentation-only indicator set reused from Phase 6; "
                "not verified real-world intelligence."
            )
        elif not target.external_allowed:
            status, explanation = "not_applicable", target.reason
        return ProviderResult(
            provider=self.name,
            indicator=target.ip,
            simulation=True,
            lookup_status=status,
            reputation_level=level,
            normalized_score=score,
            provider_score=score,
            malicious=bool(rep) if score is not None else None,
            reports=143 if rep else 0 if score is not None else None,
            checked_at=now,
            expires_at=now + timedelta(hours=self.settings.threat_intelligence_cache_ttl_hours),
            explanation=explanation,
            raw_response={
                "synthetic": True,
                "indicator_set": "phase6-local-v1",
                "listed": bool(rep),
            },
        )
