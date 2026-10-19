"""Read-only bridge to Phase 6's ReputationProvider protocol; no network calls."""

from datetime import UTC, datetime

from app.detection.reputation import Reputation
from app.threat_intelligence.service import ThreatIntelligenceService


class CachedReputationProvider:
    def __init__(self, session, settings, *, at=None):
        self.service = ThreatIntelligenceService(session, settings)
        self.at = at or datetime.now(UTC)

    def lookup_ip(self, ip):
        result = self.service.get_cached_intelligence(ip)
        if (
            result is None
            or result.stale
            or result.configuration_changed
            or result.reputation_level == "UNKNOWN"
            or result.normalized_score is None
            or result.checked_at > self.at
        ):
            return None
        return Reputation(
            result.normalized_score,
            "CyberSentinel cached intelligence ti-v1",
            result.simulation,
            expires_at=result.expires_at,
            context={
                "mode": result.mode,
                "reputation_level": result.reputation_level,
                "partial": result.partial,
                "checked_at": result.checked_at.isoformat(),
                "expires_at": result.expires_at.isoformat(),
                "providers": [
                    {
                        "provider": p.provider,
                        "status": p.lookup_status,
                        "score": p.normalized_score,
                        "provider_score": p.provider_score,
                        "explanation": p.explanation,
                    }
                    for p in result.providers
                ],
            },
        )
