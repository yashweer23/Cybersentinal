from datetime import UTC, datetime

from app.detection.base import DetectionMatch, Rule
from app.detection.reputation import LocalSyntheticReputationProvider


class SuspiciousIP(Rule):
    rule_id, title = "CS-008", "Source matches a synthetic suspicious-IP indicator"

    def __init__(self, provider=None, now=None):
        self.provider = provider or LocalSyntheticReputationProvider()
        self.now = now or datetime.now(UTC)

    def evaluate(self, events, candidates, config):
        for event in events:
            if event.id not in candidates:
                continue
            result = self.provider.lookup_ip(str(event.source_ip))
            if result is None or result.score < config.abuse_score_threshold:
                continue
            if (
                config.require_unexpired_cache
                and result.expires_at is not None
                and result.expires_at <= self.now
            ):
                continue
            yield DetectionMatch(
                self.rule_id,
                self.title,
                "The source is present in the independent local development "
                "indicator set; this is simulated reputation, not a live "
                "threat-intelligence verdict.",
                (str(event.source_ip),),
                event,
                [event],
                {
                    "indicator": str(event.source_ip),
                    "reputation_score": result.score,
                    "reputation_source": result.source,
                    "synthetic": result.synthetic,
                },
                95,
            )
