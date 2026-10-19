from app.detection.base import DetectionMatch, Rule, label, raw
from app.detection.utils.time_windows import confidence, crossings


class RepeatedDenied(Rule):
    rule_id, title = "CS-009", "Repeated access to protected resources denied"
    types, entity_columns = ("ACCESS_DENIED",), ("username", "source_ip")

    def evaluate(self, events, candidates, config):
        for entity, anchor, window, count in crossings(
            self, events, candidates, config, len, config.denied_attempt_threshold
        ):
            paths = {label(raw(e).get("resource", raw(e).get("path"))) for e in window} - {None}
            yield DetectionMatch(
                self.rule_id,
                self.title,
                "Repeated access denials for one account/source exceeded the configured limit.",
                entity,
                anchor,
                window,
                {
                    "denial_count": count,
                    "threshold": config.denied_attempt_threshold,
                    "resource_paths": sorted(paths)[:50],
                    "paths_truncated": len(paths) > 50,
                },
                confidence(count, config.denied_attempt_threshold),
            )
