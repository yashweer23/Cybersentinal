from app.detection.base import DetectionMatch, Rule
from app.detection.utils.time_windows import confidence, crossings


class BruteForce(Rule):
    rule_id, title = "CS-001", "Possible brute-force authentication"
    types, entity_columns = ("LOGIN_FAILED",), ("source_ip", "username")

    def evaluate(self, events, candidates, config):
        for entity, anchor, window, count in crossings(
            self, events, candidates, config, len, config.failed_attempt_threshold
        ):
            yield DetectionMatch(
                self.rule_id,
                self.title,
                "Repeated failed authentication against the same account from one source.",
                entity,
                anchor,
                window,
                {
                    "attempt_count": count,
                    "threshold": config.failed_attempt_threshold,
                    "source_ip": entity[0],
                    "username": entity[1],
                },
                confidence(count, config.failed_attempt_threshold),
            )
