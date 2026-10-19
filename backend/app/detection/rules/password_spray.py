from collections import Counter

from app.detection.base import DetectionMatch, Rule
from app.detection.utils.time_windows import confidence, crossings


class PasswordSpray(Rule):
    rule_id, title = "CS-002", "Possible password spraying"
    types = ("LOGIN_FAILED",)

    def applicable(self, event, config):
        return super().applicable(event, config) and bool(event.username)

    def evaluate(self, events, candidates, config):
        def measure(window):
            return sum(
                count <= config.max_attempts_per_user
                for count in Counter(e.username for e in window).values()
            )

        for entity, anchor, window, count in crossings(
            self, events, candidates, config, measure, config.distinct_user_threshold
        ):
            users = Counter(e.username for e in window)
            yield DetectionMatch(
                self.rule_id,
                self.title,
                "One source attempted authentication against many accounts with "
                "few attempts per account.",
                entity,
                anchor,
                window,
                {
                    "attempt_count": len(window),
                    "unique_username_count": len(users),
                    "qualifying_username_count": count,
                    "threshold": config.distinct_user_threshold,
                    "max_attempts_per_user": config.max_attempts_per_user,
                    "usernames": sorted(users)[:50],
                    "usernames_truncated": len(users) > 50,
                },
                confidence(count, config.distinct_user_threshold),
            )
