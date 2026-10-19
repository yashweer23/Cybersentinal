from app.detection.base import DetectionMatch, label, raw, successful
from app.detection.utils.baselines import VolumeRule, volume_baseline
from app.detection.utils.time_windows import confidence, crossings


def record_count(event):
    data = raw(event)
    count = data.get("record_count")
    if type(count) is int and 0 <= count <= 10000000:
        return count
    identifiers = data.get("record_ids")
    if isinstance(identifiers, list) and all(isinstance(x, str) for x in identifiers):
        return len(identifiers)
    # A plain access event without a batch count represents one logged access.
    return 1


class ExcessiveAccess(VolumeRule):
    rule_id, title = "CS-007", "High-volume sensitive-record access"
    types, entity_columns = ("SENSITIVE_RECORD_ACCESS", "FILE_ACCESS"), ("username",)

    def applicable(self, event, config):
        return (
            super().applicable(event, config)
            and successful(event)
            and (
                event.event_type == "SENSITIVE_RECORD_ACCESS" or raw(event).get("sensitive") is True
            )
        )

    def evaluate(self, events, candidates, config):
        baseline = volume_baseline(
            self, events, config, config.record_threshold, weight=record_count
        )

        def measure(window):
            return sum(record_count(e) for e in window)

        for entity, anchor, window, count in crossings(
            self, events, candidates, config, measure, lambda event: baseline(event)["threshold"]
        ):
            resources = {label(raw(e).get("resource_type")) for e in window} - {None}
            yield DetectionMatch(
                self.rule_id,
                self.title,
                "Logged sensitive-record access volume exceeded the configured "
                "limit. Counts represent access operations, not necessarily "
                "distinct records.",
                entity,
                anchor,
                window,
                {
                    "access_count": count,
                    "log_event_count": len(window),
                    **baseline(anchor),
                    "resource_types": sorted(resources)[:50],
                },
                confidence(count, baseline(anchor)["threshold"]),
            )
