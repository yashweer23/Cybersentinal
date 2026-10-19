from collections import Counter

from app.detection.base import DetectionMatch, label, raw
from app.detection.utils.baselines import VolumeRule, volume_baseline
from app.detection.utils.time_windows import confidence, crossings


class AbnormalAPI(VolumeRule):
    rule_id, title = "CS-010", "API request-volume burst"
    types = ("API_REQUEST",)

    def entity(self, event, config):
        value = getattr(event, config.group_by)
        return (str(value),) if value is not None else None

    def evaluate(self, events, candidates, config):
        baseline = volume_baseline(self, events, config, config.request_threshold)
        for entity, anchor, window, count in crossings(
            self, events, candidates, config, len, lambda event: baseline(event)["threshold"]
        ):
            endpoints = {label(raw(e).get("endpoint")) for e in window} - {None}
            statuses = Counter(
                str(raw(e).get("http_status"))
                if type(raw(e).get("http_status")) is int and 100 <= raw(e)["http_status"] <= 599
                else "unknown"
                for e in window
            )
            yield DetectionMatch(
                self.rule_id,
                self.title,
                "API request volume exceeded the configured per-entity time-window threshold.",
                entity,
                anchor,
                window,
                {
                    "request_count": count,
                    **baseline(anchor),
                    "group_by": config.group_by,
                    "endpoints": sorted(endpoints)[:50],
                    "endpoints_truncated": len(endpoints) > 50,
                    "response_status_distribution": dict(statuses),
                },
                confidence(count, baseline(anchor)["threshold"]),
            )
