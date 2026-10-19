"""Explainable volume baselines from completed UTC days, never ground-truth labels."""

from collections import Counter, defaultdict
from datetime import UTC, timedelta
from math import ceil
from statistics import median

from app.detection.base import Rule


class VolumeRule(Rule):
    def lookback(self, config):
        if config.baseline_enabled:
            return timedelta(days=config.baseline_days + 2)
        return super().lookback(config)

    def lookahead(self, config):
        if config.baseline_enabled:
            return timedelta(days=config.baseline_days + 1)
        return super().lookahead(config)


def volume_baseline(rule, events, config, floor, *, weight=None):
    """Sensitive access: daily sum. API: daily peak of UTC-aligned request buckets."""
    daily = defaultdict(Counter)
    buckets = Counter()
    if config.baseline_enabled:
        for event in events:
            if not rule.applicable(event, config):
                continue
            entity, moment = rule.entity(event, config), event.timestamp.astimezone(UTC)
            if weight is not None:
                daily[entity][moment.date()] += weight(event)
            else:
                bucket = int(moment.timestamp()) // config.window_seconds
                key = (entity, moment.date(), bucket)
                buckets[key] += 1
                daily[entity][moment.date()] = max(daily[entity][moment.date()], buckets[key])
    cache = {}

    def describe(event):
        entity, day = rule.entity(event, config), event.timestamp.astimezone(UTC).date()
        key = (entity, day)
        if key not in cache:
            history = [
                value
                for date, value in daily[entity].items()
                if 0 < (day - date).days <= config.baseline_days
            ]
            baseline = median(history) if len(history) >= config.minimum_baseline_days else None
            limit = (
                max(floor, ceil(baseline * config.baseline_multiplier))
                if baseline is not None
                else floor
            )
            cache[key] = {
                "threshold": limit,
                "configured_threshold": floor,
                "baseline_source": (
                    "median_daily_record_access" if weight else "median_daily_peak_request_bucket"
                )
                if baseline is not None
                else "configured_threshold",
                "baseline_value": baseline,
                "baseline_active_days": len(history),
                "baseline_multiplier": config.baseline_multiplier,
                "baseline_start_date": (day - timedelta(days=config.baseline_days)).isoformat(),
                "baseline_end_date": (day - timedelta(days=1)).isoformat(),
                "baseline_timezone": "UTC",
            }
        return cache[key]

    return describe
