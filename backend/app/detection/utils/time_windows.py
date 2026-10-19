"""Inclusive rolling windows; emit on a threshold crossing, not on every follow-on event."""

from collections import defaultdict, deque
from math import log2

from app.detection.base import order


def confidence(observed, threshold):
    # Strength of rule match only. 1x threshold=75; 2x=~82; 8x or more=95.
    return min(95, round(75 + 20 * max(0, log2(max(observed / threshold, 1))) / 3))


def crossings(rule, events, candidates, config, measure, threshold):
    groups = defaultdict(list)
    for event in events:
        if rule.applicable(event, config):
            groups[rule.entity(event, config)].append(event)
    for entity, rows in groups.items():
        window, previous_match, previous_time = deque(), False, None
        for event in sorted(rows, key=order):
            while (
                window
                and (event.timestamp - window[0].timestamp).total_seconds() > config.window_seconds
            ):
                window.popleft()
            if (
                previous_time is None
                or (event.timestamp - previous_time).total_seconds() > config.window_seconds
            ):
                previous_match = False
            window.append(event)
            value = measure(window)
            limit = threshold(event) if callable(threshold) else threshold
            if value >= limit and not previous_match and event.id in candidates:
                yield entity, event, list(window), value
            previous_match, previous_time = value >= limit, event.timestamp
