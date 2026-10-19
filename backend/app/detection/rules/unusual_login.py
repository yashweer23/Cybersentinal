from collections import defaultdict
from datetime import timedelta
from zoneinfo import ZoneInfo

from app.detection.base import DetectionMatch, Rule, order, successful


class UnusualLogin(Rule):
    rule_id, title = "CS-004", "Login outside expected activity hours"
    entity_columns = ("username",)

    def event_types(self, config):
        return tuple(config.event_types)

    def applicable(self, event, config):
        return super().applicable(event, config) and successful(event)

    def lookback(self, config):
        return timedelta(days=config.baseline_days + 1)

    def lookahead(self, config):
        # A late historical login may affect later users' baselines; bounded by baseline_days.
        return timedelta(days=config.baseline_days)

    def evaluate(self, events, candidates, config):
        history = defaultdict(list)
        zone = ZoneInfo(config.timezone)
        for event in sorted(events, key=order):
            if not self.applicable(event, config):
                continue
            local = event.timestamp.astimezone(zone)
            if event.id in candidates:
                prior = [
                    e
                    for e in history[event.username]
                    if 0
                    < (local.date() - e.timestamp.astimezone(zone).date()).days
                    <= config.baseline_days
                ]
                start, end, basis = (
                    config.normal_start_hour,
                    config.normal_end_hour,
                    "organization_hours",
                )
                if len(prior) >= config.minimum_baseline_events:
                    hours = sorted(e.timestamp.astimezone(zone).hour for e in prior)
                    # Central 80% plus explicit padding avoids a single outlier widening the range.
                    start = max(
                        0, hours[int((len(hours) - 1) * 0.1)] - config.baseline_padding_hours
                    )
                    end = min(
                        24, hours[int((len(hours) - 1) * 0.9)] + 1 + config.baseline_padding_hours
                    )
                    basis = "historical_central_80_percent"
                usual = (
                    start <= local.hour < end
                    if start < end
                    else local.hour >= start or local.hour < end
                )
                if not usual:
                    yield DetectionMatch(
                        self.rule_id,
                        self.title,
                        "A successful login occurred outside the configured or historical "
                        "activity interval; review legitimate schedule changes.",
                        (event.username,),
                        event,
                        [event],
                        {
                            "local_login_time": local.isoformat(),
                            "timezone": config.timezone,
                            "normal_start_hour": start,
                            "normal_end_hour": end,
                            "baseline_source": basis,
                            "baseline_event_count": len(prior),
                            "device": event.device,
                        },
                        80 if basis != "organization_hours" else 70,
                    )
            history[event.username].append(event)
