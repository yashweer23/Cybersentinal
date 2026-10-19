from app.detection.base import DetectionMatch, Rule, order, successful
from app.detection.utils.geo import coordinates, haversine


class ImpossibleTravel(Rule):
    rule_id, title = "CS-003", "Geographically implausible successful logins"
    types, entity_columns = ("LOGIN_SUCCESS", "ADMIN_LOGIN"), ("username",)

    def applicable(self, event, config):
        return super().applicable(event, config) and successful(event)

    def evaluate(self, events, candidates, config):
        previous = {}
        for event in sorted(events, key=order):
            if not self.applicable(event, config):
                continue
            prior = previous.get(event.username)
            previous[event.username] = event
            if prior is None or event.id not in candidates:
                continue
            a, b = coordinates(prior), coordinates(event)
            elapsed = (event.timestamp - prior.timestamp).total_seconds()
            if not a or not b or elapsed > config.window_seconds:
                continue
            distance = haversine(a, b)
            speed = distance / (elapsed / 3600) if elapsed > 0 else None
            if distance >= config.minimum_distance_km and (
                speed is None or speed > config.max_speed_kmh
            ):
                yield DetectionMatch(
                    self.rule_id,
                    self.title,
                    "Login locations imply travel exceeding the configured speed. VPNs "
                    "and shared accounts can also explain this pattern.",
                    (event.username,),
                    event,
                    [prior, event],
                    {
                        "location_a": a,
                        "location_b": b,
                        "distance_km": round(distance, 3),
                        "elapsed_hours": elapsed / 3600,
                        "required_speed_kmh": round(speed, 3) if speed is not None else None,
                        "simultaneous_logins": elapsed == 0,
                        "speed_threshold_kmh": config.max_speed_kmh,
                    },
                    90,
                )
