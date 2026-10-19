from app.detection.base import DetectionMatch, Rule
from app.detection.utils.time_windows import confidence, crossings


class SuspiciousPorts(Rule):
    rule_id, title = "CS-006", "Unusually broad destination-port activity"
    types, entity_columns = ("PORT_CONNECTION",), ("source_ip", "destination_ip")

    def applicable(self, event, config):
        return super().applicable(event, config) and event.destination_port is not None

    def evaluate(self, events, candidates, config):
        def measure(window):
            return len({e.destination_port for e in window})

        for entity, anchor, window, count in crossings(
            self, events, candidates, config, measure, config.distinct_port_threshold
        ):
            ports = sorted({e.destination_port for e in window})
            yield DetectionMatch(
                self.rule_id,
                self.title,
                "Supplied connection logs show one source contacting many ports on "
                "the same destination.",
                entity,
                anchor,
                window,
                {
                    "destination_ip": entity[1],
                    "unique_port_count": count,
                    "ports": ports[:100],
                    "ports_truncated": len(ports) > 100,
                    "threshold": config.distinct_port_threshold,
                },
                confidence(count, config.distinct_port_threshold),
            )
