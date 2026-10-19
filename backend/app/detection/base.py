"""Pure rule contract; SQL access and persistence belong to the engine/repository."""

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from app.models.security_event import SecurityEvent


def raw(event):
    return event.raw_data if isinstance(event.raw_data, dict) else {}


def label(value, maximum=255):
    return value[:maximum] if isinstance(value, str) else None


def successful(event):
    return event.status in {"success", "successful", "allowed"}


def order(event):
    return event.timestamp, str(event.id)


@dataclass
class DetectionMatch:
    rule_id: str
    title: str
    description: str
    entity: tuple[str, ...]
    anchor: SecurityEvent
    events: list[SecurityEvent]
    evidence: dict[str, Any]
    confidence: int = 75


class Rule:
    rule_id: str
    title: str
    types: tuple[str, ...] | None = None
    entity_columns: tuple[str, ...] = ("source_ip",)

    def event_types(self, config):
        return self.types

    def entity(self, event, config):
        values = tuple(getattr(event, key) for key in self.entity_columns)
        return tuple(map(str, values)) if all(value is not None for value in values) else None

    def applicable(self, event, config):
        types = self.event_types(config)
        return (types is None or event.event_type in types) and self.entity(
            event, config
        ) is not None

    def lookback(self, config):
        return timedelta(seconds=getattr(config, "window_seconds", 0) * 2)

    def lookahead(self, config):
        return timedelta(seconds=getattr(config, "window_seconds", 0))

    def evaluate(self, events, candidates, config):
        raise NotImplementedError
