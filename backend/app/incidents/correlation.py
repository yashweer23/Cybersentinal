"""Pure correlation policy. Only verified finding/event fields enter this module."""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import UUID

from app.core.enums import IncidentStatus
from app.risk.config import SCORE_VERSION

AUTH_RULES = {"CS-001", "CS-002", "CS-003", "CS-004", "CS-005", "CS-009"}
ACTIVE = {IncidentStatus.OPEN, IncidentStatus.INVESTIGATING}


@dataclass(frozen=True)
class Policy:
    minimum_risk: int
    window_minutes: int
    minimum_match: int
    reopen_minutes: int

    @classmethod
    def from_settings(cls, settings, minimum_risk=None):
        return cls(
            settings.incident_min_risk_score if minimum_risk is None else minimum_risk,
            settings.incident_correlation_window_minutes,
            settings.incident_correlation_min_score,
            settings.incident_reopen_window_minutes,
        )

    @property
    def fingerprint(self):
        return hashlib.sha256(
            json.dumps(
                {
                    **self.__dict__,
                    "algorithm": "incident-v1",
                    "score_version": SCORE_VERSION,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()


@dataclass(frozen=True)
class Context:
    finding_id: str
    username: str | None
    source_ip: str | None
    device: str | None
    rule_id: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime

    @classmethod
    def from_finding(cls, finding, device):
        if not isinstance(device, str) or device.lower() in {"", "unknown", "n/a", "none"}:
            device = None
        return cls(
            finding.finding_id,
            finding.username,
            str(finding.source_ip) if finding.source_ip else None,
            device,
            finding.rule.rule_id,
            finding.first_seen,
            finding.last_seen,
            finding.created_at,
        )


@dataclass
class Case:
    id: UUID
    incident_id: str
    first_seen: datetime
    last_seen: datetime
    status: IncidentStatus
    resolved_at: datetime | None
    created_at: datetime
    risk_score: int
    members: list[Context] = field(default_factory=list)
    username: str | None = None

    @classmethod
    def from_row(cls, row):
        return cls(
            **{
                key: getattr(row, key)
                for key in (
                    "id",
                    "incident_id",
                    "first_seen",
                    "last_seen",
                    "status",
                    "resolved_at",
                    "created_at",
                    "risk_score",
                    "username",
                )
            }
        )


def related_rules(a, b):
    return a == b or {a, b} <= AUTH_RULES or "CS-008" in {a, b}


def match(incoming, case, policy, now):
    """A hard case-span limit prevents indefinitely chaining short neighboring windows."""
    if incoming.username and case.username and incoming.username != case.username:
        return None
    if case.status not in ACTIVE:
        if not (
            case.status == IncidentStatus.RESOLVED
            and policy.reopen_minutes > 0
            and case.resolved_at
            and incoming.created_at > case.resolved_at
            and timedelta(0) <= now - case.resolved_at <= timedelta(minutes=policy.reopen_minutes)
        ):
            return None
    span = max(case.last_seen, incoming.last_seen) - min(case.first_seen, incoming.first_seen)
    if span > timedelta(minutes=policy.window_minutes):
        return None
    best = None
    for prior in case.members:
        if incoming.username and prior.username and incoming.username != prior.username:
            continue
        attributes = {}
        if incoming.username and incoming.username == prior.username:
            attributes["same_username"] = 3
        if incoming.source_ip and incoming.source_ip == prior.source_ip:
            attributes["same_source_ip"] = 3
        if incoming.device and incoming.device == prior.device:
            attributes["same_device"] = 2
        # Time and rule family cannot substitute for at least two identity attributes.
        if len(attributes) < 2:
            continue
        if related_rules(incoming.rule_id, prior.rule_id):
            attributes["related_rule"] = 2
        attributes["within_case_window"] = 2
        score = sum(attributes.values())
        if score < policy.minimum_match:
            continue
        value = {
            "score": score,
            "threshold": policy.minimum_match,
            "factors": attributes,
            "matched_finding_id": prior.finding_id,
            "case_span_seconds": span.total_seconds(),
            "window_minutes": policy.window_minutes,
        }
        if best is None or (-score, prior.finding_id) < (
            -best["score"],
            best["matched_finding_id"],
        ):
            best = value
    return best


def choose_case(incoming, cases, policy, now):
    choices = []
    for case in cases:
        decision = match(incoming, case, policy, now)
        if decision:
            gap = abs((incoming.first_seen - case.last_seen).total_seconds())
            choices.append(
                ((-decision["score"], gap, case.created_at, str(case.id)), case, decision)
            )
    if not choices:
        return None, None
    _, case, decision = min(choices, key=lambda item: item[0])
    return case, decision
