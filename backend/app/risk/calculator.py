"""Prepare bounded, explicit facts and calculate a reproducible score without SQL or AI."""

import hashlib
import json
import math
from datetime import datetime, timedelta

from app.detection.base import raw, successful
from app.risk import components
from app.risk.config import SCORE_VERSION


class InvalidEvidence(ValueError):
    """Safe reason suitable for a skipped-finding report; never include raw payloads."""


def number(data, key, *, minimum=0):
    value = data.get(key)
    if type(value) not in {int, float} or not math.isfinite(value) or value < minimum:
        raise InvalidEvidence(f"Missing or invalid evidence metric: {key}")
    return value


def strings(data, key, *, limit=200):
    value = data.get(key, [])
    if (
        not isinstance(value, list)
        or len(value) > limit
        or any(not isinstance(item, str) or len(item) > 255 for item in value)
    ):
        raise InvalidEvidence(f"Invalid evidence list: {key}")
    return sorted(set(value))


def text(data, key):
    value = data.get(key)
    return value[:255] if isinstance(value, str) else None


def validate_references(finding, events):
    ids = finding.evidence_event_ids
    if (
        not isinstance(ids, list)
        or not 1 <= len(ids) <= 200
        or any(not isinstance(value, str) or not value or len(value) > 128 for value in ids)
    ):
        raise InvalidEvidence("Invalid or oversized evidence identifiers")
    if set(ids) != {event.event_id for event in events}:
        raise InvalidEvidence("Evidence references missing security events")
    if len(set(ids)) != len(ids) or finding.event_count < len(ids):
        raise InvalidEvidence("Evidence identifiers or event count are inconsistent")
    if finding.primary_event_id not in {event.id for event in events}:
        raise InvalidEvidence("Primary event missing from retained evidence")
    if not isinstance(finding.evidence_data, dict):
        raise InvalidEvidence("Evidence must be an object")


def facts_for(finding, events, successes, reputations, config):
    validate_references(finding, events)
    e, rule = finding.evidence_data, finding.rule.rule_id
    if rule not in {f"CS-{i:03}" for i in range(1, 11)}:
        raise InvalidEvidence("No scoring policy for this detection rule")
    duration = (finding.last_seen - finding.first_seen).total_seconds()
    if duration < 0:
        raise InvalidEvidence("Finding timestamps are reversed")
    facts = {
        "rule_id": rule,
        "duration_seconds": duration,
        "event_count": finding.event_count,
        "evidence_truncated": bool(e.get("evidence_truncated", False)),
        "evidence_event_ids": sorted(finding.evidence_event_ids),
    }
    metrics = {
        "CS-001": "attempt_count",
        "CS-002": "qualifying_username_count",
        "CS-006": "unique_port_count",
        "CS-007": "access_count",
        "CS-009": "denial_count",
        "CS-010": "request_count",
    }
    if rule in metrics:
        facts.update(
            observed=number(e, metrics[rule]),
            threshold=number(e, "threshold", minimum=1),
            measure=metrics[rule],
        )
        if rule != "CS-009":
            cfg = e.get("configuration")
            if not isinstance(cfg, dict):
                raise InvalidEvidence("Missing detection configuration snapshot")
            facts["window_seconds"] = number(cfg, "window_seconds", minimum=1)
    if rule == "CS-003":
        simultaneous = e.get("simultaneous_logins") is True
        facts.update(
            distance_km=number(e, "distance_km"),
            elapsed_hours=number(e, "elapsed_hours"),
            simultaneous_logins=simultaneous,
            observed=0 if simultaneous else number(e, "required_speed_kmh"),
            threshold=number(e, "speed_threshold_kmh", minimum=1),
            measure="required_speed_kmh",
        )
        if simultaneous and (facts["elapsed_hours"] != 0 or facts["distance_km"] <= 0):
            raise InvalidEvidence("Inconsistent simultaneous travel evidence")
    if rule == "CS-004":
        try:
            local = datetime.fromisoformat(e["local_login_time"])
            if local.tzinfo is None:
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise InvalidEvidence("Invalid timezone-aware login time") from None
        start, end = number(e, "normal_start_hour"), number(e, "normal_end_hour")
        if not 0 <= start < 24 or not 0 <= end <= 24 or start == end:
            raise InvalidEvidence("Invalid expected activity interval")
        hour = local.hour + local.minute / 60 + local.second / 3600
        within = start <= hour < end if start < end else hour >= start or hour < end

        def circular(boundary):
            return min(abs(hour - boundary), 24 - abs(hour - boundary))

        facts.update(
            hours_outside=0 if within else min(circular(start), circular(end)),
            local_login_time=local.isoformat(),
            normal_start_hour=start,
            normal_end_hour=end,
        )
    if rule == "CS-005":
        before, after = text(e, "previous_role"), text(e, "new_role")
        if not before or not after:
            raise InvalidEvidence("Missing structured privilege transition")
        facts.update(
            previous_role=before.upper(),
            new_role=after.upper(),
            approval_present=bool((text(e, "approval_reference") or "").strip()),
        )
    paths = strings(e, "resource_paths") if rule == "CS-009" else []
    facts["resource_paths"] = paths
    if rule == "CS-010":
        paths += strings(e, "endpoints")
        statuses = e.get("response_status_distribution", {})
        if (
            not isinstance(statuses, dict)
            or len(statuses) > 501
            or any(type(v) is not int or v < 0 for v in statuses.values())
            or any(
                not isinstance(k, str)
                or not (k == "unknown" or (k.isascii() and k.isdigit() and 100 <= int(k) <= 599))
                for k in statuses
            )
            or sum(statuses.values()) > facts["observed"]
        ):
            raise InvalidEvidence("Invalid HTTP response distribution")
        facts["response_status_distribution"] = statuses
        facts["requests_per_minute"] = (
            round(facts["observed"] * 60 / duration, 3) if duration else None
        )
    if rule in {"CS-007", "CS-010"}:
        facts["baseline_source"] = text(e, "baseline_source")
        facts["baseline_value"] = e.get("baseline_value")
    contexts = []
    for event in sorted(events, key=lambda row: row.event_id):
        data = raw(event)
        contexts.append(
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "source_ip": str(event.source_ip),
                "status": event.status,
                "event_type": event.event_type,
                "service": event.service,
                "username": event.username,
                "destination_ip": str(event.destination_ip) if event.destination_ip else None,
                "destination_port": event.destination_port,
                "sensitive": data.get("sensitive") is True
                or event.event_type == "SENSITIVE_RECORD_ACCESS",
            }
        )
        paths += [value for key in ("endpoint", "resource", "path") if (value := text(data, key))]
    facts["event_context"], facts["paths"] = contexts, sorted(set(paths))
    users = {event.username for event in events if event.username}
    if rule == "CS-001":
        users = {finding.username} if finding.username else set()
    elif rule == "CS-002":
        users.update(strings(e, "usernames"))
    facts["targeted_usernames"] = sorted(users)
    matches = []
    if rule in {"CS-001", "CS-002"}:
        matches = [
            event
            for event in successes
            if str(event.source_ip) == str(finding.source_ip)
            and event.username in users
            and event.event_type == "LOGIN_SUCCESS"
            and successful(event)
            and finding.last_seen
            <= event.timestamp
            <= finding.last_seen + timedelta(seconds=config.success_lookahead_seconds)
        ]
    facts["successful_authentication_count"] = len(matches)
    facts["successful_authentication_event_ids"] = sorted(event.event_id for event in matches)[:20]
    facts["successful_authentication_ids_truncated"] = len(matches) > 20
    sources = {str(event.source_ip) for event in events}
    if finding.source_ip:
        sources.add(str(finding.source_ip))
    facts["reputation_context"] = [reputations[ip] for ip in sorted(sources) if ip in reputations]
    return facts


def calculate(finding, events, successes, reputations, config, *, reputation_source="local"):
    facts = facts_for(finding, events, successes, reputations, config)
    if reputation_source == "cached":
        facts["reputation_source"] = "cached"
    breakdown = {
        "severity": components.severity(finding.severity.value),
        "confidence": components.confidence(finding.confidence),
        "behavioural_intensity": components.behavioural(facts, config),
        "event_frequency": components.frequency(facts, config),
        "asset_sensitivity": components.sensitivity(facts, config),
        "reputation": components.reputation(facts),
    }
    total = sum(value["points"] for value in breakdown.values())
    # Component bounds make overflow a logic error, not something to silently conceal.
    if not 0 <= total <= 100:
        raise ValueError("Risk component total violated the 0–100 invariant")
    total = min(100, max(0, total))
    snapshot = {
        "finding_id": finding.finding_id,
        "first_seen": finding.first_seen.isoformat(),
        "last_seen": finding.last_seen.isoformat(),
        "severity": finding.severity.value,
        "confidence": finding.confidence,
        "facts": facts,
        "configuration": config.model_dump(mode="json"),
        "score_version": SCORE_VERSION,
    }
    try:
        encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        raise InvalidEvidence(
            "Evidence contains non-serializable or non-finite scoring context"
        ) from None
    breakdown.update(
        context=facts,
        configuration=snapshot["configuration"],
        detection_severity=finding.severity.value,
        detection_confidence=finding.confidence,
    )
    return dict(
        risk_score=total,
        risk_level=components.risk_level(total),
        score_version=SCORE_VERSION,
        config_hash=config.fingerprint,
        input_hash=hashlib.sha256(encoded.encode()).hexdigest(),
        breakdown=breakdown,
        severity_score=breakdown["severity"]["points"],
        confidence_score=breakdown["confidence"]["points"],
        behavioural_score=breakdown["behavioural_intensity"]["points"],
        frequency_score=breakdown["event_frequency"]["points"],
        asset_sensitivity_score=breakdown["asset_sensitivity"]["points"],
        reputation_score=breakdown["reputation"]["points"],
    )
