"""Pure component functions. Input facts are validated before reaching these functions."""

import math

from app.core.enums import SeverityLevel
from app.risk.config import (
    ADMIN_BEHAVIOUR_POINTS,
    API_COMPRESSION_MAX,
    API_ERROR_COMPOSITION_MAX,
    CAPS,
    MISSING_APPROVAL_POINTS,
    OTHER_ROLE_BEHAVIOUR_POINTS,
    REPUTATION_BANDS,
    SEVERITY_POINTS,
)


def rounded(value):
    return int(math.floor(value + 0.5))


def component(key, value, reason):
    if not math.isfinite(value) or value < 0 or value > CAPS[key]:
        raise ValueError("Risk component outside its declared bounds")
    return {"points": rounded(value), "max": CAPS[key], "reason": reason}


def severity(level):
    points = SEVERITY_POINTS[level]
    return component("severity", points, f"Finding severity is {level}; retained from detection")


def confidence(value):
    return component("confidence", value * 15 / 100, f"{value}% confidence × 15 / 100")


def behavioural(facts, config):
    key = facts["rule_id"]
    if key in {"CS-001", "CS-002", "CS-003", "CS-006", "CS-007", "CS-009", "CS-010"}:
        ratio = facts["observed"] / facts["threshold"]
        points = 20 * min(1, max(0, math.log(max(1, ratio), config.intensity_full_ratio)))
        reason = (
            f"{facts['measure']}: {facts['observed']:g} / {facts['threshold']:g} "
            f"= {ratio:.3f}×; logarithmic exceedance, full points at "
            f"{config.intensity_full_ratio:g}×"
        )
        if key == "CS-003" and facts.get("simultaneous_logins"):
            points, reason = (
                20,
                "Distant successful logins have equal timestamps; no finite travel speed",
            )
    elif key == "CS-004":
        points = 20 * min(1, facts["hours_outside"] / config.unusual_full_hours)
        reason = (
            f"Login is {facts['hours_outside']:.3f} hours from the expected activity "
            f"interval; full points at {config.unusual_full_hours:g} hours"
        )
    elif key == "CS-005":
        gained_admin = facts["new_role"] in {"ADMIN", "ADMINISTRATOR"}
        points = (ADMIN_BEHAVIOUR_POINTS if gained_admin else OTHER_ROLE_BEHAVIOUR_POINTS) + (
            MISSING_APPROVAL_POINTS if not facts["approval_present"] else 0
        )
        reason = (
            f"Role changed {facts['previous_role']} → {facts['new_role']}; "
            f"approval reference {'present' if facts['approval_present'] else 'absent'}. "
            "A role change is not proof of compromise"
        )
    else:  # CS-008 reputation is counted exclusively by the reputation component.
        points, reason = 0, "Indicator-only finding has no separate behavioral intensity metric"
    if key in {"CS-001", "CS-002"} and facts["successful_authentication_count"]:
        points = min(20, points + config.success_bonus)
        reason += (
            f"; +{config.success_bonus} before cap: Successful authentication observed "
            "following repeated failures; this does not prove compromise"
        )
    return component("behavioural_intensity", points, reason)


def frequency(facts, config):
    key = facts["rule_id"]
    if key == "CS-009":
        breadth = len(facts["resource_paths"])
        points = 15 * min(1, max(0, breadth - 1) / (config.denied_resource_full_count - 1))
        reason = (
            f"{breadth} distinct retained protected resource paths; breadth scored "
            "separately from denial count; capped evidence may understate breadth"
        )
    elif key in {"CS-001", "CS-002", "CS-006", "CS-007", "CS-010"}:
        duration, window = facts["duration_seconds"], facts["window_seconds"]
        if facts["event_count"] < 2 or duration <= 0:
            points, reason = (
                0,
                "Insufficient timestamp resolution for an independent burst-duration score",
            )
        else:
            points = 15 * max(0, 1 - min(1, duration / window))
            reason = (
                f"{duration:g} seconds span within a {window:g}-second rule window; "
                "15 × (1 − span/window). Event/record count is not counted again"
            )
        if key == "CS-010":
            statuses = facts["response_status_distribution"]
            known = {
                key: value
                for key, value in statuses.items()
                if key.isdigit() and 100 <= int(key) <= 599
            }
            total = sum(known.values())
            errors = sum(value for key, value in known.items() if int(key) >= 400)
            fraction = errors / total if total else 0
            points = points * (API_COMPRESSION_MAX / CAPS["event_frequency"]) + (
                API_ERROR_COMPOSITION_MAX * fraction
            )
            reason += (
                f"; API policy allocates 10 points to time compression and 5 to "
                f"HTTP error composition ({errors}/{total} known responses), "
                "not to request count again"
            )
    else:
        points, reason = 0, "No independent frequency/breadth signal for this finding"
    return component("event_frequency", points, reason)


def sensitivity(facts, config):
    candidates = [(0, "No configured asset or action sensitivity")]
    for event in facts["event_context"]:
        service, action = event["service"], event["event_type"]
        candidates.append(
            (
                config.service_points.get(service, config.default_service_points),
                f"Service {service or 'unknown'}",
            )
        )
        candidates.append((config.action_points.get(action, 0), f"Action {action}"))
        candidates.append(
            (
                config.account_points.get(event["username"], 0),
                f"Configured account {event['username']}",
            )
        )
        candidates.append(
            (
                config.destination_points.get(event["destination_ip"], 0),
                f"Configured destination {event['destination_ip']}",
            )
        )
        if event["sensitive"]:
            candidates.append((config.sensitive_record_points, "Sensitive-record access flag"))
        if event["destination_port"] in config.administrative_ports:
            candidates.append(
                (
                    config.administrative_port_sensitivity,
                    f"Configured administrative port {event['destination_port']}",
                )
            )
    if facts["rule_id"] == "CS-005":
        candidates.append(
            (config.role_points.get(facts["new_role"], 0), f"New role {facts['new_role']}")
        )
    for username in facts["targeted_usernames"]:
        candidates.append(
            (config.account_points.get(username, 0), f"Configured targeted account {username}")
        )
    for path in facts.get("paths", []):
        clean = path.split("?", 1)[0].rstrip("/")
        for prefix, points in config.endpoint_points.items():
            prefix = prefix.rstrip("/")
            if clean == prefix or clean.startswith(prefix + "/"):
                candidates.append((points, f"Endpoint/resource prefix {prefix}"))
    points, basis = max(candidates, key=lambda item: (item[0], item[1]))
    return component(
        "asset_sensitivity",
        points,
        f"{basis}: {points}/15; highest applicable development mapping, not summed",
    )


def reputation(facts):
    matches = facts["reputation_context"]
    score = max((item["score"] for item in matches), default=0)
    points = next((points for threshold, points in REPUTATION_BANDS if score >= threshold), 0)
    reason = (
        f"Highest local synthetic reputation score is {score}; "
        "bands: 25→4, 75→7, 90→10. This is not live threat intelligence"
        if matches
        else "No matching local indicator; unknown does not establish safety"
    )
    if any("intelligence" in item for item in matches):
        reason = (
            f"Highest explicitly selected cached reputation signal is {score}; "
            "existing bands: 25→4, 75→7, 90→10. Provider policy/context and "
            "simulation mode are retained; this is not a compromise probability"
        )
    elif facts.get("reputation_source") == "cached":
        reason = (
            "No fresh usable signal in the explicitly selected intelligence cache; "
            "missing, expired or unknown reputation does not establish safety"
        )
    return component("reputation", points, reason)


def risk_level(score):
    if type(score) is not int or not 0 <= score <= 100:
        raise ValueError("Risk total must be an integer in 0–100")
    return (
        SeverityLevel.LOW
        if score < 25
        else SeverityLevel.MEDIUM
        if score < 50
        else SeverityLevel.HIGH
        if score < 75
        else SeverityLevel.CRITICAL
    )
