"""Development-only scenario coverage. Ground-truth labels are used only in this script."""

import argparse
import json
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pydantic import ValidationError  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.exc import SQLAlchemyError  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.database import build_engine  # noqa: E402

SCENARIO_RULES = {
    "brute_force": "CS-001",
    "password_spray": "CS-002",
    "impossible_travel": "CS-003",
    "unusual_login": "CS-004",
    "privilege_escalation": "CS-005",
    "port_activity": "CS-006",
    "excessive_access": "CS-007",
    "known_malicious_ip": "CS-008",
    "access_denied": "CS-009",
    "abnormal_api": "CS-010",
}


def evaluate(session):
    scenarios = session.execute(
        text("""
        SELECT DISTINCT raw_data->'simulation'->>'scenario' AS scenario,
            raw_data->'simulation'->>'scenario_id' AS scenario_id
        FROM security_events WHERE raw_data->'simulation'->>'scenario_id' IS NOT NULL
    """)
    ).all()
    expected = {(SCENARIO_RULES[label], sid) for label, sid in scenarios if label in SCENARIO_RULES}
    matched, agreeing, seen = set(), set(), set()
    rows = session.execute(
        text("""
        SELECT f.finding_id, r.rule_id,
            e.raw_data->'simulation'->>'scenario' AS scenario,
            e.raw_data->'simulation'->>'scenario_id' AS scenario_id
        FROM detection_findings f
        JOIN detection_rules r ON r.id = f.detection_rule_id
        CROSS JOIN LATERAL jsonb_array_elements_text(f.evidence_event_ids) AS ids(event_id)
        JOIN security_events e ON e.event_id = ids.event_id
    """).execution_options(yield_per=500)
    )
    for finding_id, rule_id, label, sid in rows:
        seen.add(finding_id)
        if SCENARIO_RULES.get(label) == rule_id and (rule_id, sid) in expected:
            matched.add((rule_id, sid))
            agreeing.add(finding_id)
    missed = sorted(expected - matched)
    return {
        "expected_scenarios": len(expected),
        "detected_scenarios": len(matched),
        "missed_scenarios": len(missed),
        "unexpected_findings": len(seen - agreeing),
        "total_findings_evaluated": len(seen),
        "scenario_recall": len(matched) / len(expected) if expected else None,
        "finding_label_agreement": len(agreeing) / len(seen) if seen else None,
        "by_rule": {
            rule: {
                "expected": sum(pair[0] == rule for pair in expected),
                "detected": sum(pair[0] == rule for pair in matched),
            }
            for rule in sorted(SCENARIO_RULES.values())
        },
        "missed_examples": [{"rule_id": rule, "scenario_id": sid} for rule, sid in missed[:50]],
        "excluded_scenarios": sorted(
            {label for label, _ in scenarios if label not in SCENARIO_RULES}
        ),
        "interpretation": (
            "Scenario recall uses distinct (rule, scenario_id) pairs. A finding agrees when "
            "at least one retained evidence event has its expected rule label. Unexpected "
            "means no such labeled evidence, not proven false positive. Truncated evidence "
            "and overlapping behaviors limit this comparison. Malware alerts have no Phase "
            "6 rule. Synthetic coverage does not measure production accuracy."
        ),
    }


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    try:
        settings = get_settings()
    except ValidationError:
        print("Invalid environment configuration.")
        return 1
    if settings.app_env not in {"development", "test"}:
        print("Ground-truth evaluation requires APP_ENV=development or test.")
        return 1
    engine = build_engine(settings)
    try:
        with Session(engine) as session:
            print(json.dumps(evaluate(session), indent=2))
        return 0
    except SQLAlchemyError as exc:
        print(f"Evaluation failed ({type(exc).__name__}); check connectivity and migrations.")
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
