"""Run from backend: python -m scripts.seed_detection_rules."""

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import build_engine
from app.models import DetectionRule
from app.schemas.detection_rule import DetectionRuleCreate

DEFAULT_RULES = [
    {
        "rule_id": "CS-001",
        "name": "Brute Force Detection",
        "severity": "HIGH",
        "description": "Repeated failed authentication from one IP within a short window.",
        "configuration": {
            "failed_attempt_threshold": 5,
            "window_seconds": 120,
            "multiple_users_escalation_threshold": 2,
        },
    },
    {
        "rule_id": "CS-002",
        "name": "Password Spraying",
        "severity": "HIGH",
        "description": "Failed authentication from one source against many distinct accounts.",
        "configuration": {"distinct_user_threshold": 8, "window_seconds": 300},
    },
    {
        "rule_id": "CS-003",
        "name": "Impossible Travel",
        "severity": "HIGH",
        "description": "Successive logins imply implausible travel using supplied geolocation.",
        "configuration": {"minimum_distance_km": 500, "max_speed_kmh": 900, "window_seconds": 7200},
    },
    {
        "rule_id": "CS-004",
        "name": "Unusual Login Time",
        "severity": "MEDIUM",
        "description": "Authentication falls outside the configured normal activity hours.",
        "configuration": {
            "normal_start_hour": 8,
            "normal_end_hour": 20,
            "timezone": "Asia/Kolkata",
            "event_types": ["LOGIN_SUCCESS", "ADMIN_LOGIN"],
        },
    },
    {
        "rule_id": "CS-005",
        "name": "Privilege Escalation",
        "severity": "CRITICAL",
        "description": "An account receives administrator privileges without a recorded approval.",
        "configuration": {
            "event_type": "PRIVILEGE_CHANGE",
            "target_privileges": ["ADMIN"],
            "require_approval_reference": True,
        },
    },
    {
        "rule_id": "CS-006",
        "name": "Suspicious Port Activity",
        "severity": "HIGH",
        "description": "Connection logs show one source contacting many destination ports.",
        "configuration": {
            "distinct_port_threshold": 20,
            "window_seconds": 60,
            "event_type": "PORT_CONNECTION",
            "passive_only": True,
        },
    },
    {
        "rule_id": "CS-007",
        "name": "Excessive Sensitive Data Access",
        "severity": "HIGH",
        "description": "Sensitive record access by one account exceeds a configured window limit.",
        "configuration": {
            "record_threshold": 500,
            "window_seconds": 1200,
            "event_type": "FILE_ACCESS",
            "sensitive_only": True,
        },
    },
    {
        "rule_id": "CS-008",
        "name": "Known Malicious IP",
        "severity": "CRITICAL",
        "description": (
            "An event source matches the independent local synthetic reputation provider."
        ),
        "configuration": {"abuse_score_threshold": 75, "require_unexpired_cache": True},
    },
    {
        "rule_id": "CS-009",
        "name": "Repeated Access Denied",
        "severity": "MEDIUM",
        "description": "Repeated denied access to protected resources from one source/account.",
        "configuration": {"denied_attempt_threshold": 10, "window_seconds": 300},
    },
    {
        "rule_id": "CS-010",
        "name": "Abnormal API Activity",
        "severity": "HIGH",
        "description": "API request volume from a source/account exceeds a configured threshold.",
        "configuration": {"request_threshold": 200, "window_seconds": 60, "baseline_multiplier": 5},
    },
]


def seed_detection_rules(session: Session) -> int:
    """Insert missing definitions only; do not overwrite later configuration edits."""
    values = [DetectionRuleCreate(**rule).model_dump() for rule in DEFAULT_RULES]
    statement = (
        insert(DetectionRule)
        .values(values)
        .on_conflict_do_nothing(
            index_elements=[DetectionRule.rule_id],
        )
        .returning(DetectionRule.id)
    )
    return len(session.scalars(statement).all())


def main() -> int:
    engine = build_engine(get_settings())
    try:
        with Session(engine) as session, session.begin():
            inserted = seed_detection_rules(session)
        print(f"Detection rules: inserted={inserted}, already present={10 - inserted}")
        print("Definitions only; no detection logic is executed.")
        return 0
    except SQLAlchemyError as exc:
        print(
            f"Rule seed failed ({type(exc).__name__}). Check the DB and run alembic upgrade head."
        )
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
