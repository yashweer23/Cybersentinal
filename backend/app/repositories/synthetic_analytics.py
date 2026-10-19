"""Evaluation-only SQL: simulation labels never enter the detection or scoring engines."""

from sqlalchemy import and_, case, func, select

from app.models import DetectionFinding as F
from app.models import DetectionRule as R
from app.models import SecurityEvent as E
from app.repositories.analytics_repository import finding_events
from app.repositories.dashboard_repository import window

SCENARIOS = {
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


def evaluate(session, scope):
    label = E.raw_data["simulation"]["scenario"].astext
    sid = E.raw_data["simulation"]["scenario_id"].astext
    rule = case(SCENARIOS, value=label)
    synthetic = and_(
        sid.is_not(None), E.raw_data["simulation"]["generator_version"].astext.is_not(None)
    )
    expected = (
        select(rule.label("rule"), sid.label("scenario"))
        .where(synthetic, rule.is_not(None), *window(E.timestamp, scope))
        .distinct()
        .cte("expected")
    )
    fe = finding_events(scope)
    evidence = (
        select(
            F.id.label("finding"),
            R.rule_id.label("rule"),
            sid.label("scenario"),
            rule.label("expected_rule"),
        )
        .select_from(fe)
        .join(F, F.id == fe.c.finding_pk)
        .join(R, R.id == F.detection_rule_id)
        .join(E, E.id == fe.c.event_pk)
        .where(synthetic, *window(E.timestamp, scope))
        .cte("synthetic_evidence")
    )
    matches = (
        select(evidence.c.rule, evidence.c.scenario)
        .join(
            expected,
            and_(
                expected.c.rule == evidence.c.rule,
                expected.c.scenario == evidence.c.scenario,
                evidence.c.rule == evidence.c.expected_rule,
            ),
        )
        .distinct()
        .cte("matched")
    )
    counts = (
        session.execute(
            select(
                select(func.count())
                .select_from(expected)
                .scalar_subquery()
                .label("expected_scenarios"),
                select(func.count())
                .select_from(matches)
                .scalar_subquery()
                .label("detected_scenarios"),
                select(func.count(func.distinct(evidence.c.finding)))
                .scalar_subquery()
                .label("findings_evaluated"),
                select(func.count(func.distinct(evidence.c.finding)))
                .where(evidence.c.rule == evidence.c.expected_rule)
                .scalar_subquery()
                .label("agreeing"),
            )
        )
        .mappings()
        .one()
    )
    return dict(counts)
