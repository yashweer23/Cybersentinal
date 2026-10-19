from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.enums import IncidentStatus as Status
from app.incidents.correlation import Case, Context, Policy, choose_case, match
from app.incidents.workflow import TRANSITIONS
from app.schemas.incident import CommentRequest, IncidentQuery, IncidentRunRequest, StatusRequest

T = datetime(2026, 10, 2, 12, tzinfo=UTC)
POLICY = Policy(50, 60, 8, 0)
BASE = Context("FIND-1", "employee014", "198.51.100.44", "laptop-14", "CS-001", T, T, T)


def case(context=BASE, **values):
    defaults = dict(
        id=uuid4(),
        incident_id="INC-test",
        first_seen=context.first_seen,
        last_seen=context.last_seen,
        status=Status.OPEN,
        resolved_at=None,
        created_at=T,
        risk_score=70,
        members=[context],
    )
    defaults.update(values)
    return Case(**defaults)


def test_strong_identity_explanation_and_rule_family():
    incoming = replace(
        BASE,
        finding_id="FIND-2",
        rule_id="CS-009",
        first_seen=T + timedelta(minutes=2),
        last_seen=T + timedelta(minutes=3),
    )
    evidence = match(incoming, case(), POLICY, T)
    assert evidence["score"] == 12
    assert evidence["matched_finding_id"] == "FIND-1"
    assert evidence["factors"] == {
        "same_username": 3,
        "same_source_ip": 3,
        "same_device": 2,
        "related_rule": 2,
        "within_case_window": 2,
    }


@pytest.mark.parametrize(
    "incoming",
    [
        replace(BASE, username="other", source_ip="203.0.113.4"),
        replace(BASE, username="other"),  # shared NAT/device cannot override contradictory accounts
        replace(BASE, source_ip="203.0.113.4", device="other"),
        replace(BASE, username=None, device=None),
        replace(BASE, first_seen=T + timedelta(minutes=61), last_seen=T + timedelta(minutes=61)),
        replace(BASE, first_seen=T - timedelta(minutes=61)),
    ],
)
def test_unrelated_or_distant_context_does_not_correlate(incoming):
    assert match(incoming, case(), POLICY, T) is None


def test_same_user_device_can_correlate_different_ip():
    assert match(replace(BASE, source_ip="203.0.113.18"), case(), POLICY, T)["score"] == 9
    assert (
        match(replace(BASE, source_ip="203.0.113.18", rule_id="CS-010"), case(), POLICY, T) is None
    )


def test_full_case_span_prevents_window_chaining():
    existing = case(last_seen=T + timedelta(minutes=55))
    assert match(
        replace(BASE, first_seen=T + timedelta(minutes=60), last_seen=T + timedelta(minutes=60)),
        existing,
        POLICY,
        T,
    )
    assert (
        match(
            replace(
                BASE, first_seen=T + timedelta(minutes=65), last_seen=T + timedelta(minutes=65)
            ),
            existing,
            POLICY,
            T,
        )
        is None
    )


def test_closed_default_and_explicit_reopen_window():
    closed = case(status=Status.RESOLVED, resolved_at=T)
    incoming = replace(BASE, created_at=T + timedelta(minutes=1))
    assert match(incoming, closed, POLICY, T + timedelta(minutes=2)) is None
    enabled = replace(POLICY, reopen_minutes=10)
    assert match(incoming, closed, enabled, T + timedelta(minutes=2))
    assert match(incoming, closed, enabled, T + timedelta(minutes=11)) is None
    assert match(BASE, closed, enabled, T + timedelta(minutes=2)) is None
    closed.status = Status.FALSE_POSITIVE
    assert match(incoming, closed, enabled, T + timedelta(minutes=2)) is None


def test_tie_breaking_and_policy_fingerprints():
    first, second = case(), case(created_at=T + timedelta(seconds=1))
    assert choose_case(BASE, [second, first], POLICY, T)[0].id == first.id
    assert len(POLICY.fingerprint) == 64 and POLICY.fingerprint == replace(POLICY).fingerprint
    assert POLICY.fingerprint != replace(POLICY, minimum_risk=51).fingerprint


@pytest.mark.parametrize(
    "body",
    [
        {"status": "RESOLVED"},
        {"status": "RESOLVED", "resolution_summary": "   "},
        {"status": "FALSE_POSITIVE"},
        {"status": "FALSE_POSITIVE", "reason": " "},
        {"status": "INVALID"},
    ],
)
def test_terminal_status_requires_valid_note(body):
    with pytest.raises(ValidationError):
        StatusRequest(**body)


@pytest.mark.parametrize(
    "body",
    [
        {"minimum_risk": -1},
        {"minimum_risk": 101},
        {"minimum_risk": True},
        {"batch_size": 0},
        {"batch_size": 501},
        {"finding": ""},
    ],
)
def test_processing_input_bounds(body):
    with pytest.raises(ValidationError):
        IncidentRunRequest(**body)


def test_queries_comments_and_transition_matrix():
    with pytest.raises(ValidationError):
        IncidentQuery(minimum_risk=90, maximum_risk=20)
    with pytest.raises(ValidationError):
        IncidentQuery(start_time=T, end_time=T - timedelta(seconds=1))
    with pytest.raises(ValidationError):
        CommentRequest(comment="   ")
    assert CommentRequest(comment="  Review complete  ").comment == "Review complete"
    assert TRANSITIONS[Status.OPEN] == {Status.INVESTIGATING, Status.FALSE_POSITIVE}
    assert TRANSITIONS[Status.INVESTIGATING] == {Status.RESOLVED, Status.FALSE_POSITIVE}
    assert (
        TRANSITIONS[Status.RESOLVED] == TRANSITIONS[Status.FALSE_POSITIVE] == {Status.INVESTIGATING}
    )
