from datetime import UTC, datetime, timedelta

import bcrypt
import pytest
from sqlalchemy import func, select

from app.config import Settings
from app.core.enums import IndicatorType, UserRole
from app.models import DetectionRule, ThreatIntelligence, User
from app.repositories.threat_cache import get_cached_indicator, store_cached_indicator
from app.schemas.threat_intelligence import ThreatIntelligenceCreate
from app.schemas.user import UserResponse
from scripts.seed_demo_users import seed_demo_users
from scripts.seed_detection_rules import seed_detection_rules


def test_rule_seed_is_idempotent_and_preserves_edits(db):
    assert seed_detection_rules(db) == 10
    first = db.scalar(select(DetectionRule).where(DetectionRule.rule_id == "CS-001"))
    first.enabled = False
    first.configuration = {"failed_attempt_threshold": 12, "window_seconds": 180}
    db.flush()
    assert seed_detection_rules(db) == 0
    assert db.scalar(select(func.count()).select_from(DetectionRule)) == 10
    db.refresh(first)
    assert first.enabled is False
    assert first.configuration["failed_attempt_threshold"] == 12


def test_demo_users_use_bcrypt_and_repeat_does_not_reset_passwords(db):
    settings = Settings(_env_file=None, app_env="development")
    passwords = {name: f"only-a-test-{name}-password" for name in ("admin", "analyst", "viewer")}
    assert seed_demo_users(db, settings, passwords) == 3
    assert seed_demo_users(db, settings, {}) == 0
    users = db.scalars(select(User).order_by(User.username)).all()
    assert {user.role for user in users} == {UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER}
    for user in users:
        assert bcrypt.checkpw(passwords[user.username].encode(), user.hashed_password.encode())
        data = UserResponse.model_validate(user).model_dump(mode="json")
        assert "password" not in data and "hashed_password" not in data


def test_demo_seed_refuses_production_before_writing(db):
    with pytest.raises(ValueError, match="only with APP_ENV=development"):
        seed_demo_users(db, Settings(_env_file=None, app_env="production"), {})
    assert db.scalar(select(func.count()).select_from(User)) == 0


def test_demo_seed_rejects_account_identity_collision(db):
    db.add(
        User(
            username="admin",
            email="other@example.test",
            hashed_password="a-database-test-placeholder-hash",
        )
    )
    db.flush()
    with pytest.raises(ValueError, match="conflicts"):
        seed_demo_users(db, Settings(_env_file=None, app_env="development"), {})


@pytest.mark.parametrize(
    "kind,indicator,equivalent,normalized",
    [
        (IndicatorType.IP, "2001:0db8:0000::1", "2001:db8::1", "2001:db8::1"),
        (IndicatorType.DOMAIN, "EXAMPLE.TEST.", "example.test", "example.test"),
    ],
)
def test_cache_upsert_expiry_and_stale_response_handling(
    db, kind, indicator, equivalent, normalized
):
    now = datetime.now(UTC)
    first = ThreatIntelligenceCreate(
        indicator=indicator,
        indicator_type=kind,
        first_seen=now,
        last_checked=now,
        expires_at=now + timedelta(hours=1),
        abuse_score=10,
        source=["fixture"],
    )
    original = store_cached_indicator(db, first)
    original_id = original.id
    second = ThreatIntelligenceCreate(
        **{
            **first.model_dump(),
            "indicator": equivalent,
            "abuse_score": 90,
            "last_checked": now + timedelta(minutes=1),
            "first_seen": now + timedelta(minutes=1),
        },
    )
    updated = store_cached_indicator(db, second)
    assert updated.id == original_id
    assert updated.indicator == normalized
    assert updated.first_seen == now
    assert updated.abuse_score == 90
    stale = store_cached_indicator(db, first)
    assert stale.abuse_score == 90
    assert db.scalar(select(func.count()).select_from(ThreatIntelligence)) == 1
    assert get_cached_indicator(db, indicator, kind, at=now).id == original_id
    assert get_cached_indicator(db, indicator, kind, at=now + timedelta(hours=2)) is None
