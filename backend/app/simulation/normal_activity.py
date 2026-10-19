"""Bounded-memory, coherent user-day sessions with one sensitive-record budget per day."""

from datetime import UTC, datetime, time, timedelta
from random import Random

from app.simulation.constants import INDIA_TIME, SERVICE_USER_AGENT, EventType, Scenario
from app.simulation.factory import EventFactory, record_batch
from app.simulation.identities import UserProfile


def normal_session(factory: EventFactory, user: UserProfile, day: int, count: int):
    config = factory.config
    key = f"normal:{user.username}:{day}"
    rng = Random(f"{config.seed}:{key}")
    sid = factory.scenario_id(key)
    local_date = config.start_date + timedelta(days=day)
    midnight = datetime.combine(local_date, time(), tzinfo=INDIA_TIME)
    start = (
        midnight + timedelta(minutes=user.normal_start_minute, seconds=rng.randint(0, 59))
    ).astimezone(UTC)
    end = (
        midnight + timedelta(minutes=user.normal_end_minute, seconds=rng.randint(0, 59))
    ).astimezone(UTC)
    device = user.typical_devices[1 if rng.random() < 0.1 else 0]
    login = EventType.ADMIN_LOGIN if user.role == "administrator" else EventType.LOGIN_SUCCESS
    prefix = [login, EventType.MFA_SUCCESS]
    # Isolated typo/retry and MFA retries are benign background, not labelled attacks.
    if count >= 7 and rng.random() < 0.06:
        prefix.insert(0, EventType.LOGIN_FAILED)
    elif count >= 7 and rng.random() < 0.04:
        prefix.insert(1, EventType.MFA_FAILED)
    middle_count = count - len(prefix) - 1
    occasional_seen = set()
    for index in range(count):
        raw = {}
        agent = user.user_agent
        if count < 6:
            # Tiny samples are partial observed activity, not fabricated full sessions.
            kind = EventType.API_REQUEST
            timestamp = start + timedelta(seconds=index * 30)
        elif index < len(prefix):
            kind = prefix[index]
            timestamp = start + timedelta(seconds=index * 8)
        elif index == count - 1:
            kind, timestamp = EventType.LOGOUT, end
        else:
            slot = index - len(prefix)
            essential = (
                EventType.API_REQUEST,
                EventType.FILE_ACCESS,
                EventType.SENSITIVE_RECORD_ACCESS,
            )
            kind = (
                essential[slot]
                if slot < 3
                else rng.choices(
                    (
                        EventType.API_REQUEST,
                        EventType.FILE_ACCESS,
                        EventType.PORT_CONNECTION,
                        EventType.PASSWORD_CHANGE,
                        EventType.ACCESS_DENIED,
                    ),
                    weights=(65, 23, 10, 1, 1),
                    k=1,
                )[0]
            )
            activity_start = start + timedelta(minutes=5)
            activity_end = end - timedelta(minutes=5)
            fraction = (slot + rng.uniform(0.15, 0.85)) / middle_count
            timestamp = activity_start + (activity_end - activity_start) * fraction
        if kind in {EventType.PASSWORD_CHANGE, EventType.ACCESS_DENIED}:
            if kind in occasional_seen:
                kind = EventType.API_REQUEST
            else:
                occasional_seen.add(kind)
        service = "authentication"
        if kind == EventType.API_REQUEST:
            service = rng.choice(user.typical_services)
            raw = {
                "method": "GET",
                "endpoint": rng.choice(("/api/profile", "/api/tasks", "/api/records")),
                "http_status": 200,
                "response_time_ms": rng.randint(18, 180),
            }
        elif kind == EventType.FILE_ACCESS:
            service = "files-service"
            raw = {
                "resource_type": "document",
                "path": f"/shared/team{int(user.internal_ip.rsplit('.', 1)[1]) % 8}/handbook.pdf",
                "operation": "read",
                "sensitive": False,
            }
        elif kind == EventType.SENSITIVE_RECORD_ACCESS:
            service = "records-api"
            raw = record_batch(
                sid, 0, rng.randint(config.normal_records_min, config.normal_records_max)
            )
        elif kind == EventType.PORT_CONNECTION:
            service = "database" if user.role in {"analyst", "administrator"} else "web-gateway"
            agent = SERVICE_USER_AGENT
            raw = {"transport": "tcp", "connection_result": "established"}
        elif kind in {EventType.PASSWORD_CHANGE, EventType.MFA_SUCCESS, EventType.MFA_FAILED}:
            service = "identity-service"
            raw = {"method": "self_service" if kind == EventType.PASSWORD_CHANGE else "totp"}
        elif kind == EventType.ADMIN_LOGIN:
            service = "admin-console"
            raw = {"approval_reference": f"CHG-DEMO-{day + 1:03}"}
        elif kind == EventType.ACCESS_DENIED:
            service, raw = (
                "employee-portal",
                {"resource": "/reports/restricted", "reason": "role_required"},
            )
        yield factory.make(
            key=f"{key}:{index}",
            scenario=Scenario.NORMAL,
            scenario_id=sid,
            timestamp=timestamp,
            user=user,
            event_type=kind,
            rng=rng,
            service=service,
            raw=raw,
            device=device,
            user_agent=agent,
        )
