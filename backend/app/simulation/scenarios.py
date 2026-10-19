"""Pure log-producing scenario functions. No sockets, database, or detection logic."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from math import ceil
from random import Random

from app.simulation.config import SimulationConfig
from app.simulation.constants import (
    API_USER_AGENT,
    LONDON,
    NEW_YORK,
    PORTS,
    SYNTHETIC_THREAT_IPS,
    EventType,
    Scenario,
)
from app.simulation.factory import EventFactory, record_batch
from app.simulation.identities import UserProfile


def episode_sizes(scenario: Scenario, config: SimulationConfig) -> tuple[int, ...]:
    """Legal whole-episode event counts; sensitive records can be batched in a log."""
    match scenario:
        case Scenario.BRUTE_FORCE:
            return tuple(
                range(config.brute_force_min_failures + 1, config.brute_force_max_failures + 2)
            )
        case Scenario.PASSWORD_SPRAY:
            return tuple(
                sorted(
                    {
                        users * attempts
                        for users in range(config.spray_min_users, config.spray_max_users + 1)
                        for attempts in range(1, config.spray_max_attempts + 1)
                    }
                )
            )
        case Scenario.IMPOSSIBLE_TRAVEL:
            return (2,)
        case Scenario.PRIVILEGE_ESCALATION:
            return (4,)
        case Scenario.PORT_ACTIVITY:
            return tuple(range(20, len(PORTS) + 1))
        case Scenario.EXCESSIVE_ACCESS:
            return (ceil(config.excessive_records / config.records_per_event),)
        case Scenario.ABNORMAL_API:
            return tuple(range(config.api_burst_min, config.api_burst_max + 1))
        case Scenario.ACCESS_DENIED:
            return tuple(range(8, 21))
        case Scenario.UNUSUAL_LOGIN | Scenario.MALICIOUS_IP | Scenario.MALWARE_ALERT:
            return (1,)
        case _:
            raise ValueError(f"{scenario} is not a single suspicious scenario")


@dataclass
class Episode:
    factory: EventFactory
    scenario: Scenario
    size: int
    number: int
    profiles: tuple[UserProfile, ...]

    def __post_init__(self):
        self.key = f"episode:{self.scenario.value}:{self.number}"
        self.sid = self.factory.scenario_id(self.key)
        self.rng = Random(f"{self.factory.config.seed}:{self.key}")
        employees = [p for p in self.profiles if p.role == "employee"]
        self.user = self.rng.choice(employees)
        # Office daytime in UTC; even the longest episode fits inside one UTC day.
        self.day = self.rng.randrange(self.config.days)
        self.start = self.config.start + timedelta(
            days=self.day, hours=4, seconds=self.rng.randint(0, 7 * 3600)
        )
        self.source = (
            f"{self.rng.choice(('192.0.2', '198.51.100', '203.0.113'))}.{self.rng.randint(1, 254)}"
        )

    @property
    def config(self):
        return self.factory.config

    def emit(
        self,
        index: int,
        kind: EventType,
        *,
        duration: int = 60,
        timestamp: datetime | None = None,
        user: UserProfile | None = None,
        **kwargs,
    ):
        moment = timestamp or self.start + timedelta(
            seconds=duration * index / max(self.size - 1, 1)
        )
        return self.factory.make(
            key=f"{self.key}:{index}",
            scenario=self.scenario,
            scenario_id=self.sid,
            timestamp=moment,
            user=user or self.user,
            event_type=kind,
            rng=self.rng,
            **kwargs,
        )


def brute_force(episode: Episode):
    for index in range(episode.size):
        kind = EventType.LOGIN_FAILED
        if index == episode.size - 1:
            kind = episode.rng.choices(
                (EventType.ACCOUNT_LOCKED, EventType.LOGIN_SUCCESS), weights=(4, 1), k=1
            )[0]
        # Failed attempts themselves span the configured window; outcome follows one second later.
        seconds = episode.config.brute_force_window_seconds * index / (episode.size - 2)
        if index == episode.size - 1:
            seconds = episode.config.brute_force_window_seconds + 1
        yield episode.emit(
            index,
            kind,
            timestamp=episode.start + timedelta(seconds=seconds),
            source_ip=episode.source,
            device="WS-EXTERNAL-SIM",
            raw={"authentication_method": "password"},
        )


def password_spray(episode: Episode):
    combinations = [
        (users, attempts)
        for users in range(episode.config.spray_min_users, episode.config.spray_max_users + 1)
        for attempts in range(1, episode.config.spray_max_attempts + 1)
        if users * attempts == episode.size
    ]
    user_count, _ = episode.rng.choice(combinations)
    users = episode.rng.sample(episode.profiles, user_count)
    for index in range(episode.size):
        yield episode.emit(
            index,
            EventType.LOGIN_FAILED,
            user=users[index % user_count],
            duration=episode.config.spray_window_seconds,
            source_ip=episode.source,
            device="WS-EXTERNAL-SIM",
            raw={"authentication_method": "password"},
        )


def impossible_travel(episode: Episode):
    yield episode.emit(0, EventType.LOGIN_SUCCESS, location=episode.user.location)
    yield episode.emit(
        1,
        EventType.LOGIN_SUCCESS,
        duration=episode.rng.randint(20, 55) * 60,
        source_ip=episode.source,
        location=episode.rng.choice((LONDON, NEW_YORK)),
        service="vpn",
        device="WS-EXTERNAL-SIM",
    )


def unusual_login(episode: Episode):
    # 20:30..22:59 UTC = 02:00..04:29 India the following local calendar day.
    moment = episode.config.start + timedelta(
        days=episode.day,
        hours=20,
        minutes=30 + episode.rng.randint(0, 149),
        seconds=episode.rng.randint(0, 59),
    )
    yield episode.emit(0, EventType.LOGIN_SUCCESS, timestamp=moment)


def privilege_escalation(episode: Episode):
    for index, kind in enumerate(
        (
            EventType.LOGIN_SUCCESS,
            EventType.ACCESS_DENIED,
            EventType.PRIVILEGE_CHANGE,
            EventType.ADMIN_LOGIN,
        )
    ):
        raw = {"resource": "/admin/users"}
        if kind == EventType.PRIVILEGE_CHANGE:
            raw = {
                "previous_role": "employee",
                "new_role": "administrator",
                "changed_by": episode.user.username,
                "approval_reference": None,
            }
        yield episode.emit(
            index,
            kind,
            duration=180,
            raw=raw,
            service="authentication" if index == 0 else "admin-console",
        )


def port_activity(episode: Episode):
    for index, port in enumerate(episode.rng.sample(PORTS, episode.size)):
        yield episode.emit(
            index,
            EventType.PORT_CONNECTION,
            duration=45,
            source_ip=episode.source,
            service="database",
            destination_port=port,
            device="WS-EXTERNAL-SIM",
            user_agent=API_USER_AGENT,
            status="observed",
            raw={"transport": "tcp", "connection_result": "observed"},
        )


def excessive_access(episode: Episode):
    offset = 0
    for index in range(episode.size):
        count = min(episode.config.records_per_event, episode.config.excessive_records - offset)
        yield episode.emit(
            index,
            EventType.SENSITIVE_RECORD_ACCESS,
            duration=episode.config.excessive_window_seconds,
            service="records-api",
            raw=record_batch(episode.sid, offset, count),
        )
        offset += count


def abnormal_api(episode: Episode):
    for index in range(episode.size):
        limited = index > episode.size * 0.8 and episode.rng.random() < 0.6
        yield episode.emit(
            index,
            EventType.API_REQUEST,
            duration=episode.config.api_burst_window_seconds,
            service="records-api",
            source_ip=episode.source,
            device="WS-EXTERNAL-SIM",
            user_agent=API_USER_AGENT,
            status="rate_limited" if limited else "success",
            raw={
                "method": "GET",
                "endpoint": "/api/records",
                "http_status": 429 if limited else 200,
                "response_time_ms": episode.rng.randint(80, 600),
            },
        )


def access_denied(episode: Episode):
    for index in range(episode.size):
        yield episode.emit(
            index,
            EventType.ACCESS_DENIED,
            duration=90,
            service="admin-console",
            raw={
                "resource": ("/admin/users", "/admin/audit", "/internal/config")[index % 3],
                "reason": "insufficient_role",
            },
        )


def malicious_ip(episode: Episode):
    record = episode.emit(
        0,
        EventType.LOGIN_FAILED,
        source_ip=episode.rng.choice(SYNTHETIC_THREAT_IPS),
        device="WS-EXTERNAL-SIM",
        location=LONDON,
    )
    if episode.config.ground_truth:
        record.event.raw_data["simulation"]["simulation_expected_reputation"] = 92
    yield record


def malware_alert(episode: Episode):
    yield episode.emit(
        0,
        EventType.MALWARE_ALERT,
        service="internal-api",
        raw={
            "detection_source": "simulated_endpoint_security",
            "category": "suspicious_process",
            "action": "quarantined",
            "signature": "SIM-DEMO-001",
        },
    )


BUILDERS = {
    Scenario.BRUTE_FORCE: brute_force,
    Scenario.PASSWORD_SPRAY: password_spray,
    Scenario.IMPOSSIBLE_TRAVEL: impossible_travel,
    Scenario.UNUSUAL_LOGIN: unusual_login,
    Scenario.PRIVILEGE_ESCALATION: privilege_escalation,
    Scenario.PORT_ACTIVITY: port_activity,
    Scenario.EXCESSIVE_ACCESS: excessive_access,
    Scenario.ABNORMAL_API: abnormal_api,
    Scenario.ACCESS_DENIED: access_denied,
    Scenario.MALICIOUS_IP: malicious_ip,
    Scenario.MALWARE_ALERT: malware_alert,
}
