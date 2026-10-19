from dataclasses import dataclass
from datetime import timedelta, timezone
from enum import StrEnum

GENERATOR_VERSION = "1"
INDIA_TIME = timezone(timedelta(hours=5, minutes=30), name="Asia/Kolkata")
PRESETS = {"small": 1_000, "medium": 10_000, "large": 100_000}


class EventType(StrEnum):
    """Simulator vocabulary; the existing event schema remains extensible strings."""

    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    ACCESS_DENIED = "ACCESS_DENIED"
    FILE_ACCESS = "FILE_ACCESS"
    SENSITIVE_RECORD_ACCESS = "SENSITIVE_RECORD_ACCESS"
    ADMIN_LOGIN = "ADMIN_LOGIN"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    PRIVILEGE_CHANGE = "PRIVILEGE_CHANGE"
    PORT_CONNECTION = "PORT_CONNECTION"
    API_REQUEST = "API_REQUEST"
    MALWARE_ALERT = "MALWARE_ALERT"
    MFA_SUCCESS = "MFA_SUCCESS"
    MFA_FAILED = "MFA_FAILED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"


class Scenario(StrEnum):
    NORMAL = "normal"
    BRUTE_FORCE = "brute_force"
    PASSWORD_SPRAY = "password_spray"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    UNUSUAL_LOGIN = "unusual_login"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PORT_ACTIVITY = "port_activity"
    EXCESSIVE_ACCESS = "excessive_access"
    ABNORMAL_API = "abnormal_api"
    ACCESS_DENIED = "access_denied"
    MALICIOUS_IP = "malicious_ip"
    MALWARE_ALERT = "malware_alert"
    MIXED = "mixed"

    @property
    def label(self) -> str:
        return {self.NORMAL: "normal_activity", self.MALICIOUS_IP: "known_malicious_ip"}.get(
            self, self.value
        )


# Minimum-sized complete episodes are reserved before larger episodes are added.
CORE_SCENARIOS = (
    Scenario.BRUTE_FORCE,
    Scenario.PASSWORD_SPRAY,
    Scenario.IMPOSSIBLE_TRAVEL,
    Scenario.UNUSUAL_LOGIN,
    Scenario.EXCESSIVE_ACCESS,
)
OTHER_SCENARIOS = (
    Scenario.PRIVILEGE_ESCALATION,
    Scenario.PORT_ACTIVITY,
    Scenario.ABNORMAL_API,
    Scenario.ACCESS_DENIED,
    Scenario.MALICIOUS_IP,
    Scenario.MALWARE_ALERT,
)
SCENARIO_WEIGHTS = (3, 2, 1, 1, 2, 1, 2, 3, 2, 1, 1)
SYNTHETIC_THREAT_IPS = ("192.0.2.44", "198.51.100.73", "203.0.113.18")
PORTS = (
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    389,
    443,
    445,
    465,
    587,
    636,
    993,
    995,
    1433,
    1521,
    2049,
    2375,
    3000,
    3306,
    3389,
    4444,
    5000,
    5432,
    5672,
    5900,
    6379,
    6443,
    8000,
    8008,
    8080,
    8081,
    8443,
    8888,
    9000,
    9090,
    9200,
)
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
)
API_USER_AGENT = "CyberSentinel-DemoClient/1.0"
SERVICE_USER_AGENT = "CyberSentinel-InternalService/1.0"
SERVICES = {
    "authentication": ("10.0.10.10", "SRV-AUTH-01", 443),
    "employee-portal": ("10.0.10.11", "SRV-PORTAL-01", 443),
    "records-api": ("10.0.10.15", "SRV-API-01", 443),
    "files-service": ("10.0.10.16", "SRV-FILES-01", 445),
    "admin-console": ("10.0.10.17", "SRV-ADMIN-01", 443),
    "vpn": ("10.0.10.18", "SRV-VPN-01", 443),
    "identity-service": ("10.0.10.19", "SRV-ID-01", 443),
    "database": ("10.0.10.20", "SRV-DB-01", 5432),
    "web-gateway": ("10.0.10.21", "SRV-WEB-01", 443),
    "internal-api": ("10.0.10.22", "SRV-API-02", 443),
}


@dataclass(frozen=True)
class Location:
    city: str
    country: str
    latitude: float
    longitude: float
    code: str


OFFICES = (
    Location("Hyderabad", "India", 17.385, 78.4867, "HYD"),
    Location("Bengaluru", "India", 12.9716, 77.5946, "BLR"),
    Location("Chennai", "India", 13.0827, 80.2707, "CHE"),
    Location("Pune", "India", 18.5204, 73.8567, "PUN"),
    Location("Mumbai", "India", 19.076, 72.8777, "MUM"),
    Location("Delhi", "India", 28.6139, 77.209, "DEL"),
)
LONDON = Location("London", "United Kingdom", 51.5074, -0.1278, "LON")
NEW_YORK = Location("New York", "United States", 40.7128, -74.006, "NYC")
