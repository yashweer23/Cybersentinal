from app.detection.rules.abnormal_api import AbnormalAPI
from app.detection.rules.brute_force import BruteForce
from app.detection.rules.excessive_access import ExcessiveAccess
from app.detection.rules.impossible_travel import ImpossibleTravel
from app.detection.rules.malicious_ip import SuspiciousIP
from app.detection.rules.password_spray import PasswordSpray
from app.detection.rules.privilege_escalation import PrivilegeEscalation
from app.detection.rules.repeated_access_denied import RepeatedDenied
from app.detection.rules.suspicious_ports import SuspiciousPorts
from app.detection.rules.unusual_login import UnusualLogin

RULE_TYPES = {
    cls.rule_id: cls
    for cls in (
        BruteForce,
        PasswordSpray,
        ImpossibleTravel,
        UnusualLogin,
        PrivilegeEscalation,
        SuspiciousPorts,
        ExcessiveAccess,
        SuspiciousIP,
        RepeatedDenied,
        AbnormalAPI,
    )
}
