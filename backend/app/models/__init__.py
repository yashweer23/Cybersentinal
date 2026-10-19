"""Import every mapped model so Alembic sees the complete schema."""

from app.models.ai_analysis import AIAnalysis
from app.models.audit_log import AuditLog
from app.models.auth_session import AuthSession
from app.models.detection_finding import DetectionFinding
from app.models.detection_rule import DetectionRule
from app.models.incident import Incident
from app.models.incident_comment import IncidentComment
from app.models.incident_evidence import IncidentEvidence
from app.models.incident_finding import IncidentFinding
from app.models.incident_processing import IncidentProcessing
from app.models.risk_assessment import RiskAssessment
from app.models.security_event import SecurityEvent
from app.models.system_metric import SystemMetric
from app.models.threat_intelligence import ThreatIntelligence
from app.models.threat_intelligence_result import ThreatIntelligenceResult, ThreatProviderState
from app.models.user import User

__all__ = [
    "AIAnalysis",
    "AuditLog",
    "AuthSession",
    "DetectionRule",
    "DetectionFinding",
    "Incident",
    "IncidentComment",
    "IncidentEvidence",
    "IncidentFinding",
    "IncidentProcessing",
    "SecurityEvent",
    "RiskAssessment",
    "SystemMetric",
    "ThreatIntelligence",
    "ThreatIntelligenceResult",
    "ThreatProviderState",
    "User",
]
