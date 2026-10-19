"""One deliberately replaceable assessment per finding and algorithm version."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import SeverityLevel
from app.database import Base
from app.models.common import JSON_OBJECT, SEVERITY_LEVEL, CreatedAt, UUIDPrimaryKey
from app.models.detection_finding import DetectionFinding


class RiskAssessment(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "risk_assessments"
    __table_args__ = (
        UniqueConstraint("detection_finding_id", "score_version", name="uq_risk_finding_version"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score_range"),
        CheckConstraint("severity_score BETWEEN 0 AND 25", name="severity_score_range"),
        CheckConstraint("confidence_score BETWEEN 0 AND 15", name="confidence_score_range"),
        CheckConstraint("behavioural_score BETWEEN 0 AND 20", name="behavioural_score_range"),
        CheckConstraint("frequency_score BETWEEN 0 AND 15", name="frequency_score_range"),
        CheckConstraint("asset_sensitivity_score BETWEEN 0 AND 15", name="sensitivity_score_range"),
        CheckConstraint("reputation_score BETWEEN 0 AND 10", name="reputation_score_range"),
        CheckConstraint(
            "risk_score = severity_score + confidence_score + behavioural_score + "
            "frequency_score + asset_sensitivity_score + reputation_score",
            name="component_sum",
        ),
        CheckConstraint(
            "risk_level::text = CASE WHEN risk_score < 25 THEN 'LOW' "
            "WHEN risk_score < 50 THEN 'MEDIUM' WHEN risk_score < 75 THEN 'HIGH' "
            "ELSE 'CRITICAL' END",
            name="level_matches_score",
        ),
        CheckConstraint(
            "jsonb_typeof(breakdown) = 'object' AND breakdown ?& "
            "ARRAY['severity','confidence','behavioural_intensity',"
            "'event_frequency','asset_sensitivity','reputation']",
            name="breakdown_object",
        ),
        CheckConstraint(
            "COALESCE("
            "jsonb_typeof(breakdown->'severity'->'points') = 'number' AND "
            "(breakdown->'severity'->>'points')::numeric = severity_score AND "
            "(breakdown->'severity'->>'max')::numeric = 25 AND "
            "jsonb_typeof(breakdown->'severity'->'reason') = 'string' AND "
            "length(btrim(breakdown->'severity'->>'reason')) > 0"
            ", false)",
            name="explain_severity",
        ),
        CheckConstraint(
            "COALESCE("
            "jsonb_typeof(breakdown->'confidence'->'points') = 'number' AND "
            "(breakdown->'confidence'->>'points')::numeric = confidence_score AND "
            "(breakdown->'confidence'->>'max')::numeric = 15 AND "
            "jsonb_typeof(breakdown->'confidence'->'reason') = 'string' AND "
            "length(btrim(breakdown->'confidence'->>'reason')) > 0"
            ", false)",
            name="explain_confidence",
        ),
        CheckConstraint(
            "COALESCE("
            "jsonb_typeof(breakdown->'behavioural_intensity'->'points') = 'number' AND "
            "(breakdown->'behavioural_intensity'->>'points')::numeric = behavioural_score AND "
            "(breakdown->'behavioural_intensity'->>'max')::numeric = 20 AND "
            "jsonb_typeof(breakdown->'behavioural_intensity'->'reason') = 'string' AND "
            "length(btrim(breakdown->'behavioural_intensity'->>'reason')) > 0"
            ", false)",
            name="explain_behavioural_intensity",
        ),
        CheckConstraint(
            "COALESCE("
            "jsonb_typeof(breakdown->'event_frequency'->'points') = 'number' AND "
            "(breakdown->'event_frequency'->>'points')::numeric = frequency_score AND "
            "(breakdown->'event_frequency'->>'max')::numeric = 15 AND "
            "jsonb_typeof(breakdown->'event_frequency'->'reason') = 'string' AND "
            "length(btrim(breakdown->'event_frequency'->>'reason')) > 0"
            ", false)",
            name="explain_event_frequency",
        ),
        CheckConstraint(
            "COALESCE("
            "jsonb_typeof(breakdown->'asset_sensitivity'->'points') = 'number' AND "
            "(breakdown->'asset_sensitivity'->>'points')::numeric = asset_sensitivity_score AND "
            "(breakdown->'asset_sensitivity'->>'max')::numeric = 15 AND "
            "jsonb_typeof(breakdown->'asset_sensitivity'->'reason') = 'string' AND "
            "length(btrim(breakdown->'asset_sensitivity'->>'reason')) > 0"
            ", false)",
            name="explain_asset_sensitivity",
        ),
        CheckConstraint(
            "COALESCE("
            "jsonb_typeof(breakdown->'reputation'->'points') = 'number' AND "
            "(breakdown->'reputation'->>'points')::numeric = reputation_score AND "
            "(breakdown->'reputation'->>'max')::numeric = 10 AND "
            "jsonb_typeof(breakdown->'reputation'->'reason') = 'string' AND "
            "length(btrim(breakdown->'reputation'->>'reason')) > 0"
            ", false)",
            name="explain_reputation",
        ),
        CheckConstraint("input_hash ~ '^[0-9a-f]{64}$'", name="input_hash_format"),
        CheckConstraint("config_hash ~ '^[0-9a-f]{64}$'", name="config_hash_format"),
        Index("ix_risk_version_score_time", "score_version", "risk_score", "calculated_at"),
        Index("ix_risk_level", "risk_level"),
        Index("ix_risk_calculated_at", "calculated_at"),
    )
    assessment_id: Mapped[str] = mapped_column(String(64), unique=True)
    detection_finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("detection_findings.id", ondelete="RESTRICT")
    )
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[SeverityLevel] = mapped_column(SEVERITY_LEVEL)
    score_version: Mapped[str] = mapped_column(String(32))
    severity_score: Mapped[int] = mapped_column(Integer)
    confidence_score: Mapped[int] = mapped_column(Integer)
    behavioural_score: Mapped[int] = mapped_column(Integer)
    frequency_score: Mapped[int] = mapped_column(Integer)
    asset_sensitivity_score: Mapped[int] = mapped_column(Integer)
    reputation_score: Mapped[int] = mapped_column(Integer)
    breakdown: Mapped[dict[str, Any]] = mapped_column(JSON_OBJECT)
    config_hash: Mapped[str] = mapped_column(String(64))
    input_hash: Mapped[str] = mapped_column(String(64))
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finding: Mapped[DetectionFinding] = relationship(lazy="joined")
