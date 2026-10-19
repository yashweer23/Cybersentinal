"""Versioned explainable risk assessments, without changing findings or incidents.

Revision ID: 0004_risk_assessments
Revises: 0003_detection_findings
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0004_risk_assessments"
down_revision = "0003_detection_findings"
branch_labels = None
depends_on = None


def upgrade():
    severity = pg.ENUM(
        "LOW", "MEDIUM", "HIGH", "CRITICAL", name="severity_level", create_type=False
    )
    components = {
        "severity_score": 25,
        "confidence_score": 15,
        "behavioural_score": 20,
        "frequency_score": 15,
        "asset_sensitivity_score": 15,
        "reputation_score": 10,
    }
    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("assessment_id", sa.String(64), nullable=False),
        sa.Column("detection_finding_id", sa.UUID(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", severity, nullable=False),
        sa.Column("score_version", sa.String(32), nullable=False),
        *[sa.Column(name, sa.Integer(), nullable=False) for name in components],
        sa.Column("breakdown", pg.JSONB(none_as_null=True), nullable=False),
        sa.Column("config_hash", sa.String(64), nullable=False),
        sa.Column("input_hash", sa.String(64), nullable=False),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_assessments")),
        sa.UniqueConstraint("assessment_id", name=op.f("uq_risk_assessments_assessment_id")),
        sa.UniqueConstraint(
            "detection_finding_id", "score_version", name="uq_risk_finding_version"
        ),
        sa.ForeignKeyConstraint(
            ["detection_finding_id"], ["detection_findings.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score_range"),
        *[
            sa.CheckConstraint(
                f"{name} BETWEEN 0 AND {maximum}",
                name=(
                    "sensitivity_score_range"
                    if name == "asset_sensitivity_score"
                    else name + "_range"
                ),
            )
            for name, maximum in components.items()
        ],
        sa.CheckConstraint(
            "risk_score = severity_score + confidence_score + behavioural_score + "
            "frequency_score + asset_sensitivity_score + reputation_score",
            name="component_sum",
        ),
        sa.CheckConstraint(
            "risk_level::text = CASE WHEN risk_score < 25 THEN 'LOW' "
            "WHEN risk_score < 50 THEN 'MEDIUM' WHEN risk_score < 75 THEN 'HIGH' "
            "ELSE 'CRITICAL' END",
            name="level_matches_score",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(breakdown) = 'object' AND breakdown ?& "
            "ARRAY['severity','confidence','behavioural_intensity',"
            "'event_frequency','asset_sensitivity','reputation']",
            name="breakdown_object",
        ),
        sa.CheckConstraint(
            "COALESCE("
            "jsonb_typeof(breakdown->'severity'->'points') = 'number' AND "
            "(breakdown->'severity'->>'points')::numeric = severity_score AND "
            "(breakdown->'severity'->>'max')::numeric = 25 AND "
            "jsonb_typeof(breakdown->'severity'->'reason') = 'string' AND "
            "length(btrim(breakdown->'severity'->>'reason')) > 0"
            ", false)",
            name="explain_severity",
        ),
        sa.CheckConstraint(
            "COALESCE("
            "jsonb_typeof(breakdown->'confidence'->'points') = 'number' AND "
            "(breakdown->'confidence'->>'points')::numeric = confidence_score AND "
            "(breakdown->'confidence'->>'max')::numeric = 15 AND "
            "jsonb_typeof(breakdown->'confidence'->'reason') = 'string' AND "
            "length(btrim(breakdown->'confidence'->>'reason')) > 0"
            ", false)",
            name="explain_confidence",
        ),
        sa.CheckConstraint(
            "COALESCE("
            "jsonb_typeof(breakdown->'behavioural_intensity'->'points') = 'number' AND "
            "(breakdown->'behavioural_intensity'->>'points')::numeric = behavioural_score AND "
            "(breakdown->'behavioural_intensity'->>'max')::numeric = 20 AND "
            "jsonb_typeof(breakdown->'behavioural_intensity'->'reason') = 'string' AND "
            "length(btrim(breakdown->'behavioural_intensity'->>'reason')) > 0"
            ", false)",
            name="explain_behavioural_intensity",
        ),
        sa.CheckConstraint(
            "COALESCE("
            "jsonb_typeof(breakdown->'event_frequency'->'points') = 'number' AND "
            "(breakdown->'event_frequency'->>'points')::numeric = frequency_score AND "
            "(breakdown->'event_frequency'->>'max')::numeric = 15 AND "
            "jsonb_typeof(breakdown->'event_frequency'->'reason') = 'string' AND "
            "length(btrim(breakdown->'event_frequency'->>'reason')) > 0"
            ", false)",
            name="explain_event_frequency",
        ),
        sa.CheckConstraint(
            "COALESCE("
            "jsonb_typeof(breakdown->'asset_sensitivity'->'points') = 'number' AND "
            "(breakdown->'asset_sensitivity'->>'points')::numeric = asset_sensitivity_score AND "
            "(breakdown->'asset_sensitivity'->>'max')::numeric = 15 AND "
            "jsonb_typeof(breakdown->'asset_sensitivity'->'reason') = 'string' AND "
            "length(btrim(breakdown->'asset_sensitivity'->>'reason')) > 0"
            ", false)",
            name="explain_asset_sensitivity",
        ),
        sa.CheckConstraint(
            "COALESCE("
            "jsonb_typeof(breakdown->'reputation'->'points') = 'number' AND "
            "(breakdown->'reputation'->>'points')::numeric = reputation_score AND "
            "(breakdown->'reputation'->>'max')::numeric = 10 AND "
            "jsonb_typeof(breakdown->'reputation'->'reason') = 'string' AND "
            "length(btrim(breakdown->'reputation'->>'reason')) > 0"
            ", false)",
            name="explain_reputation",
        ),
        sa.CheckConstraint("input_hash ~ '^[0-9a-f]{64}$'", name="input_hash_format"),
        sa.CheckConstraint("config_hash ~ '^[0-9a-f]{64}$'", name="config_hash_format"),
    )
    op.create_index(
        "ix_risk_version_score_time",
        "risk_assessments",
        ["score_version", "risk_score", "calculated_at"],
    )
    op.create_index("ix_risk_level", "risk_assessments", ["risk_level"])
    op.create_index("ix_risk_calculated_at", "risk_assessments", ["calculated_at"])


def downgrade():
    op.drop_table("risk_assessments")
