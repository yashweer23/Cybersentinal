"""Mode-separated reputation cache bundles and provider-wide cooldowns.

Revision ID: 0006_threat_intelligence
Revises: 0005_incident_workflow
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0006_threat_intelligence"
down_revision = "0005_incident_workflow"
branch_labels = None
depends_on = None


def upgrade():
    # UNKNOWN is distinct from false/zero. Preserve all existing non-null values.
    for field in ("malicious", "abuse_score", "confidence_score", "reports"):
        op.alter_column("threat_intelligence", field, nullable=True)
    op.create_table(
        "threat_intelligence_results",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("indicator_id", sa.UUID(), nullable=False),
        sa.Column("mode", sa.String(8), nullable=False),
        sa.Column("reputation_level", sa.String(24), nullable=False),
        sa.Column("normalized_score", sa.Integer(), nullable=True),
        sa.Column("malicious", sa.Boolean(), nullable=True),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("payload", pg.JSONB(none_as_null=True), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["indicator_id"], ["threat_intelligence.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("indicator_id", "mode"),
        sa.CheckConstraint("mode IN ('mock','live')", name="mode_valid"),
        sa.CheckConstraint(
            "reputation_level IN ('MALICIOUS','SUSPICIOUS','NO_ADVERSE_SIGNALS','UNKNOWN')",
            name="reputation_valid",
        ),
        sa.CheckConstraint("normalized_score BETWEEN 0 AND 100", name="score_range"),
        sa.CheckConstraint("jsonb_typeof(payload) = 'object'", name="payload_object"),
        sa.CheckConstraint("policy_hash ~ '^[0-9a-f]{64}$'", name="policy_hash_format"),
    )
    op.create_index(
        "ix_threat_intelligence_results_expires_at", "threat_intelligence_results", ["expires_at"]
    )
    op.create_table(
        "threat_provider_state",
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("credential_hash", sa.String(64), nullable=False),
        sa.Column("next_allowed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_status", sa.String(32), nullable=False),
        sa.PrimaryKeyConstraint("provider"),
    )


def downgrade():
    op.drop_table("threat_provider_state")
    op.drop_index(
        "ix_threat_intelligence_results_expires_at", table_name="threat_intelligence_results"
    )
    op.drop_table("threat_intelligence_results")
    # Return to the pre-Phase-9 compatibility representation on deliberate downgrade.
    for field, fallback in (
        ("malicious", "false"),
        ("abuse_score", "0"),
        ("confidence_score", "0"),
        ("reports", "0"),
    ):
        op.execute(
            sa.text(f"UPDATE threat_intelligence SET {field}={fallback} WHERE {field} IS NULL")
        )
        op.alter_column("threat_intelligence", field, nullable=False)
