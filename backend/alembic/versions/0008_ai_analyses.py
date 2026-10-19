"""Versioned evidence-grounded analyst explanations.

Revision ID: 0008_ai_analyses
Revises: 0007_dashboard_polling
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0008_ai_analyses"
down_revision = "0007_dashboard_polling"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ai_analyses",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
        ),
        sa.Column("analysis_id", sa.String(64), nullable=False),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model", sa.String(100)),
        sa.Column("analysis_mode", sa.String(16), nullable=False),
        sa.Column("context_version", sa.String(16), nullable=False),
        sa.Column("context_hash", sa.String(64), nullable=False),
        sa.Column("config_hash", sa.String(64), nullable=False),
        sa.Column("response", postgresql.JSONB(none_as_null=True), nullable=False),
        sa.Column(
            "generated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.clock_timestamp(),
            nullable=False,
        ),
        sa.Column(
            "generated_by_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.UniqueConstraint("analysis_id", name="uq_ai_analyses_analysis_id"),
        sa.CheckConstraint("analysis_mode IN ('AI','FALLBACK')", name="mode_valid"),
        sa.CheckConstraint("context_hash ~ '^[0-9a-f]{64}$'", name="context_hash_format"),
        sa.CheckConstraint("config_hash ~ '^[0-9a-f]{64}$'", name="config_hash_format"),
        sa.CheckConstraint("jsonb_typeof(response) = 'object'", name="response_object"),
    )
    op.create_index(
        "ix_ai_analyses_incident_generated", "ai_analyses", ["incident_id", "generated_at"]
    )
    op.create_index(
        "ix_ai_analyses_cache", "ai_analyses", ["incident_id", "context_hash", "config_hash"]
    )


def downgrade():
    op.drop_table("ai_analyses")
