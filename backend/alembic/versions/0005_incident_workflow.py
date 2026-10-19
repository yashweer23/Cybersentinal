"""Extend existing incident cases with finding links and independent processing state.

Revision ID: 0005_incident_workflow
Revises: 0004_risk_assessments
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0005_incident_workflow"
down_revision = "0004_risk_assessments"
branch_labels = None
depends_on = None


def upgrade():
    for name in ("first_seen", "last_seen", "risk_updated_at"):
        op.add_column("incidents", sa.Column(name, sa.DateTime(timezone=True), nullable=True))
    op.add_column("incidents", sa.Column("resolution_summary", sa.Text(), nullable=True))
    op.add_column("incidents", sa.Column("risk_score_version", sa.String(32), nullable=True))
    op.execute("UPDATE incidents SET first_seen = detected_at, last_seen = detected_at")
    for name in ("first_seen", "last_seen"):
        op.alter_column("incidents", name, nullable=False)
    op.create_check_constraint("ordered_window", "incidents", "last_seen >= first_seen")
    for name in ("created_at", "username"):
        op.create_index("ix_incidents_" + name, "incidents", [name])
    op.create_table(
        "incident_findings",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("detection_finding_id", sa.UUID(), nullable=False),
        sa.Column(
            "added_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.Column("relationship_reason", sa.Text(), nullable=False),
        sa.Column("correlation_data", pg.JSONB(none_as_null=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["detection_finding_id"], ["detection_findings.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("incident_id", "detection_finding_id"),
        sa.UniqueConstraint("detection_finding_id"),
        sa.CheckConstraint("length(btrim(relationship_reason)) > 0", name="reason_nonempty"),
        sa.CheckConstraint("jsonb_typeof(correlation_data) = 'object'", name="correlation_object"),
    )
    op.create_table(
        "incident_processing",
        sa.Column("detection_finding_id", sa.UUID(), nullable=False),
        sa.Column("risk_input_hash", sa.String(64), nullable=False),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("context_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("detection_finding_id"),
        sa.ForeignKeyConstraint(
            ["detection_finding_id"], ["detection_findings.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint("risk_input_hash ~ '^[0-9a-f]{64}$'", name="risk_hash_format"),
        sa.CheckConstraint("policy_hash ~ '^[0-9a-f]{64}$'", name="policy_hash_format"),
        sa.CheckConstraint("outcome IN ('LINKED', 'DEFERRED')", name="outcome_valid"),
    )
    op.add_column("incident_evidence", sa.Column("detection_finding_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_incident_evidence_detection_finding_id_detection_findings",
        "incident_evidence",
        "detection_findings",
        ["detection_finding_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "ix_incident_evidence_detection_finding_id", "incident_evidence", ["detection_finding_id"]
    )


def downgrade():
    op.drop_index("ix_incident_evidence_detection_finding_id", table_name="incident_evidence")
    op.drop_constraint(
        "fk_incident_evidence_detection_finding_id_detection_findings",
        "incident_evidence",
        type_="foreignkey",
    )
    op.drop_column("incident_evidence", "detection_finding_id")
    op.drop_table("incident_processing")
    op.drop_table("incident_findings")
    for name in ("created_at", "username"):
        op.drop_index("ix_incidents_" + name, table_name="incidents")
    op.drop_constraint(op.f("ck_incidents_ordered_window"), "incidents", type_="check")
    for name in (
        "risk_score_version",
        "resolution_summary",
        "risk_updated_at",
        "last_seen",
        "first_seen",
    ):
        op.drop_column("incidents", name)
