"""Immutable detection findings and bounded-window query indexes.

Revision ID: 0003_detection_findings
Revises: 0002_auth_sessions
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0003_detection_findings"
down_revision = "0002_auth_sessions"
branch_labels = None
depends_on = None

INDEXES = {
    "ix_security_events_pending_order": ["processed", "timestamp", "id"],
    "ix_security_events_type_time": ["event_type", "timestamp"],
    "ix_security_events_source_time": ["source_ip", "timestamp"],
    "ix_security_events_user_time": ["username", "timestamp"],
}


def upgrade():
    severity = pg.ENUM(
        "LOW", "MEDIUM", "HIGH", "CRITICAL", name="severity_level", create_type=False
    )
    op.create_table(
        "detection_findings",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("finding_id", sa.String(64), nullable=False),
        sa.Column("detection_rule_id", sa.UUID(), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", severity, nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("source_ip", pg.INET(), nullable=True),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("primary_event_id", sa.UUID(), nullable=False),
        sa.Column("evidence_event_ids", pg.JSONB(none_as_null=True), nullable=False),
        sa.Column("evidence_data", pg.JSONB(none_as_null=True), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("entity_key", sa.String(640), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detection_findings")),
        sa.UniqueConstraint("finding_id", name=op.f("uq_detection_findings_finding_id")),
        sa.UniqueConstraint("fingerprint", name=op.f("uq_detection_findings_fingerprint")),
        sa.ForeignKeyConstraint(["detection_rule_id"], ["detection_rules.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["primary_event_id"], ["security_events.id"], ondelete="RESTRICT"),
        sa.CheckConstraint("confidence BETWEEN 0 AND 100", name="confidence_range"),
        sa.CheckConstraint("event_count > 0", name="positive_event_count"),
        sa.CheckConstraint("last_seen >= first_seen", name="ordered_window"),
        sa.CheckConstraint("fingerprint ~ '^[0-9a-f]{64}$'", name="fingerprint_format"),
        sa.CheckConstraint("jsonb_typeof(evidence_event_ids) = 'array'", name="evidence_array"),
        sa.CheckConstraint("jsonb_typeof(evidence_data) = 'object'", name="evidence_object"),
    )
    for suffix, columns in {
        "rule_seen": ["detection_rule_id", "last_seen"],
        "last_seen": ["last_seen"],
        "severity": ["severity"],
        "source_ip": ["source_ip"],
        "username": ["username"],
    }.items():
        op.create_index("ix_detection_findings_" + suffix, "detection_findings", columns)
    for name, columns in INDEXES.items():
        op.create_index(name, "security_events", columns)
    # Correct only the untouched legacy description; preserve all analyst configuration.
    op.execute(
        sa.text(
            "UPDATE detection_rules SET description = "
            "'An event source matches the independent local synthetic reputation provider.' "
            "WHERE rule_id = 'CS-008' AND description = "
            "'An event source matches a malicious, unexpired reputation cache entry.'"
        )
    )


def downgrade():
    op.drop_table("detection_findings")
    for name in INDEXES:
        op.drop_index(name, table_name="security_events")
