"""create core cybersentinel tables

Revision ID: 0001_core
Revises:
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001_core"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen definitions: migrations never import the application's evolving ORM models.
USER_ROLE = postgresql.ENUM("ADMIN", "ANALYST", "VIEWER", name="user_role", create_type=False)
SEVERITY = postgresql.ENUM(
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
    name="severity_level",
    create_type=False,
)
STATUS = postgresql.ENUM(
    "OPEN",
    "INVESTIGATING",
    "RESOLVED",
    "FALSE_POSITIVE",
    name="incident_status",
    create_type=False,
)
INDICATOR = postgresql.ENUM("IP", "DOMAIN", name="indicator_type", create_type=False)


def upgrade() -> None:
    for native_enum in (USER_ROLE, SEVERITY, STATUS, INDICATOR):
        native_enum.create(op.get_bind(), checkfirst=False)
    op.create_table(
        "detection_rules",
        sa.Column("rule_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", SEVERITY, nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "configuration",
            postgresql.JSONB(none_as_null=True, astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "jsonb_typeof(configuration) = 'object'",
            name=op.f("ck_detection_rules_configuration_object"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detection_rules")),
        sa.UniqueConstraint("rule_id", name=op.f("uq_detection_rules_rule_id")),
    )
    op.create_table(
        "security_events",
        sa.Column("event_id", sa.String(length=128), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", postgresql.INET(), nullable=False),
        sa.Column("destination_ip", postgresql.INET(), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("service", sa.String(length=100), nullable=True),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("country", sa.String(length=100), nullable=True),
        sa.Column("device", sa.String(length=255), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column(
            "raw_data",
            postgresql.JSONB(none_as_null=True, astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("processed", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "jsonb_typeof(raw_data) = 'object'", name=op.f("ck_security_events_raw_data_object")
        ),
        sa.CheckConstraint(
            "destination_port BETWEEN 0 AND 65535",
            name=op.f("ck_security_events_destination_port_range"),
        ),
        sa.CheckConstraint(
            "source_port BETWEEN 0 AND 65535", name=op.f("ck_security_events_source_port_range")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_events")),
        sa.UniqueConstraint("event_id", name=op.f("uq_security_events_event_id")),
    )
    op.create_index(
        op.f("ix_security_events_event_type"), "security_events", ["event_type"], unique=False
    )
    op.create_index(
        op.f("ix_security_events_processed"), "security_events", ["processed"], unique=False
    )
    op.create_index(
        op.f("ix_security_events_source_ip"), "security_events", ["source_ip"], unique=False
    )
    op.create_index(
        op.f("ix_security_events_timestamp"), "security_events", ["timestamp"], unique=False
    )
    op.create_index(
        op.f("ix_security_events_username"), "security_events", ["username"], unique=False
    )
    op.create_table(
        "system_metrics",
        sa.Column("metric_name", sa.String(length=100), nullable=False),
        sa.Column("metric_value", sa.Numeric(precision=20, scale=6), nullable=False),
        sa.Column("unit", sa.String(length=32), nullable=False),
        sa.Column(
            "timestamp", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "metadata",
            postgresql.JSONB(none_as_null=True, astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.CheckConstraint(
            "jsonb_typeof(metadata) = 'object'", name=op.f("ck_system_metrics_metadata_object")
        ),
        sa.CheckConstraint(
            "metric_value <> 'NaN'::numeric", name=op.f("ck_system_metrics_metric_value_finite")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_system_metrics")),
    )
    op.create_index(
        "ix_system_metrics_name_timestamp",
        "system_metrics",
        ["metric_name", "timestamp"],
        unique=False,
    )
    op.create_table(
        "threat_intelligence",
        sa.Column("indicator", sa.String(length=253), nullable=False),
        sa.Column("indicator_type", INDICATOR, nullable=False),
        sa.Column("malicious", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("abuse_score", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "confidence_score",
            sa.Numeric(precision=5, scale=2),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("reports", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("country", sa.String(length=100), nullable=True),
        sa.Column("isp", sa.String(length=255), nullable=True),
        sa.Column(
            "source",
            postgresql.JSONB(none_as_null=True, astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "raw_response",
            postgresql.JSONB(none_as_null=True, astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_checked",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.CheckConstraint(
            "CASE WHEN indicator_type = 'IP' THEN indicator = host(indicator::inet) "
            "ELSE indicator = lower(btrim(indicator)) AND right(indicator, 1) <> '.' END",
            name=op.f("ck_threat_intelligence_indicator_canonical"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(raw_response) = 'object'",
            name=op.f("ck_threat_intelligence_raw_response_object"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(source) = 'array'", name=op.f("ck_threat_intelligence_source_array")
        ),
        sa.CheckConstraint(
            "abuse_score BETWEEN 0 AND 100", name=op.f("ck_threat_intelligence_abuse_score_range")
        ),
        sa.CheckConstraint(
            "confidence_score BETWEEN 0 AND 100",
            name=op.f("ck_threat_intelligence_confidence_score_range"),
        ),
        sa.CheckConstraint(
            "expires_at > last_checked", name=op.f("ck_threat_intelligence_cache_expiry")
        ),
        sa.CheckConstraint(
            "first_seen <= last_checked", name=op.f("ck_threat_intelligence_seen_before_checked")
        ),
        sa.CheckConstraint("reports >= 0", name=op.f("ck_threat_intelligence_reports_nonnegative")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_intelligence")),
        sa.UniqueConstraint(
            "indicator_type", "indicator", name="uq_threat_intelligence_type_indicator"
        ),
    )
    op.create_index(
        op.f("ix_threat_intelligence_expires_at"),
        "threat_intelligence",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_threat_intelligence_indicator"), "threat_intelligence", ["indicator"], unique=False
    )
    op.create_table(
        "users",
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=150), nullable=True),
        sa.Column("role", USER_ROLE, server_default=sa.text("'VIEWER'"), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("email = lower(btrim(email))", name=op.f("ck_users_email_normalized")),
        sa.CheckConstraint(
            "length(hashed_password) >= 20", name=op.f("ck_users_password_hash_length")
        ),
        sa.CheckConstraint(
            "length(username) BETWEEN 3 AND 64", name=op.f("ck_users_username_length")
        ),
        sa.CheckConstraint(
            "username = lower(btrim(username))", name=op.f("ck_users_username_normalized")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
        sa.UniqueConstraint("username", name=op.f("uq_users_username")),
    )
    op.create_table(
        "audit_logs",
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("entity_type", sa.String(length=100), nullable=False),
        sa.Column("entity_id", sa.String(length=128), nullable=False),
        sa.Column(
            "old_value", postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True
        ),
        sa.Column(
            "new_value", postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True
        ),
        sa.Column(
            "timestamp", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_audit_logs_user_id_users"), ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_logs")),
    )
    op.create_index(
        "ix_audit_logs_entity", "audit_logs", ["entity_type", "entity_id"], unique=False
    )
    op.create_index(op.f("ix_audit_logs_timestamp"), "audit_logs", ["timestamp"], unique=False)
    op.create_index(op.f("ix_audit_logs_user_id"), "audit_logs", ["user_id"], unique=False)
    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("detection_rule_id", sa.UUID(), nullable=False),
        sa.Column("source_ip", postgresql.INET(), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("severity", SEVERITY, nullable=False),
        sa.Column("confidence", sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column("status", STATUS, server_default=sa.text("'OPEN'"), nullable=False),
        sa.Column("assigned_analyst_id", sa.UUID(), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "ai_analysis", postgresql.JSONB(none_as_null=True, astext_type=sa.Text()), nullable=True
        ),
        sa.Column(
            "recommended_actions",
            postgresql.JSONB(none_as_null=True, astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "ai_analysis IS NULL OR jsonb_typeof(ai_analysis) = 'object'",
            name=op.f("ck_incidents_ai_analysis_object"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(recommended_actions) = 'array'",
            name=op.f("ck_incidents_recommended_actions_array"),
        ),
        sa.CheckConstraint(
            "confidence BETWEEN 0 AND 100", name=op.f("ck_incidents_confidence_range")
        ),
        sa.CheckConstraint(
            "resolved_at IS NULL OR resolved_at >= detected_at",
            name=op.f("ck_incidents_resolution_time"),
        ),
        sa.CheckConstraint(
            "risk_score BETWEEN 0 AND 100", name=op.f("ck_incidents_risk_score_range")
        ),
        sa.ForeignKeyConstraint(
            ["assigned_analyst_id"],
            ["users.id"],
            name=op.f("fk_incidents_assigned_analyst_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["detection_rule_id"],
            ["detection_rules.id"],
            name=op.f("fk_incidents_detection_rule_id_detection_rules"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incidents")),
        sa.UniqueConstraint("incident_id", name=op.f("uq_incidents_incident_id")),
    )
    op.create_index(
        op.f("ix_incidents_assigned_analyst_id"), "incidents", ["assigned_analyst_id"], unique=False
    )
    op.create_index(op.f("ix_incidents_detected_at"), "incidents", ["detected_at"], unique=False)
    op.create_index(
        op.f("ix_incidents_detection_rule_id"), "incidents", ["detection_rule_id"], unique=False
    )
    op.create_index(op.f("ix_incidents_risk_score"), "incidents", ["risk_score"], unique=False)
    op.create_index(op.f("ix_incidents_severity"), "incidents", ["severity"], unique=False)
    op.create_index(op.f("ix_incidents_source_ip"), "incidents", ["source_ip"], unique=False)
    op.create_index(op.f("ix_incidents_status"), "incidents", ["status"], unique=False)
    op.create_table(
        "incident_comments",
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("comment", sa.Text(), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(btrim(comment)) > 0", name=op.f("ck_incident_comments_comment_nonempty")
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_incident_comments_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_incident_comments_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_comments")),
    )
    op.create_index(
        op.f("ix_incident_comments_incident_id"), "incident_comments", ["incident_id"], unique=False
    )
    op.create_index(
        op.f("ix_incident_comments_user_id"), "incident_comments", ["user_id"], unique=False
    )
    op.create_table(
        "incident_evidence",
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("security_event_id", sa.UUID(), nullable=False),
        sa.Column("evidence_type", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "evidence_data",
            postgresql.JSONB(none_as_null=True, astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "jsonb_typeof(evidence_data) = 'object'",
            name=op.f("ck_incident_evidence_evidence_data_object"),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_incident_evidence_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["security_event_id"],
            ["security_events.id"],
            name=op.f("fk_incident_evidence_security_event_id_security_events"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_evidence")),
        sa.UniqueConstraint(
            "incident_id",
            "security_event_id",
            "evidence_type",
            name=op.f("uq_incident_evidence_incident_id"),
        ),
    )
    op.create_index(
        op.f("ix_incident_evidence_incident_id"), "incident_evidence", ["incident_id"], unique=False
    )
    op.create_index(
        op.f("ix_incident_evidence_security_event_id"),
        "incident_evidence",
        ["security_event_id"],
        unique=False,
    )
    op.execute("""
        CREATE FUNCTION touch_updated_at() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            NEW.updated_at := statement_timestamp();
            RETURN NEW;
        END;
        $$;
    """)
    for table in ("users", "detection_rules", "incidents", "incident_comments"):
        op.execute(
            f"CREATE TRIGGER trg_{table}_updated_at BEFORE UPDATE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION touch_updated_at()"
        )


def downgrade() -> None:
    # Table removal also removes their indexes, constraints and update triggers.
    op.drop_index(op.f("ix_incident_evidence_security_event_id"), table_name="incident_evidence")
    op.drop_index(op.f("ix_incident_evidence_incident_id"), table_name="incident_evidence")
    op.drop_table("incident_evidence")
    op.drop_index(op.f("ix_incident_comments_user_id"), table_name="incident_comments")
    op.drop_index(op.f("ix_incident_comments_incident_id"), table_name="incident_comments")
    op.drop_table("incident_comments")
    op.drop_index(op.f("ix_incidents_status"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_source_ip"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_severity"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_risk_score"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_detection_rule_id"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_detected_at"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_assigned_analyst_id"), table_name="incidents")
    op.drop_table("incidents")
    op.drop_index(op.f("ix_audit_logs_user_id"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_timestamp"), table_name="audit_logs")
    op.drop_index("ix_audit_logs_entity", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_table("users")
    op.drop_index(op.f("ix_threat_intelligence_indicator"), table_name="threat_intelligence")
    op.drop_index(op.f("ix_threat_intelligence_expires_at"), table_name="threat_intelligence")
    op.drop_table("threat_intelligence")
    op.drop_index("ix_system_metrics_name_timestamp", table_name="system_metrics")
    op.drop_table("system_metrics")
    op.drop_index(op.f("ix_security_events_username"), table_name="security_events")
    op.drop_index(op.f("ix_security_events_timestamp"), table_name="security_events")
    op.drop_index(op.f("ix_security_events_source_ip"), table_name="security_events")
    op.drop_index(op.f("ix_security_events_processed"), table_name="security_events")
    op.drop_index(op.f("ix_security_events_event_type"), table_name="security_events")
    op.drop_table("security_events")
    op.drop_table("detection_rules")
    op.execute("DROP FUNCTION touch_updated_at()")
    for native_enum in (INDICATOR, STATUS, SEVERITY, USER_ROLE):
        native_enum.drop(op.get_bind(), checkfirst=False)
