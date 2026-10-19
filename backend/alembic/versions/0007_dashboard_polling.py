"""Commit-ordered event polling without changing existing event UUIDs.

Revision ID: 0007_dashboard_polling
Revises: 0006_threat_intelligence
"""

import sqlalchemy as sa

from alembic import op

revision = "0007_dashboard_polling"
down_revision = "0006_threat_intelligence"
branch_labels = None
depends_on = None


def upgrade():
    # The existing connection's 3s statement budget is inappropriate for a large backfill.
    # This local setting lasts only for the migration transaction.
    op.execute("SET LOCAL statement_timeout = '60s'")
    op.add_column(
        "security_events", sa.Column("ingestion_sequence", sa.BigInteger(), nullable=True)
    )
    op.execute("""
        WITH ordered AS (
            SELECT id, row_number() OVER (ORDER BY created_at, id) AS position
            FROM security_events
        )
        UPDATE security_events AS e SET ingestion_sequence = ordered.position
        FROM ordered WHERE e.id = ordered.id
    """)
    op.execute("CREATE SEQUENCE security_events_ingestion_sequence_seq AS bigint CACHE 1")
    op.execute("""
        SELECT setval('security_events_ingestion_sequence_seq',
            COALESCE((SELECT max(ingestion_sequence) FROM security_events), 0) + 1, false)
    """)
    op.execute("""
        ALTER SEQUENCE security_events_ingestion_sequence_seq
        OWNED BY security_events.ingestion_sequence
    """)
    op.alter_column("security_events", "ingestion_sequence", nullable=False)
    op.create_unique_constraint(
        "uq_security_events_ingestion_sequence", "security_events", ["ingestion_sequence"]
    )
    op.create_check_constraint(
        "ingestion_sequence_positive", "security_events", "ingestion_sequence > 0"
    )
    # A sequence alone can skip a late COMMIT. Serialize writers before allocating numbers.
    # Row-level triggers also cover direct SQL/ORM inserts and ON CONFLICT ingestion.
    op.execute("""
        CREATE FUNCTION assign_event_ingestion_sequence() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'UPDATE' THEN
                IF NEW.ingestion_sequence IS DISTINCT FROM OLD.ingestion_sequence THEN
                    RAISE EXCEPTION 'Event ingestion sequence is immutable';
                END IF;
                RETURN NEW;
            END IF;
            PERFORM pg_advisory_xact_lock(112953, 10);
            NEW.ingestion_sequence := nextval(
                format('%I.security_events_ingestion_sequence_seq', TG_TABLE_SCHEMA)::regclass
            );
            RETURN NEW;
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER assign_event_ingestion_sequence
        BEFORE INSERT OR UPDATE OF ingestion_sequence ON security_events
        FOR EACH ROW EXECUTE FUNCTION assign_event_ingestion_sequence()
    """)


def downgrade():
    op.execute("DROP TRIGGER assign_event_ingestion_sequence ON security_events")
    op.execute("DROP FUNCTION assign_event_ingestion_sequence()")
    op.drop_constraint("uq_security_events_ingestion_sequence", "security_events", type_="unique")
    op.drop_constraint(
        op.f("ck_security_events_ingestion_sequence_positive"), "security_events", type_="check"
    )
    # Owned sequence is dropped with its column.
    op.drop_column("security_events", "ingestion_sequence")
