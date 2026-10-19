"""Add revocable authentication sessions without changing existing user data.

Revision ID: 0002_auth_sessions
Revises: 0001_core
"""

import sqlalchemy as sa

from alembic import op

revision = "0002_auth_sessions"
down_revision = "0001_core"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("refresh_token_hash", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_used_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_auth_sessions")),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_auth_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "refresh_token_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_auth_sessions_token_hash_format")
        ),
        sa.CheckConstraint(
            "expires_at > created_at", name=op.f("ck_auth_sessions_expiry_after_creation")
        ),
    )
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])
    op.create_index("ix_auth_sessions_expires_at", "auth_sessions", ["expires_at"])


def downgrade() -> None:
    # Existing domain tables/users are preserved. This ends all persisted sessions.
    op.drop_table("auth_sessions")
