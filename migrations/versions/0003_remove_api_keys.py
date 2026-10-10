"""Remove API-key storage after narrowing the assignment MVP to web sessions.

Revision ID: 0003_remove_api_keys
Revises: 0002_cleanup_indexes
"""

from alembic import op
import sqlalchemy as sa


revision = "0003_remove_api_keys"
down_revision = "0002_cleanup_indexes"
branch_labels = None
depends_on = None


def upgrade():
    # Existing API keys become invalid when this migration drops their records.
    op.execute("DROP TABLE IF EXISTS api_keys")


def downgrade():
    # A downgrade restores the empty table shape; removed key secrets cannot be restored.
    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("secret_digest", sa.LargeBinary(length=32), nullable=False, unique=True),
        sa.Column("level", sa.String(length=32), nullable=False),
        sa.Column("scopes", sa.String(length=256), nullable=False),
        sa.Column("pepper_version", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])
    op.create_index("ix_api_keys_owner_revoked", "api_keys", ["user_id", "revoked_at"])
