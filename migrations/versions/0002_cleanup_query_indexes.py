"""Add indexes used by session cleanup and common owner queries.

Revision ID: 0002_cleanup_indexes
Revises: 0001_initial
"""

from alembic import op

revision = "0002_cleanup_indexes"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    # The initial migration builds from current metadata for fresh installs.
    # IF NOT EXISTS also upgrades databases created by an earlier initial build.
    op.create_index("ix_sessions_last_seen", "sessions", ["last_seen_at"], if_not_exists=True)
    op.create_index("ix_items_owner_status", "items", ["owner_id", "status"], if_not_exists=True)
    op.create_index(
        "ix_items_owner_kind_status_created",
        "items",
        ["owner_id", "kind", "status", "created_at"],
        if_not_exists=True,
    )


def downgrade():
    op.drop_index("ix_items_owner_kind_status_created", table_name="items", if_exists=True)
    op.drop_index("ix_items_owner_status", table_name="items", if_exists=True)
    op.drop_index("ix_sessions_last_seen", table_name="sessions", if_exists=True)
