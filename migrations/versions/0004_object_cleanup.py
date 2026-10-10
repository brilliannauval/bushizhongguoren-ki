"""Add a retryable ledger for encrypted object deletion.

Revision ID: 0004_object_cleanup
Revises: 0003_remove_api_keys
"""

import sqlalchemy as sa
from alembic import op


revision = "0004_object_cleanup"
down_revision = "0003_remove_api_keys"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if not sa.inspect(bind).has_table("object_cleanup"):
        op.create_table(
            "object_cleanup",
            sa.Column("object_key", sa.String(length=80), primary_key=True),
            sa.Column("owner_id", sa.String(length=36), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    if not sa.inspect(bind).has_index("object_cleanup", "ix_object_cleanup_owner_id"):
        op.create_index("ix_object_cleanup_owner_id", "object_cleanup", ["owner_id"])


def downgrade():
    bind = op.get_bind()
    if sa.inspect(bind).has_table("object_cleanup"):
        op.drop_index("ix_object_cleanup_owner_id", table_name="object_cleanup")
        op.drop_table("object_cleanup")
