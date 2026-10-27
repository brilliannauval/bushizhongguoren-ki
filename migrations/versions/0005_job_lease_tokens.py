"""Fence background workers with per-claim lease tokens.

Revision ID: 0005_job_lease_tokens
Revises: 0004_object_cleanup
"""

import sqlalchemy as sa
from alembic import op


revision = "0005_job_lease_tokens"
down_revision = "0004_object_cleanup"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "lease_token" not in {column["name"] for column in inspector.get_columns("jobs")}:
        op.add_column("jobs", sa.Column("lease_token", sa.String(length=36), nullable=True))
    if "lease_token" not in {column["name"] for column in inspector.get_columns("benchmark_runs")}:
        op.add_column("benchmark_runs", sa.Column("lease_token", sa.String(length=36), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "lease_token" in {column["name"] for column in inspector.get_columns("benchmark_runs")}:
        op.drop_column("benchmark_runs", "lease_token")
    if "lease_token" in {column["name"] for column in inspector.get_columns("jobs")}:
        op.drop_column("jobs", "lease_token")
