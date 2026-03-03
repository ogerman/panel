"""add tls_min_version and tls_max_version to hosts

Revision ID: a1e4f7b0c2d3
Revises: 2f3179c6dc49
Create Date: 2026-03-04

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "a1e4f7b0c2d3"
down_revision = "2f3179c6dc49"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("hosts", schema=None) as batch_op:
        batch_op.add_column(sa.Column("tls_min_version", sa.String(length=8), nullable=True))
        batch_op.add_column(sa.Column("tls_max_version", sa.String(length=8), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("hosts", schema=None) as batch_op:
        batch_op.drop_column("tls_max_version")
        batch_op.drop_column("tls_min_version")
