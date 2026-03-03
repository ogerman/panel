"""merge prod-test heads (subscription_templates merge + tls_min_max_version)

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6, a1e4f7b0c2d3
Create Date: 2026-03-03 23:00:00.000000

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "b2c3d4e5f6a7"
down_revision = ("a1b2c3d4e5f6", "a1e4f7b0c2d3")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
