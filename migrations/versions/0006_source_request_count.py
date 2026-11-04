"""Account per-page outbound requests for paged ATS source hourly budgets."""

from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("fetch_attempts", sa.Column(
        "request_count", sa.Integer(), nullable=False, server_default="1",
    ))


def downgrade():
    op.drop_column("fetch_attempts", "request_count")
