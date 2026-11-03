"""Separate packaged catalog from per-instance settings and record admin changes."""

from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("sources", sa.Column("origin", sa.String(16), nullable=False,
                                       server_default="official"))
    op.add_column("sources", sa.Column("catalog_revision", sa.String(64), nullable=True))
    op.add_column("sources", sa.Column("overrides", sa.JSON(), nullable=False,
                                       server_default=sa.text("'{}'")))
    op.create_table(
        "source_audits",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("sources.id"), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("before", sa.JSON(), nullable=True),
        sa.Column("after", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_source_audits_source_id", "source_audits", ["source_id"])


def downgrade():
    op.drop_index("ix_source_audits_source_id", table_name="source_audits")
    op.drop_table("source_audits")
    op.drop_column("sources", "overrides")
    op.drop_column("sources", "catalog_revision")
    op.drop_column("sources", "origin")
