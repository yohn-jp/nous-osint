from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("items", sa.Column("organization", sa.String(length=200), nullable=True))
    op.add_column("items", sa.Column("published_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("items", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_items_organization", "items", ["organization"])
    op.create_index("ix_items_published_at", "items", ["published_at"])

def downgrade():
    op.drop_index("ix_items_published_at", table_name="items")
    op.drop_index("ix_items_organization", table_name="items")
    op.drop_column("items", "updated_at")
    op.drop_column("items", "published_at")
    op.drop_column("items", "organization")
