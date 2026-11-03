from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

def upgrade():
    op.execute("CREATE INDEX ix_items_title_fts ON items USING GIN (to_tsvector('simple', title))")

def downgrade():
    op.execute("DROP INDEX ix_items_title_fts")
