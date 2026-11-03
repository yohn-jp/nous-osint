from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

def upgrade():
    op.create_check_constraint("ck_items_state", "items",
                               "state IN ('current', 'unknown', 'stale', 'closed')")

def downgrade():
    op.drop_constraint("ck_items_state", "items", type_="check")
