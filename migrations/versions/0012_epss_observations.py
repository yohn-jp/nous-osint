"""Append-only FIRST EPSS lookup observations and crash-safe bounded poll schedule.

EPSS is a forward-looking probability independent of KEV exploitation evidence.
The runtime role may insert observations but never edit past daily snapshots.
"""
from alembic import op
import sqlalchemy as sa

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "epss_observations",
        sa.Column("cve_id", sa.String(64), primary_key=True),
        sa.Column("checked_on", sa.Date(), primary_key=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("score_date", sa.Date(), nullable=True),
        sa.Column("score", sa.Numeric(10, 9), nullable=True),
        sa.Column("percentile", sa.Numeric(10, 9), nullable=True),
        sa.CheckConstraint("score IS NULL OR (score >= 0 AND score <= 1)", name="ck_epss_score"),
        sa.CheckConstraint(
            "percentile IS NULL OR (percentile >= 0 AND percentile <= 1)",
            name="ck_epss_percentile",
        ),
        sa.CheckConstraint(
            "(score IS NULL AND percentile IS NULL AND score_date IS NULL) OR "
            "(score IS NOT NULL AND percentile IS NOT NULL AND score_date IS NOT NULL)",
            name="ck_epss_complete",
        ),
    )
    op.create_index(
        "ix_epss_observations_observed", "epss_observations", ["cve_id", "fetched_at"],
    )
    op.create_table(
        "epss_poll_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("next_due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(60)),
        sa.CheckConstraint("id = 1", name="ck_epss_singleton"),
    )
    op.execute(sa.text(
        "INSERT INTO epss_poll_state (id, next_due_at) "
        "VALUES (1, '1970-01-01T00:00:00+00:00')",
    ))
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_runtime') THEN
                EXECUTE format('GRANT SELECT, INSERT ON TABLE %I.epss_observations TO nous_runtime', current_schema());
                EXECUTE format('GRANT SELECT, UPDATE ON TABLE %I.epss_poll_state TO nous_runtime', current_schema());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_api') THEN
                EXECUTE format('GRANT SELECT ON TABLE %I.epss_observations TO nous_api', current_schema());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_mcp') THEN
                EXECUTE format('GRANT SELECT ON TABLE %I.epss_observations TO nous_mcp', current_schema());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_report_worker') THEN
                EXECUTE format('GRANT SELECT ON TABLE %I.epss_observations TO nous_report_worker', current_schema());
            END IF;
        END
        $$;
    """))


def downgrade():
    op.drop_table("epss_poll_state")
    op.drop_index("ix_epss_observations_observed", table_name="epss_observations")
    op.drop_table("epss_observations")
