"""Preserve complete KEV membership and freshness as immutable as-of observations.

Historical ItemVersion entries alone cannot prove that a CVE remained in a later
complete catalog; current item.state cannot answer questions about past cutoffs.
Catalog contents are deduplicated by digest and each successful 200/304 fetch
commits an observation in the same ingestion transaction.
"""
from alembic import op
import sqlalchemy as sa

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "kev_catalog_contents",
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column("cve_ids", sa.JSON(), nullable=False),
    )
    op.create_table(
        "kev_catalog_observations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("sources.id"), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("digest", sa.String(64), sa.ForeignKey("kev_catalog_contents.digest"), nullable=False),
    )
    op.create_index(
        "ix_kev_catalog_source_observed", "kev_catalog_observations",
        ["source_id", "observed_at"],
    )
    # The runtime can only append complete observations; read surfaces may not
    # mutate catalog membership. Roles are optional at migration time.
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_runtime') THEN
                EXECUTE format('GRANT INSERT ON TABLE %I.kev_catalog_contents, %I.kev_catalog_observations TO nous_runtime', current_schema(), current_schema());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_api') THEN
                EXECUTE format('GRANT SELECT ON TABLE %I.kev_catalog_contents, %I.kev_catalog_observations TO nous_api', current_schema(), current_schema());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_mcp') THEN
                EXECUTE format('GRANT SELECT ON TABLE %I.kev_catalog_contents, %I.kev_catalog_observations TO nous_mcp', current_schema(), current_schema());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_report_worker') THEN
                EXECUTE format('GRANT SELECT ON TABLE %I.kev_catalog_contents, %I.kev_catalog_observations TO nous_report_worker', current_schema(), current_schema());
            END IF;
        END
        $$;
    """))


def downgrade():
    op.drop_index("ix_kev_catalog_source_observed", table_name="kev_catalog_observations")
    op.drop_table("kev_catalog_observations")
    op.drop_table("kev_catalog_contents")
