"""Append-only public CVE repository metadata catalogs, indexed by year.

Directory tree metadata is collected from GitHub; no template body, PoC code
or URL derived from third-party content is requested or executed.
"""
from alembic import op
import sqlalchemy as sa

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "public_artifact_contents",
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column("entries", sa.JSON(), nullable=False),
    )
    op.create_table(
        "public_artifact_observations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("year", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("commit_sha", sa.String(40), nullable=False),
        sa.Column("digest", sa.String(64),
                  sa.ForeignKey("public_artifact_contents.digest"), nullable=False),
        sa.CheckConstraint("provider IN ('trickest', 'nuclei_http')",
                           name="ck_public_artifact_provider"),
        sa.CheckConstraint("year BETWEEN 1999 AND 2100", name="ck_public_artifact_year"),
        sa.UniqueConstraint("provider", "year", "observed_at",
                            name="uq_public_artifact_observation"),
    )
    op.create_index(
        "ix_public_artifact_provider_year_asof", "public_artifact_observations",
        ["provider", "year", "observed_at"],
    )
    op.create_table(
        "public_artifact_poll_state",
        sa.Column("provider", sa.String(32), primary_key=True),
        sa.Column("year", sa.Integer(), primary_key=True),
        sa.Column("next_due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(60)),
        sa.CheckConstraint("provider IN ('trickest', 'nuclei_http')",
                           name="ck_public_artifact_poll_provider"),
        sa.CheckConstraint("year BETWEEN 1999 AND 2100",
                           name="ck_public_artifact_poll_year"),
    )
    # Grants apply only to existing roles; cluster provisioning may follow migrations.
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_runtime') THEN
                EXECUTE format('GRANT SELECT, INSERT ON TABLE %I.public_artifact_contents TO nous_runtime', current_schema());
                EXECUTE format('GRANT INSERT ON TABLE %I.public_artifact_observations TO nous_runtime', current_schema());
                EXECUTE format('GRANT SELECT, INSERT, UPDATE ON TABLE %I.public_artifact_poll_state TO nous_runtime', current_schema());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_api') THEN
                EXECUTE format('GRANT SELECT ON TABLE %I.public_artifact_contents, %I.public_artifact_observations TO nous_api', current_schema(), current_schema());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_mcp') THEN
                EXECUTE format('GRANT SELECT ON TABLE %I.public_artifact_contents, %I.public_artifact_observations TO nous_mcp', current_schema(), current_schema());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_report_worker') THEN
                EXECUTE format('GRANT SELECT ON TABLE %I.public_artifact_contents, %I.public_artifact_observations TO nous_report_worker', current_schema(), current_schema());
            END IF;
        END
        $$;
    """))


def downgrade():
    op.drop_table("public_artifact_poll_state")
    op.drop_index("ix_public_artifact_provider_year_asof",
                  table_name="public_artifact_observations")
    op.drop_table("public_artifact_observations")
    op.drop_table("public_artifact_contents")
