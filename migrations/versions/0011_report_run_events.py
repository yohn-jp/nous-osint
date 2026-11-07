"""Append-only report diagnostics and durable stage checkpoint metadata."""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("report_runs", sa.Column("failed_stage", sa.String(32), nullable=True))
    op.add_column("report_runs", sa.Column(
        "retry_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "report_run_events",
        sa.Column("run_id", sa.String(36), sa.ForeignKey("report_runs.id"), primary_key=True),
        sa.Column("attempt", sa.Integer(), primary_key=True),
        sa.Column("seq", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stage", sa.String(32), nullable=False),
        sa.Column("event_type", sa.String(48), nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("exit_status", sa.Integer()),
        sa.Column("elapsed_ms", sa.Integer()),
        sa.Column("usage", sa.JSON()),
        sa.Column("artifact_sha256", sa.String(64)),
        sa.Column("diagnostic_ref", sa.String(512)),
        sa.Column("retryable", sa.Boolean()),
        sa.Column("input_sha256", sa.String(64)),
        sa.Column("schema_revision", sa.String(64)),
        sa.Column("prompt_revision", sa.String(64)),
        sa.Column("model", sa.String(128)),
        sa.Column("cli_version", sa.String(64)),
        sa.Column("stdout_bytes", sa.Integer()),
        sa.Column("stderr_bytes", sa.Integer()),
        sa.Column("jsonl_last_event", sa.String(48)),
    )
    op.create_index("ix_report_run_events_run", "report_run_events",
                    ["run_id", "attempt", "seq"])
    # The report worker can append events but cannot mutate or erase history.
    # The admin role reads these allowlisted fields; the API's normal role
    # never receives a grant to the private event history.
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_report_worker') THEN
                EXECUTE format('GRANT SELECT, INSERT ON TABLE %I.report_run_events TO nous_report_worker', current_schema());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_admin') THEN
                EXECUTE format('GRANT SELECT ON TABLE %I.report_run_events TO nous_admin', current_schema());
            END IF;
        END
        $$;
    """))


def downgrade():
    op.drop_index("ix_report_run_events_run", table_name="report_run_events")
    op.drop_table("report_run_events")
    op.drop_column("report_runs", "retry_at")
    op.drop_column("report_runs", "failed_stage")
