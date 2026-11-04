"""Durable report schedules, fenced runs, immutable publications and evidence."""
from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "report_schedules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("template_id", sa.String(80), nullable=False),
        sa.Column("template_revision", sa.String(64), nullable=False),
        sa.Column("template_snapshot", sa.JSON(), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("timezone", sa.String(64), nullable=False),
        sa.Column("cadence", sa.String(16), nullable=False),
        sa.Column("local_time", sa.String(5), nullable=False),
        sa.Column("next_slot_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("cadence IN ('daily','weekly')", name="ck_report_schedule_cadence"),
    )
    op.create_index("ix_report_schedules_next_slot_at", "report_schedules", ["next_slot_at"])

    op.create_table(
        "report_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("schedule_id", sa.String(36), sa.ForeignKey("report_schedules.id")),
        sa.Column("schedule_slot", sa.DateTime(timezone=True)),
        sa.Column("trigger", sa.String(16), nullable=False),
        sa.Column("created_by", sa.String(256)),
        sa.Column("template_id", sa.String(80), nullable=False),
        sa.Column("template_revision", sa.String(64), nullable=False),
        sa.Column("template_snapshot", sa.JSON(), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), unique=True),
        sa.Column("request_sha256", sa.String(64)),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("stage", sa.String(32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column("lease_token", sa.String(36)),
        sa.Column("observed_cutoff", sa.DateTime(timezone=True)),
        sa.Column("bundle_sha256", sa.String(64)),
        sa.Column("bundle_path", sa.Text()),
        sa.Column("stage_artifacts", sa.JSON(), nullable=False),
        sa.Column("report_id", sa.String(36)),
        sa.Column("error_code", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("schedule_id", "schedule_slot", name="uq_report_schedule_slot"),
        sa.CheckConstraint(
            "state IN ('queued','leased','running','validating','publishing','published',"
            "'skipped','failed','cancelled')", name="ck_report_run_state"),
        sa.CheckConstraint("trigger IN ('manual','scheduled')", name="ck_report_run_trigger"),
    )
    op.create_index("ix_report_runs_queue", "report_runs",
                    ["state", "available_at", "created_at"])

    op.create_table(
        "reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("report_runs.id"), nullable=False, unique=True),
        sa.Column("slug", sa.String(128), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("template_id", sa.String(80), nullable=False),
        sa.Column("article_schema_version", sa.Integer(), nullable=False),
        sa.Column("article", sa.JSON(), nullable=False),
        sa.Column("headline", sa.String(240), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("artifact_digest", sa.String(64), nullable=False),
        sa.Column("artifact_path", sa.Text(), nullable=False),
        sa.Column("supersedes_id", sa.String(36), sa.ForeignKey("reports.id")),
        sa.Column("model", sa.String(128)),
        sa.Column("harness_version", sa.String(64), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.UniqueConstraint("slug", name="uq_reports_slug"),
    )

    op.create_table(
        "report_evidence",
        sa.Column("report_id", sa.String(36), sa.ForeignKey("reports.id"), primary_key=True),
        sa.Column("evidence_id", sa.String(16), primary_key=True),
        sa.Column("item_id", sa.Integer(), sa.ForeignKey("items.id"), nullable=False),
        sa.Column("item_version_id", sa.Integer(), sa.ForeignKey("item_versions.id"), nullable=False),
        sa.Column("item_version_sha256", sa.String(64), nullable=False),
        sa.Column("source_key", sa.String(100), nullable=False),
        sa.Column("publisher_url", sa.Text(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("relation", sa.String(24), nullable=False),
        sa.CheckConstraint("relation IN ('record','reference','kev','title_mention')",
                           name="ck_report_evidence_relation"),
    )
    op.create_index("ix_report_evidence_item_version", "report_evidence", ["item_version_id"])

    op.create_table(
        "report_site_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("active_digest", sa.String(64), nullable=False),
        sa.Column("pending_digest", sa.String(64)),
        sa.Column("pending_run_id", sa.String(36)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_report_site_state_singleton"),
        sa.CheckConstraint(
            "(pending_digest IS NULL AND pending_run_id IS NULL) OR "
            "(pending_digest IS NOT NULL AND pending_run_id IS NOT NULL)",
            name="ck_report_site_state_pending_pair"),
    )


def downgrade():
    op.drop_table("report_site_state")
    op.drop_index("ix_report_evidence_item_version", table_name="report_evidence")
    op.drop_table("report_evidence")
    op.drop_table("reports")
    op.drop_index("ix_report_runs_queue", table_name="report_runs")
    op.drop_table("report_runs")
    op.drop_index("ix_report_schedules_next_slot_at", table_name="report_schedules")
    op.drop_table("report_schedules")
