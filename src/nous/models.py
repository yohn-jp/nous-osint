from datetime import datetime, timezone
from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base

def now():
    return datetime.now(timezone.utc)

class Source(Base):
    __tablename__ = "sources"
    id: Mapped[int] = mapped_column(primary_key=True)
    source_key: Mapped[str] = mapped_column(String(100), unique=True)
    kind: Mapped[str] = mapped_column(String(20))
    url: Mapped[str] = mapped_column(Text)
    adapter: Mapped[str] = mapped_column(String(40))
    item_kind: Mapped[str] = mapped_column(String(30))
    config_revision: Mapped[str] = mapped_column(String(64))
    config: Mapped[dict] = mapped_column(JSON)
    enabled: Mapped[bool] = mapped_column(Boolean)
    interval_minutes: Mapped[int] = mapped_column(Integer)
    max_requests_per_hour: Mapped[int] = mapped_column(Integer)
    origin: Mapped[str] = mapped_column(String(16), default="official")
    catalog_revision: Mapped[str | None] = mapped_column(String(64))
    overrides: Mapped[dict] = mapped_column(JSON, default=dict)
    next_due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(100))
    etag: Mapped[str | None] = mapped_column(Text)
    last_modified: Mapped[str | None] = mapped_column(Text)

class SourceAudit(Base):
    __tablename__ = "source_audits"
    __table_args__ = (Index("ix_source_audits_source_id", "source_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"))
    actor: Mapped[str] = mapped_column(String(256))
    action: Mapped[str] = mapped_column(String(40))
    before: Mapped[dict | None] = mapped_column(JSON)
    after: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class FetchJob(Base):
    __tablename__ = "fetch_jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"))
    dedupe_key: Mapped[str] = mapped_column(String(120), unique=True)
    state: Mapped[str] = mapped_column(String(20), default="queued")
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0)

class FetchAttempt(Base):
    __tablename__ = "fetch_attempts"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("fetch_jobs.id"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    ended_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    outcome: Mapped[str] = mapped_column(String(30))
    http_status: Mapped[int | None] = mapped_column(Integer)
    request_count: Mapped[int] = mapped_column(Integer, default=1)
    final_url: Mapped[str | None] = mapped_column(Text)
    error_code: Mapped[str | None] = mapped_column(String(100))

class Item(Base):
    __tablename__ = "items"
    __table_args__ = (UniqueConstraint("source_id", "external_id"), Index("ix_items_kind", "kind"))
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"))
    external_id: Mapped[str] = mapped_column(Text)
    canonical_url: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(30))
    title: Mapped[str] = mapped_column(Text)
    organization: Mapped[str | None] = mapped_column(String(200), index=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state: Mapped[str] = mapped_column(String(20), default="current")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    current_version: Mapped[int] = mapped_column(Integer, default=0)
    current_hash: Mapped[str] = mapped_column(String(64), default="")

class ItemVersion(Base):
    __tablename__ = "item_versions"
    __table_args__ = (UniqueConstraint("item_id", "version"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("items.id"))
    version: Mapped[int] = mapped_column(Integer)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    sha256: Mapped[str] = mapped_column(String(64))
    attributes: Mapped[dict] = mapped_column(JSON)
    provenance: Mapped[dict] = mapped_column(JSON)

class CveItemLink(Base):
    """Source-backed association to an exact CVE identifier, never fuzzy identity."""
    __tablename__ = "cve_item_links"
    __table_args__ = (Index("ix_cve_item_links_cve_id", "cve_id"),)
    item_id: Mapped[int] = mapped_column(ForeignKey("items.id"), primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    relation: Mapped[str] = mapped_column(String(24))


class ReportSchedule(Base):
    __tablename__ = "report_schedules"
    __table_args__ = (CheckConstraint("cadence IN ('daily','weekly')", name="ck_report_schedule_cadence"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    template_id: Mapped[str] = mapped_column(String(80))
    template_revision: Mapped[str] = mapped_column(String(64))
    template_snapshot: Mapped[dict] = mapped_column(JSON)
    parameters: Mapped[dict] = mapped_column(JSON)
    timezone: Mapped[str] = mapped_column(String(64))
    cadence: Mapped[str] = mapped_column(String(16))
    local_time: Mapped[str] = mapped_column(String(5))
    next_slot_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ReportRun(Base):
    __tablename__ = "report_runs"
    __table_args__ = (
        UniqueConstraint("schedule_id", "schedule_slot", name="uq_report_schedule_slot"),
        CheckConstraint(
            "state IN ('queued','leased','running','validating','publishing','published',"
            "'skipped','failed','cancelled')", name="ck_report_run_state"),
        Index("ix_report_runs_queue", "state", "available_at", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    schedule_id: Mapped[str | None] = mapped_column(ForeignKey("report_schedules.id"))
    schedule_slot: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trigger: Mapped[str] = mapped_column(String(16))
    template_id: Mapped[str] = mapped_column(String(80))
    template_revision: Mapped[str] = mapped_column(String(64))
    template_snapshot: Mapped[dict] = mapped_column(JSON)
    parameters: Mapped[dict] = mapped_column(JSON)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), unique=True)
    state: Mapped[str] = mapped_column(String(24), default="queued")
    stage: Mapped[str] = mapped_column(String(32), default="queued")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_token: Mapped[str | None] = mapped_column(String(36))
    observed_cutoff: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    bundle_sha256: Mapped[str | None] = mapped_column(String(64))
    bundle_path: Mapped[str | None] = mapped_column(Text)
    stage_artifacts: Mapped[dict] = mapped_column(JSON, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (UniqueConstraint("slug", name="uq_reports_slug"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("report_runs.id"), unique=True)
    slug: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(32))
    template_id: Mapped[str] = mapped_column(String(80))
    article_schema_version: Mapped[int] = mapped_column(Integer, default=1)
    article: Mapped[dict] = mapped_column(JSON)
    headline: Mapped[str] = mapped_column(String(240))
    summary: Mapped[list] = mapped_column(JSON)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    artifact_digest: Mapped[str] = mapped_column(String(64))
    artifact_path: Mapped[str] = mapped_column(Text)
    supersedes_id: Mapped[str | None] = mapped_column(ForeignKey("reports.id"))
    model: Mapped[str | None] = mapped_column(String(128))
    harness_version: Mapped[str] = mapped_column(String(64))
    input_digest: Mapped[str] = mapped_column(String(64))


class ReportEvidence(Base):
    __tablename__ = "report_evidence"
    __table_args__ = (
        CheckConstraint("relation IN ('record','reference','kev','title_mention')",
                        name="ck_report_evidence_relation"),
        Index("ix_report_evidence_item_version", "item_version_id"),
    )
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id"), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("items.id"))
    item_version_id: Mapped[int] = mapped_column(ForeignKey("item_versions.id"))
    item_version_sha256: Mapped[str] = mapped_column(String(64))
    source_key: Mapped[str] = mapped_column(String(100))
    publisher_url: Mapped[str] = mapped_column(Text)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    relation: Mapped[str] = mapped_column(String(24))
