import hashlib
from datetime import date
import json
from pathlib import Path
from urllib.parse import urlparse
import yaml
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from .models import Source

KINDS = {"job_posting", "news", "advisory", "vulnerability", "company_update"}
ADAPTERS = {"rss": {"rss_v1"}, "json_api": {"json_v1", "greenhouse_jobs_v1",
                                           "lever_jobs_v1", "ashby_jobs_v1"},
            "html": {"html_v1", "automattic_html_v1"}}

class Policy(BaseModel):
    reviewed_at: str
    terms_url: str | None = None
    robots_url: str | None = None
    content_storage: str = "metadata_only"
    note: str
    license_id: str = Field(default="NOASSERTION", min_length=3, max_length=100)
    license_url: str | None = None
    attribution: str | None = Field(default=None, max_length=200)

    @field_validator("reviewed_at")
    @classmethod
    def reviewed_date(cls, value):
        try:
            date.fromisoformat(value)
        except (ValueError, TypeError) as exc:
            raise ValueError("policy review date must be YYYY-MM-DD") from exc
        return value

class SourceConfig(BaseModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,99}$")
    kind: str
    url: str
    adapter: str
    item_kind: str
    organization: str | None = Field(default=None, max_length=200)
    interval_minutes: int = Field(ge=15)
    max_requests_per_hour: int = Field(ge=1, le=60)
    max_concurrency: int = Field(ge=1, le=4)
    max_pages: int = Field(default=1, ge=1, le=10)
    enabled: bool
    policy: Policy
    selectors: dict[str, str] = Field(default_factory=dict)
    json_path: str | None = None
    field_map: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def valid(self):
        parsed = urlparse(self.url)
        if self.kind not in ADAPTERS or self.adapter not in ADAPTERS[self.kind]:
            raise ValueError("unsupported adapter")
        if (self.item_kind not in KINDS or parsed.scheme != "https" or
                not parsed.hostname or parsed.username or parsed.password or parsed.fragment):
            raise ValueError("invalid source kind or endpoint")
        if self.policy.content_storage != "metadata_only" or not self.policy.note.strip():
            raise ValueError("unreviewed policy")
        ats_hosts = {
            "greenhouse_jobs_v1": ("boards-api.greenhouse.io", r"^/v1/boards/[a-zA-Z0-9_-]+/jobs$"),
            "lever_jobs_v1": ("api.lever.co", r"^/v0/postings/[a-zA-Z0-9_-]+$"),
            "ashby_jobs_v1": ("api.ashbyhq.com", r"^/posting-api/job-board/[a-zA-Z0-9_-]+$"),
        }
        if self.adapter in ats_hosts:
            import re
            host, path = ats_hosts[self.adapter]
            if (self.kind != "json_api" or self.item_kind != "job_posting" or
                    parsed.hostname != host or not re.fullmatch(path, parsed.path)):
                raise ValueError("ATS adapter must use its official public GET endpoint")
            if self.adapter == "lever_jobs_v1":
                if self.max_pages > self.max_requests_per_hour:
                    raise ValueError("Lever max_pages must fit the hourly request budget")
            elif self.max_pages != 1:
                raise ValueError("nonpaginated ATS must use max_pages=1")
        elif self.max_pages != 1:
            raise ValueError("max_pages is supported only by Lever job boards")
        if self.adapter == "html_v1" and not {"item", "title", "url"} <= self.selectors.keys():
            raise ValueError("HTML selectors required")
        return self

def load_registry(path="sources"):
    result = []
    seen = set()
    for file in sorted(Path(path).glob("*.yaml")):
        data = yaml.safe_load(file.read_text())
        for raw in data if isinstance(data, list) else [data]:
            source = SourceConfig.model_validate(raw)
            if source.id in seen:
                raise ValueError(f"duplicate source ID: {source.id}")
            seen.add(source.id)
            result.append(source)
    return result

def revision_of(config: dict) -> str:
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def apply_config(row: Source, raw: dict):
    """Update effective collection configuration without erasing runtime history."""
    config = SourceConfig.model_validate(raw)
    row.kind, row.url, row.adapter, row.item_kind = (
        config.kind, config.url, config.adapter, config.item_kind
    )
    row.config = config.model_dump()
    row.config_revision = revision_of(row.config)
    row.enabled, row.interval_minutes = config.enabled, config.interval_minutes
    row.max_requests_per_hour = config.max_requests_per_hour


def sync(session, configs):
    """Import official catalog idempotently; retain instance custom sources/overrides."""
    active_keys = set()
    for cfg in configs:
        if cfg.id in active_keys:
            raise ValueError(f"duplicate official source ID: {cfg.id}")
        active_keys.add(cfg.id)
        raw = cfg.model_dump()
        row = session.scalar(select(Source).where(Source.source_key == cfg.id).with_for_update())
        if row is None:
            row = Source(source_key=cfg.id, origin="official", overrides={})
            session.add(row)
        elif row.origin != "official":
            raise ValueError(f"custom source conflicts with official catalog: {cfg.id}")
        overrides = row.overrides or {}
        # The administrator owns only operational overrides, not the origin URL
        # or parsing/policy contract. A catalog update preserves those overrides.
        if overrides.keys() - {
            "enabled", "interval_minutes", "max_requests_per_hour", "max_concurrency"
        }:
            raise ValueError(f"unsupported official override: {cfg.id}")
        apply_config(row, {**raw, **overrides})
        row.catalog_revision = revision_of(raw)

    for row in session.scalars(select(Source).where(
        Source.origin == "official", Source.enabled.is_(True)
    ).with_for_update()):
        if row.source_key not in active_keys:
            row.enabled = False
            row.config = {**row.config, "enabled": False}
            row.config_revision = revision_of(row.config)
    session.commit()
