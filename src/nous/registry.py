import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse
import yaml
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from .models import Source

KINDS = {"job_posting", "news", "advisory", "vulnerability", "company_update"}
ADAPTERS = {"rss": {"rss_v1"}, "json_api": {"json_v1"},
            "html": {"html_v1", "automattic_html_v1"}}

class Policy(BaseModel):
    reviewed_at: str
    terms_url: str | None = None
    robots_url: str | None = None
    content_storage: str = "metadata_only"
    note: str

class SourceConfig(BaseModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,99}$")
    kind: str
    url: str
    adapter: str
    item_kind: str
    interval_minutes: int = Field(ge=15)
    max_requests_per_hour: int = Field(ge=1, le=60)
    max_concurrency: int = Field(ge=1, le=4)
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
        if self.item_kind not in KINDS or parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("invalid source kind or endpoint")
        if self.policy.content_storage != "metadata_only" or not self.policy.note:
            raise ValueError("unreviewed policy")
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

def sync(session, configs):
    for cfg in configs:
        raw = cfg.model_dump()
        revision = hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()
        row = session.scalar(select(Source).where(Source.source_key == cfg.id))
        if row is None:
            row = Source(source_key=cfg.id)
            session.add(row)
        row.kind, row.url, row.adapter, row.item_kind = cfg.kind, cfg.url, cfg.adapter, cfg.item_kind
        row.config_revision, row.config = revision, raw
        row.enabled, row.interval_minutes = cfg.enabled, cfg.interval_minutes
        row.max_requests_per_hour = cfg.max_requests_per_hour
    session.commit()
