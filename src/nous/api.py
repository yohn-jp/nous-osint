from datetime import datetime
from functools import lru_cache
from alembic.config import Config
from alembic.script import ScriptDirectory
from typing import Any, Literal
from fastapi import FastAPI, HTTPException, Query, Path
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text
from .db import session_factory
from .cve_queries import query_cve
from .models import FetchAttempt, FetchJob, Item, ItemVersion, Source

app = FastAPI(title="Nous OSINT", version="0.1.0")

ItemKind = Literal["job_posting", "news", "advisory", "vulnerability", "company_update"]
ItemState = Literal["current", "unknown", "stale", "closed"]


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LiveResponse(APIModel):
    status: Literal["ok"]


class ReadyResponse(LiveResponse):
    schema_version: str = Field(alias="schema")


class SourceResponse(APIModel):
    id: str
    kind: Literal["rss", "json_api", "html"]
    item_kind: ItemKind
    enabled: bool
    last_success_at: datetime | None
    next_due_at: datetime
    last_error: str | None


class ItemResponse(APIModel):
    id: int
    source: str
    kind: ItemKind
    title: str
    organization: str | None = None
    url: str
    state: ItemState
    first_seen_at: datetime
    last_seen_at: datetime
    published_at: datetime | None = None
    updated_at: datetime | None = None
    current_version: int = Field(ge=1)


class ItemPageResponse(APIModel):
    items: list[ItemResponse]
    next_cursor: int | None


class ItemDetailResponse(ItemResponse):
    attributes: dict[str, Any]
    provenance: dict[str, Any]


class VersionResponse(APIModel):
    version: int = Field(ge=1)
    observed_at: datetime
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    attributes: dict[str, Any]
    provenance: dict[str, Any]


class ChangeResponse(APIModel):
    item_id: int
    kind: ItemKind
    title: str
    version: int = Field(ge=1)
    observed_at: datetime


class ChangesResponse(APIModel):
    changes: list[ChangeResponse]


class CveReferenceResponse(APIModel):
    item_id: int
    source: str
    relation: Literal["kev", "record", "reference", "title_mention"]
    kind: ItemKind
    state: ItemState
    title: str
    url: str
    last_seen_at: datetime
    source_url: str
    source_adapter: str


class KevStatusResponse(APIModel):
    status: Literal["listed", "not_listed", "unknown"]
    catalog_as_of: datetime | None
    catalog_fresh: bool
    item_id: int | None
    date_added: str | None
    due_date: str | None
    vendor: str | None
    product: str | None
    known_ransomware_campaign_use: str | None
    source_url: str | None


class CveResponse(APIModel):
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    canonical_url: str
    kev: KevStatusResponse
    references: list[CveReferenceResponse]
    references_truncated: bool


class StatusResponse(APIModel):
    jobs: dict[str, int]
    attempts: dict[str, int]


@app.get("/health/live", response_model=LiveResponse)
def live():
    return {"status": "ok"}

@lru_cache(maxsize=1)
def expected_schema_head():
    # The image carries alembic.ini and migrations in /app.
    return ScriptDirectory.from_config(Config("alembic.ini")).get_current_head()


@app.get("/health/ready", response_model=ReadyResponse)
def ready():
    try:
        expected = expected_schema_head()
        with session_factory()() as db:
            db.execute(text("select 1"))
            version = db.execute(text("select version_num from alembic_version")).scalar_one()
        if not expected or version != expected:
            raise HTTPException(status_code=503, detail="database schema is not current")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="database is not ready") from exc
    return {"status": "ok", "schema": version}

@app.get("/v1/sources", response_model=list[SourceResponse])
def sources():
    with session_factory()() as db:
        return [{"id": s.source_key, "kind": s.kind, "item_kind": s.item_kind,
                 "enabled": s.enabled, "last_success_at": s.last_success_at,
                 "next_due_at": s.next_due_at, "last_error": s.last_error}
                for s in db.scalars(select(Source).order_by(Source.source_key))]

def item_dict(item, source):
    return {"id": item.id, "source": source.source_key, "kind": item.kind,
            "title": item.title, "organization": item.organization,
            "url": item.canonical_url, "state": item.state,
            "first_seen_at": item.first_seen_at, "last_seen_at": item.last_seen_at,
            "published_at": item.published_at, "updated_at": item.updated_at,
            "current_version": item.current_version}

@app.get("/v1/items", response_model=ItemPageResponse)
def items(kind: ItemKind | None = None, state: ItemState | None = None,
          organization: str | None = Query(None, min_length=1, max_length=200),
          source: str | None = Query(None, min_length=3, max_length=100,
                                     pattern=r"^[a-z][a-z0-9-]*$"),
          q: str | None = Query(None, min_length=1, max_length=200),
          since: AwareDatetime | None = None,
          published_since: AwareDatetime | None = None,
          limit: int = Query(50, ge=1, le=100),
          cursor: int | None = Query(None, ge=0)):
    with session_factory()() as db:
        query = select(Item, Source).join(Source, Item.source_id == Source.id)
        if kind:
            query = query.where(Item.kind == kind)
        if state:
            query = query.where(Item.state == state)
        if source:
            query = query.where(Source.source_key == source)
        if organization:
            query = query.where(Item.organization == organization)
        if q:
            query = query.where(func.to_tsvector("simple", Item.title)
                                .op("@@")(func.plainto_tsquery("simple", q)))
        if since:
            query = query.where(Item.last_seen_at >= since)
        if published_since:
            query = query.where(Item.published_at >= published_since)
        if cursor is not None:
            query = query.where(Item.id > cursor)
        rows = db.execute(query.order_by(Item.id).limit(limit + 1)).all()
        return {"items": [item_dict(i, s) for i, s in rows[:limit]],
                "next_cursor": rows[limit - 1][0].id if len(rows) > limit else None}

@app.get("/v1/items/{item_id}", response_model=ItemDetailResponse)
def item(item_id: int):
    with session_factory()() as db:
        row = db.execute(select(Item, Source).join(Source).where(Item.id == item_id)).first()
        if not row:
            raise HTTPException(404, "item not found")
        version = db.scalar(select(ItemVersion).where(ItemVersion.item_id == item_id)
                            .order_by(ItemVersion.version.desc()).limit(1))
        return {**item_dict(*row), "attributes": version.attributes,
                "provenance": version.provenance}

@app.get("/v1/items/{item_id}/versions", response_model=list[VersionResponse])
def versions(item_id: int, limit: int = Query(50, ge=1, le=100),
             before: int | None = Query(None, ge=1)):
    with session_factory()() as db:
        if not db.get(Item, item_id):
            raise HTTPException(404, "item not found")
        query = select(ItemVersion).where(ItemVersion.item_id == item_id)
        if before is not None:
            query = query.where(ItemVersion.version < before)
        query = query.order_by(ItemVersion.version.desc()).limit(limit)
        return [{"version": v.version, "observed_at": v.observed_at,
                 "sha256": v.sha256, "attributes": v.attributes, "provenance": v.provenance}
                for v in db.scalars(query)]

@app.get("/v1/cves/{cve_id}", response_model=CveResponse)
def cve(cve_id: str = Path(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$", max_length=64)):
    """Exact CVE identity and source-attributed KEV status, with no live HTTP."""
    with session_factory()() as db:
        return query_cve(db, cve_id)


@app.get("/v1/changes", response_model=ChangesResponse)
def changes(since: AwareDatetime, kind: ItemKind | None = None,
            limit: int = Query(50, ge=1, le=100)):
    with session_factory()() as db:
        query = select(ItemVersion, Item).join(Item).where(ItemVersion.observed_at >= since)
        if kind:
            query = query.where(Item.kind == kind)
        return {"changes": [{"item_id": item.id, "kind": item.kind,
                             "title": v.attributes["title"],
                             "version": v.version, "observed_at": v.observed_at}
                            for v, item in db.execute(query.order_by(ItemVersion.id.desc()).limit(limit))]}

@app.get("/v1/status", response_model=StatusResponse)
def status():
    with session_factory()() as db:
        return {"jobs": dict(db.execute(select(FetchJob.state, func.count()).group_by(FetchJob.state)).all()),
                "attempts": dict(db.execute(select(FetchAttempt.outcome, func.count())
                                            .group_by(FetchAttempt.outcome)).all())}
