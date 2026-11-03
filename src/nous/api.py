from datetime import datetime
from fastapi import FastAPI, HTTPException, Query
from sqlalchemy import func, select, text
from .db import session_factory
from .models import FetchAttempt, FetchJob, Item, ItemVersion, Source

app = FastAPI(title="Nous OSINT", version="0.1.0")

@app.get("/health/live")
def live():
    return {"status": "ok"}

@app.get("/health/ready")
def ready():
    with session_factory()() as db:
        db.execute(text("select 1"))
        version = db.execute(text("select version_num from alembic_version")).scalar_one()
        return {"status": "ok", "schema": version}

@app.get("/v1/sources")
def sources():
    with session_factory()() as db:
        return [{"id": s.source_key, "kind": s.kind, "item_kind": s.item_kind,
                 "enabled": s.enabled, "last_success_at": s.last_success_at,
                 "next_due_at": s.next_due_at, "last_error": s.last_error}
                for s in db.scalars(select(Source).order_by(Source.source_key))]

def item_dict(item, source):
    return {"id": item.id, "source": source.source_key, "kind": item.kind,
            "title": item.title, "url": item.canonical_url, "state": item.state,
            "first_seen_at": item.first_seen_at, "last_seen_at": item.last_seen_at,
            "current_version": item.current_version}

@app.get("/v1/items")
def items(kind: str | None = None, source: str | None = None, q: str | None = None,
          since: datetime | None = None, limit: int = Query(50, ge=1, le=100), cursor: int | None = None):
    with session_factory()() as db:
        query = select(Item, Source).join(Source, Item.source_id == Source.id)
        if kind:
            query = query.where(Item.kind == kind)
        if source:
            query = query.where(Source.source_key == source)
        if q:
            query = query.where(Item.title.ilike("%" + q.replace("%", "\\%").replace("_", "\\_") + "%"))
        if since:
            query = query.where(Item.last_seen_at >= since)
        if cursor:
            query = query.where(Item.id > cursor)
        rows = db.execute(query.order_by(Item.id).limit(limit + 1)).all()
        return {"items": [item_dict(i, s) for i, s in rows[:limit]],
                "next_cursor": rows[limit - 1][0].id if len(rows) > limit else None}

@app.get("/v1/items/{item_id}")
def item(item_id: int):
    with session_factory()() as db:
        row = db.execute(select(Item, Source).join(Source).where(Item.id == item_id)).first()
        if not row:
            raise HTTPException(404, "item not found")
        version = db.scalar(select(ItemVersion).where(ItemVersion.item_id == item_id)
                            .order_by(ItemVersion.version.desc()).limit(1))
        return {**item_dict(*row), "attributes": version.attributes,
                "provenance": version.provenance}

@app.get("/v1/items/{item_id}/versions")
def versions(item_id: int):
    with session_factory()() as db:
        if not db.get(Item, item_id):
            raise HTTPException(404, "item not found")
        return [{"version": v.version, "observed_at": v.observed_at,
                 "sha256": v.sha256, "attributes": v.attributes, "provenance": v.provenance}
                for v in db.scalars(select(ItemVersion).where(ItemVersion.item_id == item_id)
                                    .order_by(ItemVersion.version.desc()))]

@app.get("/v1/changes")
def changes(since: datetime, kind: str | None = None, limit: int = Query(50, ge=1, le=100)):
    with session_factory()() as db:
        query = select(ItemVersion, Item).join(Item).where(ItemVersion.observed_at >= since)
        if kind:
            query = query.where(Item.kind == kind)
        return [{"item_id": item.id, "kind": item.kind, "title": item.title,
                 "version": v.version, "observed_at": v.observed_at}
                for v, item in db.execute(query.order_by(ItemVersion.id.desc()).limit(limit))]

@app.get("/v1/status")
def status():
    with session_factory()() as db:
        return {"jobs": dict(db.execute(select(FetchJob.state, func.count()).group_by(FetchJob.state)).all()),
                "attempts": dict(db.execute(select(FetchAttempt.outcome, func.count())
                                            .group_by(FetchAttempt.outcome)).all())}
