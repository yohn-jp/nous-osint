"""Operator-only source management on the Access-authenticated gateway.

No GitHub credential or remote MCP mutation. The admin gateway uses a distinct
database role and an explicit Access subject allowlist; source definitions and
audit history are private to this instance.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from .models import Source, SourceAudit
from .onboard_source import probe
from .registry import SourceConfig, apply_config, load_registry, revision_of

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
_SOURCE_ID = re.compile(r"^[a-z][a-z0-9-]{2,99}$")
_MAX_REQUEST = 16384


def _factory():
    path = os.getenv("NOUS_ADMIN_DATABASE_URL_FILE")
    if not path:
        raise HTTPException(503, "admin database secret is not configured")
    try:
        dsn = Path(path).read_text().strip()
    except OSError as exc:
        raise HTTPException(503, "admin database secret is unavailable") from exc
    if not dsn:
        raise HTTPException(503, "admin database secret is empty")
    return sessionmaker(create_engine(dsn, pool_pre_ping=True))


def _admin_subjects():
    return {s.strip() for s in os.getenv("NOUS_ADMIN_SUBJECTS", "").split(",") if s.strip()}


def _public_origin():
    host = os.getenv("NOUS_PUBLIC_HOST", "nous.yohn.jp").lower().strip()
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host):
        raise HTTPException(503, "invalid public host configuration")
    return "https://" + host


@app.middleware("http")
async def require_admin(request: Request, call_next):
    identity = request.scope.get("state", {}).get("access_identity")
    if not identity or not _admin_subjects() or identity.subject not in _admin_subjects():
        return _error(403, "administrator access required")
    if request.method not in ("GET", "HEAD"):
        if (request.headers.get("origin") != _public_origin() or
                request.headers.get("x-nous-admin-action") != "1" or
                request.headers.get("content-type", "").split(";", 1)[0] != "application/json" or
                request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none") or
                len(await request.body()) > _MAX_REQUEST):
            return _error(403, "unsafe administration request")
    return await call_next(request)


def _error(code, detail):
    from fastapi.responses import JSONResponse
    return JSONResponse({"detail": detail}, status_code=code,
                        headers={"Cache-Control": "no-store"})


def _row(row):
    return {
        "id": row.source_key,
        "origin": row.origin,
        "config": row.config,
        "overrides": row.overrides or {},
        "catalog_revision": row.catalog_revision,
        "enabled": row.enabled,
        "last_success_at": row.last_success_at,
        "next_due_at": row.next_due_at,
        "last_error": row.last_error,
    }


def _audit(db, row, actor, action, before):
    db.add(SourceAudit(source_id=row.id, actor=actor, action=action,
                       before=before, after=_row(row)["config"]))


def _id_or_404(key):
    if not _SOURCE_ID.fullmatch(key):
        raise HTTPException(404, "source not found")


def _official():
    return {c.id: c for c in load_registry()}


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    interval_minutes: int | None = Field(default=None, ge=15)
    max_requests_per_hour: int | None = Field(default=None, ge=1, le=60)
    max_concurrency: int | None = Field(default=None, ge=1, le=4)


@app.get("/v1/admin/session")
def session(request: Request):
    return {"allowed": True}


@app.get("/v1/admin/catalog")
def catalog():
    factory = _factory()
    bundled = _official()
    with factory() as db:
        rows = {row.source_key: row for row in db.scalars(
            select(Source).where(Source.origin == "official"))}
        return [
            {"config": cfg.model_dump(), "catalog_revision": revision_of(cfg.model_dump()),
             "installed": key in rows, "runtime": _row(rows[key]) if key in rows else None}
            for key, cfg in sorted(bundled.items())
        ]


@app.get("/v1/admin/sources")
def sources():
    factory = _factory()
    with factory() as db:
        return [_row(row) for row in db.scalars(select(Source).order_by(Source.source_key))]


@app.post("/v1/admin/sources", status_code=201)
def create_source(config: SourceConfig, request: Request):
    if config.enabled:
        raise HTTPException(422, "new custom sources must start disabled")
    if config.id in _official():
        raise HTTPException(409, "official source ID is reserved")
    factory = _factory()
    with factory() as db:
        if db.scalar(select(Source.id).where(Source.source_key == config.id)):
            raise HTTPException(409, "source ID already exists")
        row = Source(source_key=config.id, origin="custom", overrides={})
        apply_config(row, config.model_dump())
        db.add(row)
        db.flush()
        _audit(db, row, request.state.access_identity.subject, "create", None)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(409, "source ID already exists") from exc
        return _row(row)


@app.put("/v1/admin/sources/{key}")
def update_source(key: str, config: SourceConfig, request: Request):
    _id_or_404(key)
    if config.id != key:
        raise HTTPException(422, "source ID is immutable")
    factory = _factory()
    with factory() as db:
        row = db.scalar(select(Source).where(Source.source_key == key).with_for_update())
        if row is None:
            raise HTTPException(404, "source not found")
        if row.origin != "custom":
            raise HTTPException(409, "official definitions are maintained in Git")
        before = row.config.copy()
        apply_config(row, config.model_dump())
        _audit(db, row, request.state.access_identity.subject, "edit", before)
        db.commit()
        return _row(row)


@app.patch("/v1/admin/sources/{key}/settings")
def update_settings(key: str, changes: Settings, request: Request):
    _id_or_404(key)
    payload = changes.model_dump(exclude_unset=True)
    if not payload or any(value is None for value in payload.values()):
        raise HTTPException(422, "at least one concrete setting is required")
    factory = _factory()
    with factory() as db:
        row = db.scalar(select(Source).where(Source.source_key == key).with_for_update())
        if row is None:
            raise HTTPException(404, "source not found")
        before = row.config.copy()
        if row.origin == "official":
            cfg = _official().get(key)
            if cfg is None:
                raise HTTPException(409, "source is no longer in the official catalog")
            # Overrides are limited to operational fields; publisher URL and
            # extraction policy always come from the reviewed packaged catalog.
            overrides = {**(row.overrides or {}), **payload}
            effective = SourceConfig.model_validate({**cfg.model_dump(), **overrides})
            row.overrides = overrides
            row.catalog_revision = revision_of(cfg.model_dump())
        else:
            effective = SourceConfig.model_validate({**row.config, **payload})
        apply_config(row, effective.model_dump())
        _audit(db, row, request.state.access_identity.subject, "settings", before)
        db.commit()
        return _row(row)


@app.post("/v1/admin/sources/{key}/probe")
def probe_source(key: str):
    _id_or_404(key)
    factory = _factory()
    with factory() as db:
        row = db.scalar(select(Source).where(Source.source_key == key))
        if not row:
            raise HTTPException(404, "source not found")
        config = SourceConfig.model_validate(row.config)
    try:
        return probe(config)
    except Exception as exc:
        # No upstream bodies or credentials are returned to the administrator.
        raise HTTPException(422, f"source probe failed: {type(exc).__name__}") from exc


@app.get("/v1/admin/audits")
def audits():
    factory = _factory()
    with factory() as db:
        rows = db.scalars(select(SourceAudit).order_by(SourceAudit.id.desc()).limit(100))
        return [
            {"source_id": row.source_id, "actor": row.actor, "action": row.action,
             "created_at": row.created_at, "before": row.before, "after": row.after}
            for row in rows
        ]
