"""Operator-only source management on the Access-authenticated gateway.

No GitHub credential or remote MCP mutation. The admin gateway uses a distinct
database role and an explicit Access subject allowlist; source definitions and
audit history are private to this instance.
"""
from __future__ import annotations

import os
from functools import lru_cache
import re
from pathlib import Path
from datetime import datetime, time, timedelta, timezone
from typing import Any, Literal
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, create_engine, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from .models import (FetchJob, Report, ReportRun, ReportSchedule, Source, SourceAudit, now)
from .onboard_source import probe
from .registry import SourceConfig, apply_config, load_registry, revision_of
from .report_templates import (normalize_parameters, public_template_list,
                               resolve_template)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
_SOURCE_ID = re.compile(r"^[a-z][a-z0-9-]{2,99}$")
_REPORT_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,126}$")
_MAX_REQUEST = 16384


@lru_cache(maxsize=4)
def _factory_for_dsn(dsn):
    return sessionmaker(create_engine(dsn, pool_pre_ping=True))


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
    return _factory_for_dsn(dsn)


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


class ReportRunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    template_id: Literal["security-daily", "cve-kev-deep-dive"]
    parameters: dict[str, Any]
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=128,
                                        pattern=r"^[A-Za-z0-9._:-]+$")


class ReportScheduleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    template_id: Literal["security-daily"]
    parameters: dict[str, Any]
    timezone: str = Field(min_length=1, max_length=64)
    cadence: Literal["daily", "weekly"]
    local_time: str = Field(pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")


class ReportScheduleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


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
        # Do not relabel a live fetch with a new publisher URL or parser.
        active = db.scalar(select(FetchJob.id).where(
            FetchJob.source_id == row.id, FetchJob.state == "leased",
            FetchJob.lease_until > now()
        ).limit(1))
        if active is not None:
            raise HTTPException(409, "wait for the active fetch before editing")
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


def _published_url(db, report_id):
    if not report_id:
        return None
    row = db.execute(select(Report.category, Report.slug).where(Report.id == report_id)).first()
    if row is None or row.category not in {"security", "cve"} or not _REPORT_SLUG.fullmatch(row.slug):
        return None
    return f"/reports/{row.category}/{row.slug}/"


def _run_list_row(db, row):
    return {
        "run_id": row.id,
        "template_id": row.template_id,
        "created_at": row.created_at,
        "trigger": row.trigger,
        "state": row.state,
        "stage": row.stage,
        "attempts": row.attempts,
        "error_code": row.error_code,
        "published_url": _published_url(db, row.report_id),
    }


def _schedule_row(row):
    return {
        "id": row.id,
        "template_id": row.template_id,
        "template_revision": row.template_revision,
        "parameters": {"category": row.parameters.get("category")},
        "timezone": row.timezone,
        "cadence": row.cadence,
        "local_time": row.local_time,
        "next_slot_at": row.next_slot_at,
        "enabled": row.enabled,
        "created_at": row.created_at,
    }


@app.get("/v1/admin/report-templates")
def report_templates():
    return public_template_list()


@app.post("/v1/admin/report-runs", status_code=202)
def create_report_run(body: ReportRunCreate, request: Request):
    try:
        template = resolve_template(body.template_id)
        parameters = normalize_parameters(body.template_id, body.parameters, now=now())
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(422, "invalid report template parameters") from exc
    key = body.idempotency_key or str(uuid.uuid4())
    current = now()
    factory = _factory()
    with factory() as db:
        existing = db.scalar(select(ReportRun).where(ReportRun.idempotency_key == key))
        if existing is not None:
            if (existing.template_id != body.template_id or existing.parameters != parameters or
                    existing.template_revision != template["revision_key"]):
                raise HTTPException(409, "idempotency key is already used for different input")
            return {"run_id": existing.id, "state": existing.state}
        row = ReportRun(
            id=str(uuid.uuid4()), trigger="manual", created_by=request.state.access_identity.subject,
            template_id=body.template_id, template_revision=template["revision_key"],
            template_snapshot=template, parameters=parameters, idempotency_key=key,
            state="queued", stage="queued", attempts=0, available_at=current,
            stage_artifacts={}, created_at=current,
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            existing = db.scalar(select(ReportRun).where(ReportRun.idempotency_key == key))
            if (existing is not None and existing.template_id == body.template_id and
                    existing.parameters == parameters and
                    existing.template_revision == template["revision_key"]):
                return {"run_id": existing.id, "state": existing.state}
            raise HTTPException(409, "idempotency key is already used") from exc
        return {"run_id": row.id, "state": row.state}


@app.get("/v1/admin/report-runs")
def report_runs(limit: int = Query(50, ge=1, le=100), cursor: str | None = None):
    factory = _factory()
    with factory() as db:
        query = select(ReportRun).order_by(ReportRun.created_at.desc(), ReportRun.id.desc())
        if cursor is not None:
            try:
                cursor_id = str(uuid.UUID(cursor))
            except (ValueError, TypeError, AttributeError) as exc:
                raise HTTPException(422, "invalid report run cursor") from exc
            cursor_row = db.get(ReportRun, cursor_id)
            if cursor_row is None:
                raise HTTPException(422, "invalid report run cursor")
            query = query.where(or_(
                ReportRun.created_at < cursor_row.created_at,
                and_(ReportRun.created_at == cursor_row.created_at,
                     ReportRun.id < cursor_row.id),
            ))
        rows = db.scalars(query.limit(limit + 1)).all()
        has_more = len(rows) > limit
        rows = rows[:limit]
        return {"runs": [_run_list_row(db, row) for row in rows],
                "next_cursor": rows[-1].id if has_more and rows else None}


@app.get("/v1/admin/report-runs/{run_id}")
def report_run(run_id: str):
    try:
        run_id = str(uuid.UUID(run_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(404, "report run not found") from exc
    factory = _factory()
    with factory() as db:
        row = db.get(ReportRun, run_id)
        if row is None:
            raise HTTPException(404, "report run not found")
        result = _run_list_row(db, row)
        stage_order = ("evidence", "plan", "fact_check", "draft", "article",
                       "article_validated", "publishing", "published")
        artifacts = row.stage_artifacts if isinstance(row.stage_artifacts, dict) else {}
        stages = {name: "complete" for name in stage_order if name in artifacts}
        if row.stage in stage_order and row.stage not in stages:
            stages[row.stage] = "running" if row.state in {
                "leased", "running", "validating", "publishing"} else row.state
        result.update(parameters=row.parameters, stages=stages)
        return result


@app.get("/v1/admin/report-schedules")
def report_schedules():
    factory = _factory()
    with factory() as db:
        rows = db.scalars(select(ReportSchedule).order_by(
            ReportSchedule.created_at.desc(), ReportSchedule.id.desc()).limit(100))
        return {"schedules": [_schedule_row(row) for row in rows]}


@app.post("/v1/admin/report-schedules", status_code=201)
def create_report_schedule(body: ReportScheduleCreate, request: Request):
    if set(body.parameters) - {"category"}:
        raise HTTPException(422, "unsupported schedule parameters")
    try:
        zone = ZoneInfo(body.timezone)
        template = resolve_template("security-daily")
        normalized = normalize_parameters("security-daily", {
            "timezone": body.timezone, "category": body.parameters.get("category"),
        }, now=now())
    except (KeyError, TypeError, ValueError, ZoneInfoNotFoundError) as exc:
        raise HTTPException(422, "invalid report schedule") from exc
    current = now()
    local_time = time.fromisoformat(body.local_time)
    local_current = current.astimezone(zone)
    slot_local = datetime.combine(local_current.date(), local_time, tzinfo=zone)
    if body.cadence == "weekly":
        # A weekly schedule starts on its creation weekday and keeps that day.
        if slot_local.astimezone(timezone.utc) <= current:
            slot_local += timedelta(days=7)
    elif slot_local.astimezone(timezone.utc) <= current:
        slot_local += timedelta(days=1)
    slot = slot_local.astimezone(timezone.utc)
    row = ReportSchedule(
        id=str(uuid.uuid4()), template_id="security-daily",
        template_revision=template["revision_key"], template_snapshot=template,
        parameters={"category": normalized["category"]}, timezone=body.timezone,
        cadence=body.cadence, local_time=body.local_time, next_slot_at=slot,
        enabled=True, created_by=request.state.access_identity.subject,
        created_at=current, updated_at=current,
    )
    factory = _factory()
    with factory() as db:
        db.add(row)
        db.commit()
        return _schedule_row(row)


@app.patch("/v1/admin/report-schedules/{schedule_id}")
def update_report_schedule(schedule_id: str, changes: ReportScheduleUpdate):
    try:
        schedule_id = str(uuid.UUID(schedule_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(404, "report schedule not found") from exc
    factory = _factory()
    with factory() as db:
        row = db.scalar(select(ReportSchedule).where(
            ReportSchedule.id == schedule_id).with_for_update())
        if row is None:
            raise HTTPException(404, "report schedule not found")
        row.enabled = changes.enabled
        row.updated_at = now()
        db.commit()
        return _schedule_row(row)
