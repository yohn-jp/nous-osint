import hashlib
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
from sqlalchemy import func, or_, select, text
from sqlalchemy.dialects.postgresql import insert
from .adapters import extract
from .db import session_factory
from .fetch import fetch
from .models import FetchAttempt, FetchJob, Item, ItemVersion, Source, now
from .registry import load_registry, sync

logging.basicConfig(level=logging.INFO, format='%(message)s')
log = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)

def event(name, **fields):
    log.info(json.dumps({"event": name, **fields}, default=str))

def schedule_once(factory):
    with factory() as db:
        sync(db, load_registry())
        due = db.scalars(select(Source).where(Source.enabled.is_(True), Source.next_due_at <= now())
                         .with_for_update(skip_locked=True)).all()
        for source in due:
            # The due timestamp is stable until this transaction commits.
            key = f"{source.source_key}:{source.next_due_at.isoformat()}"
            db.add(FetchJob(source_id=source.id, dedupe_key=key))
            source.next_due_at = now() + timedelta(minutes=source.interval_minutes)
        db.commit()
        event("scheduled", count=len(due))

def claim(factory):
    with factory() as db:
        current = now()
        job = db.scalar(select(FetchJob).where(
            or_(FetchJob.state == "queued", (FetchJob.state == "leased") &
                (FetchJob.lease_until < current)), FetchJob.available_at <= current)
            .order_by(FetchJob.available_at, FetchJob.id).with_for_update(skip_locked=True))
        if job is None:
            return None
        source = db.scalar(select(Source).where(Source.id == job.source_id).with_for_update())
        if not source.enabled:
            job.state = "cancelled"
            db.commit()
            return None
        host = urlparse(source.url).hostname
        lock_key = int.from_bytes(hashlib.sha256(host.encode()).digest()[:8], "big", signed=True)
        db.execute(text("select pg_advisory_xact_lock(:key)"), {"key": lock_key})
        active = db.execute(select(FetchJob, Source).join(Source, FetchJob.source_id == Source.id)
                            .where(FetchJob.state == "leased", FetchJob.lease_until > current)).all()
        source_active = sum(j.source_id == source.id for j, _ in active)
        host_active = sum(urlparse(s.url).hostname == host for _, s in active)
        if source_active >= source.config["max_concurrency"] or host_active >= 1:
            job.available_at = current + timedelta(seconds=15)
            db.commit()
            return None
        earliest = current - timedelta(hours=1)
        count = db.scalar(select(func.count()).select_from(FetchAttempt).join(FetchJob)
                          .where(FetchJob.source_id == source.id, FetchAttempt.started_at >= earliest))
        if count >= source.max_requests_per_hour:
            job.available_at = current + timedelta(minutes=10)
            db.commit()
            return None
        job.state = "leased"
        job.lease_until = current + timedelta(minutes=5)
        job.attempts += 1
        db.commit()
        return job.id

def store_item(db, source, raw, final_url):
    external_id = raw.get("id") or raw.get("url")
    title = raw.get("title")
    url = raw.get("url")
    if not isinstance(external_id, str) or not isinstance(title, str) or not isinstance(url, str):
        raise ValueError("missing item identity, title or URL")
    if not url.startswith("https://") or len(title) > 1000:
        raise ValueError("invalid item URL or title")
    attrs = {"title": title.strip(), "url": url, "published": raw.get("published"),
             "updated": raw.get("updated")}
    digest = hashlib.sha256(json.dumps(attrs, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    db.execute(insert(Item).values(source_id=source.id, external_id=external_id,
                                   canonical_url=url, kind=source.item_kind, title=title)
               .on_conflict_do_nothing(index_elements=["source_id", "external_id"]))
    item = db.scalar(select(Item).where(Item.source_id == source.id, Item.external_id == external_id)
                     .with_for_update())
    item.last_seen_at = now()
    item.state = "current"
    item.organization = source.config.get("organization")
    item.published_at = parse_timestamp(raw.get("published"))
    item.updated_at = parse_timestamp(raw.get("updated"))
    if item.current_hash != digest:
        item.current_version += 1
        item.current_hash = digest
        item.title = title
        item.canonical_url = url
        db.add(ItemVersion(item_id=item.id, version=item.current_version, sha256=digest,
                           attributes=attrs, provenance={"source_url": source.url,
                           "final_url": final_url, "item_url": url,
                           "retrieved_at": now().isoformat(), "adapter": source.adapter,
                           "extraction_method": "deterministic_parser"}))

def parse_timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None

def process(factory, job_id):
    with factory() as db:
        job = db.get(FetchJob, job_id)
        source = db.get(Source, job.source_id)
        url, etag, modified = source.url, source.etag, source.last_modified
    started = now()
    status = None
    final_url = None
    error = None
    retry_after = None
    try:
        status, body, headers, final_url = fetch(url, etag, modified)
        if status == 304:
            outcome = "unchanged"
            records = []
        elif status == 200:
            records = extract(source, body, final_url)
            outcome = "success"
        elif status == 429:
            value = headers.get("retry-after")
            if value:
                try:
                    retry_after = int(value)
                except ValueError:
                    retry_after = max(0, int((parsedate_to_datetime(value) - now()).total_seconds()))
            raise RuntimeError("rate_limited")
        elif status >= 500:
            raise RuntimeError("upstream_error")
        else:
            raise ValueError(f"http_{status}")
    except Exception as exc:
        error = type(exc).__name__ + ":" + str(exc)[:80]
        outcome = "failure"
        records = []
        headers = {}
    with factory() as db:
        job = db.get(FetchJob, job_id)
        source = db.get(Source, job.source_id)
        try:
            for raw in records:
                store_item(db, source, raw, final_url)
            if outcome == "success":
                seen = {raw.get("id") or raw.get("url") for raw in records}
                for old_item in db.scalars(select(Item).where(Item.source_id == source.id)):
                    if old_item.external_id not in seen:
                        old_item.state = ("stale" if old_item.state == "unknown" and
                                          old_item.last_seen_at < now() - timedelta(days=7)
                                          else "unknown")
            if outcome != "failure":
                source.last_success_at = now()
                source.last_error = None
                source.etag = headers.get("etag", source.etag)
                source.last_modified = headers.get("last-modified", source.last_modified)
                job.state = "done"
            else:
                raise ValueError(error)
        except Exception as exc:
            db.rollback()
            job = db.get(FetchJob, job_id)
            source = db.get(Source, job.source_id)
            error = str(exc)[:100]
            source.last_error = error
            retryable = status in (429, 500, 502, 503, 504) or "Timeout" in error
            job.state = "queued" if retryable and job.attempts < 5 else "failed"
            if job.state == "queued":
                delay = min(3600, max(retry_after or 0, 30 * 2 ** job.attempts))
                job.available_at = now() + timedelta(seconds=delay)
            outcome = "failure"
        db.add(FetchAttempt(job_id=job_id, started_at=started, ended_at=now(), outcome=outcome,
                            http_status=status, final_url=final_url, error_code=error))
        db.commit()
        event("fetch", source=source.source_key, outcome=outcome, status=status, error=error)

def main(mode):
    factory = session_factory()
    while True:
        try:
            if mode == "scheduler":
                schedule_once(factory)
                time.sleep(30)
            else:
                job_id = claim(factory)
                if job_id:
                    process(factory, job_id)
                else:
                    time.sleep(5)
        except Exception as exc:
            event("runtime_error", error=str(exc)[:120])
            time.sleep(10)

if __name__ == "__main__":
    import sys
    main(sys.argv[1])
