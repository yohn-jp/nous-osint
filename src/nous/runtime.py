import hashlib
import json
import logging
import socket
import time
import httpx
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
from sqlalchemy import func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert
from .adapters import extract
from .job_postings import fetch_lever_board
from .cve_index import cve_relations, record_item_version_cves, sync_item_cves
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
        scheduled = 0
        for source in due:
            # A source has at most one queued/leased poll. Keeping the cadence
            # advance even when a poll is pending prevents outage catch-up from
            # creating an unbounded backlog or replaying stale catalog states.
            pending = db.scalar(select(FetchJob.id).where(
                FetchJob.source_id == source.id,
                FetchJob.state.in_(("queued", "leased")),
            ).limit(1))
            if pending is None:
                # The due timestamp is stable until this transaction commits.
                key = hashlib.sha256(f"{source.source_key}\0{source.next_due_at.isoformat()}".encode()).hexdigest()
                db.add(FetchJob(source_id=source.id, dedupe_key=key))
                scheduled += 1
            source.next_due_at = now() + timedelta(minutes=source.interval_minutes)
        db.commit()
        event("scheduled", count=scheduled, deferred=len(due) - scheduled)

def claim(factory):
    with factory() as db:
        current = now()
        job = db.scalar(select(FetchJob).where(
            or_(FetchJob.state == "queued", (FetchJob.state == "leased") &
                (FetchJob.lease_until < current)), FetchJob.available_at <= current)
            .order_by(FetchJob.available_at, FetchJob.id).with_for_update(skip_locked=True))
        if job is None:
            return None
        # An abandoned lease counts toward the same retry budget as caught failures.
        if job.attempts >= 5:
            job.state = "failed"
            job.lease_until = None
            db.commit()
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
        count = db.scalar(select(func.coalesce(func.sum(FetchAttempt.request_count), 0))
                          .select_from(FetchAttempt).join(FetchJob)
                          .where(FetchJob.source_id == source.id, FetchAttempt.started_at >= earliest))
        required = source.config.get("max_pages", 1) if source.adapter == "lever_jobs_v1" else 1
        if count + required > source.max_requests_per_hour:
            job.available_at = current + timedelta(minutes=10)
            db.commit()
            return None
        job.state = "leased"
        job.lease_until = current + timedelta(minutes=5)
        job.attempts += 1
        attempt = job.attempts
        db.commit()
        # The attempt generation fences a Worker whose lease expires while it
        # is performing network I/O. The ID alone can be reclaimed by another.
        return job.id, attempt

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
    if source.item_kind == "job_posting" and isinstance(raw.get("job"), dict):
        attrs["job"] = raw["job"]
    if source.item_kind == "vulnerability" and isinstance(raw.get("vulnerability"), dict):
        attrs["vulnerability"] = raw["vulnerability"]
    if source.item_kind != "job_posting":
        # Freeze exact CVE identities/relation grades into this immutable
        # observation so cutoff queries do not inherit a later link mutation.
        attrs["cve_relations"] = cve_relations(source, raw)
    digest = hashlib.sha256(json.dumps(attrs, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    db.execute(insert(Item).values(source_id=source.id, external_id=external_id,
                                   canonical_url=url, kind=source.item_kind, title=title)
               .on_conflict_do_nothing(index_elements=["source_id", "external_id"]))
    item = db.scalar(select(Item).where(Item.source_id == source.id, Item.external_id == external_id)
                     .with_for_update())
    # Correlate CVE and KEV identities transactionally with this observation.
    # A publisher title mention never becomes an authoritative KEV assertion.
    if source.item_kind != "job_posting":
        sync_item_cves(db, item, source, raw)
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
        version = ItemVersion(item_id=item.id, version=item.current_version, sha256=digest,
                              attributes=attrs, provenance={"source_url": source.url,
                              "final_url": final_url, "item_url": url,
                              "retrieved_at": now().isoformat(), "adapter": source.adapter,
                              "extraction_method": "deterministic_parser"})
        db.add(version)
        db.flush()
        record_item_version_cves(db, version.id, attrs.get("cve_relations", {}))

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

def process(factory, job_id, claim_attempt=None):
    """Fetch and persist only if this Worker still owns its claim generation.

    A missing claim_attempt is supported for isolated ingestion fixtures only;
    the scheduler/Worker entry point always passes claim()'s generation.
    """
    with factory() as db:
        job = db.get(FetchJob, job_id)
        source = db.get(Source, job.source_id)
        url, etag, modified = source.url, source.etag, source.last_modified
    started = now()
    status = None
    final_url = None
    error = None
    retry_after = None
    retryable_fetch_failure = False
    requests_made = 0

    def counted_fetch(*args):
        nonlocal requests_made
        requests_made += 1
        return fetch(*args)

    try:
        if source.adapter == "lever_jobs_v1":
            # All pages must succeed before store_item or missing-item state
            # changes. Lever does not use a first-page conditional ETag.
            status, records, headers, final_url = fetch_lever_board(source, counted_fetch)
        else:
            status, body, headers, final_url = counted_fetch(url, etag, modified)
        if status == 304:
            outcome = "unchanged"
            records = []
        elif status == 200:
            if source.adapter != "lever_jobs_v1":
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
        # HTTPX transports and DNS resolution fail before an HTTP status exists.
        retryable_fetch_failure = isinstance(
            exc, (httpx.TransportError, socket.gaierror, ConnectionError, TimeoutError)
        )
        error = type(exc).__name__ + ":" + str(exc)[:80]
        outcome = "failure"
        records = []
        headers = {}
    with factory() as db:
        job = db.scalar(select(FetchJob).where(
            FetchJob.id == job_id
        ).with_for_update())
        # Fetching occurs outside the lease transaction; a slow fetch may
        # finish after a different Worker has reclaimed the same job. Lock and
        # check the generation, state, and expiration before any item mutation.
        if claim_attempt is not None and (
            job is None or job.attempts != claim_attempt or
            job.state != "leased" or job.lease_until is None or
            job.lease_until <= now()
        ):
            db.add(FetchAttempt(
                job_id=job_id, started_at=started, ended_at=now(),
                outcome="stale_lease", http_status=status, final_url=final_url,
                error_code="stale_lease", request_count=max(requests_made, 1),
            ))
            db.commit()
            event("fetch_discarded", job=job_id, reason="stale_lease")
            return
        source = db.get(Source, job.source_id)
        try:
            for raw in records:
                store_item(db, source, raw, final_url)
            if outcome == "unchanged":
                # 304 confirms the unchanged representation still describes the
                # current records; absent/unknown entries are not resurrected.
                db.execute(update(Item).where(Item.source_id == source.id,
                                              Item.state == "current")
                           .values(last_seen_at=now()))
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
            # Rollback drops the FOR UPDATE lock. Reacquire it and fence again
            # before changing the job's retry state: another Worker can claim
            # this job between the failed observation TX and recovery.
            job = db.scalar(select(FetchJob).where(
                FetchJob.id == job_id
            ).with_for_update())
            if claim_attempt is not None and (
                job is None or job.attempts != claim_attempt or
                job.state != "leased" or job.lease_until is None or
                job.lease_until <= now()
            ):
                db.add(FetchAttempt(
                    job_id=job_id, started_at=started, ended_at=now(),
                    outcome="stale_lease", http_status=status, final_url=final_url,
                    error_code="stale_lease", request_count=max(requests_made, 1),
                ))
                db.commit()
                event("fetch_discarded", job=job_id, reason="stale_lease")
                return
            source = db.get(Source, job.source_id)
            error = str(exc)[:100]
            source.last_error = error
            retryable = retryable_fetch_failure or status in (429, 500, 502, 503, 504)
            job.state = "queued" if retryable and job.attempts < 5 else "failed"
            if job.state == "queued":
                delay = min(3600, max(retry_after or 0, 30 * 2 ** job.attempts))
                job.available_at = now() + timedelta(seconds=delay)
            outcome = "failure"
        db.add(FetchAttempt(job_id=job_id, started_at=started, ended_at=now(), outcome=outcome,
                            http_status=status, final_url=final_url, error_code=error,
                            request_count=max(requests_made, 1)))
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
                claimed = claim(factory)
                if claimed:
                    process(factory, *claimed)
                else:
                    time.sleep(5)
        except Exception as exc:
            event("runtime_error", error=str(exc)[:120])
            time.sleep(10)

if __name__ == "__main__":
    import sys
    main(sys.argv[1])
