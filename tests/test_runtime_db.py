import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from sqlalchemy import func, select
import pytest
from nous import runtime
from nous.db import session_factory
from nous.models import FetchAttempt, FetchJob, Item, ItemVersion, Source

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="PostgreSQL required")


def test_host_concurrency_claim():
    factory = session_factory()
    key = "concurrent-" + uuid.uuid4().hex[:12]
    ids = []
    with factory() as db:
        for suffix in ("a", "b"):
            source = Source(source_key=key + suffix, kind="json_api",
                            url=f"https://same-host.example/{suffix}", adapter="json_v1",
                            item_kind="news", config_revision="test",
                            config={"max_concurrency": 1}, enabled=True, interval_minutes=60,
                            max_requests_per_hour=10)
            db.add(source)
            db.flush()
            job = FetchJob(source_id=source.id, dedupe_key=key + suffix)
            db.add(job)
            db.flush()
            ids.append(job.id)
        db.commit()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: runtime.claim(factory), range(2)))
    assert sum(result in ids for result in results) == 1
    assert results.count(None) == 1
    with factory() as db:
        states = [db.get(FetchJob, job_id).state for job_id in ids]
        assert sorted(states) == ["leased", "queued"]


def test_concurrent_same_item_creates_one_version():
    factory = session_factory()
    key = "same-item-" + uuid.uuid4().hex[:12]
    with factory() as db:
        source = Source(source_key=key, kind="json_api", url="https://example.org/api",
                        adapter="json_v1", item_kind="news", config_revision="test",
                        config={"max_concurrency": 1}, enabled=True, interval_minutes=60,
                        max_requests_per_hour=10)
        db.add(source)
        db.commit()
        source_id = source.id

    gate = Barrier(2)
    def write(_):
        with factory() as db:
            source = db.get(Source, source_id)
            gate.wait()
            runtime.store_item(db, source, {"id": "same", "title": "Same title",
                                            "url": "https://example.org/same"}, source.url)
            db.commit()

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(write, range(2)))
    with factory() as db:
        items = db.scalars(select(Item).where(Item.source_id == source_id)).all()
        assert len(items) == 1
        assert db.scalar(select(func.count()).select_from(ItemVersion)
                         .where(ItemVersion.item_id == items[0].id)) == 1

def test_versioning_and_failures(monkeypatch):
    factory = session_factory()
    key = "test-" + uuid.uuid4().hex[:12]
    with factory() as db:
        source = Source(source_key=key, kind="json_api", url="https://example.org/api",
                        adapter="json_v1", item_kind="news", config_revision="test",
                        config={"max_concurrency": 1}, enabled=True, interval_minutes=60,
                        max_requests_per_hour=4)
        db.add(source)
        db.flush()
        job = FetchJob(source_id=source.id, dedupe_key=key)
        db.add(job)
        db.commit()
        job_id, source_id = job.id, source.id

    def response(title):
        payload = [{"id": "story-1", "url": "https://example.org/story-1", "title": title}]
        return 200, json.dumps(payload).encode(), {}, "https://example.org/api"

    monkeypatch.setattr(runtime, "fetch", lambda *a: response("Original"))
    runtime.process(factory, job_id)
    runtime.process(factory, job_id)
    with factory() as db:
        item = db.scalar(select(Item).where(Item.source_id == source_id))
        assert db.scalar(select(func.count()).select_from(ItemVersion).where(ItemVersion.item_id == item.id)) == 1

    monkeypatch.setattr(runtime, "fetch", lambda *a: response("Updated"))
    runtime.process(factory, job_id)
    with factory() as db:
        item = db.scalar(select(Item).where(Item.source_id == source_id))
        assert item.current_version == 2

    monkeypatch.setattr(runtime, "fetch", lambda *a: (304, b"", {}, "https://example.org/api"))
    runtime.process(factory, job_id)
    monkeypatch.setattr(runtime, "fetch", lambda *a: (429, b"", {"retry-after": "120"}, "https://example.org/api"))
    runtime.process(factory, job_id)
    with factory() as db:
        assert db.get(FetchJob, job_id).state == "queued"
        assert db.scalar(select(FetchAttempt).where(FetchAttempt.job_id == job_id)
                         .order_by(FetchAttempt.id.desc())).http_status == 429

    monkeypatch.setattr(runtime, "fetch", lambda *a: (_ for _ in ()).throw(TimeoutError("timeout")))
    runtime.process(factory, job_id)
    monkeypatch.setattr(runtime, "fetch", lambda *a: (200, b"not-json", {}, "https://example.org/api"))
    runtime.process(factory, job_id)
    with factory() as db:
        item = db.scalar(select(Item).where(Item.source_id == source_id))
        assert item.current_version == 2
        assert db.get(FetchJob, job_id).state == "failed"



def test_exhausted_expired_lease_is_failed_without_reclaim():
    from datetime import timedelta
    from nous.models import now
    factory = session_factory()
    key = "exhausted-" + uuid.uuid4().hex[:12]
    with factory() as db:
        source = Source(source_key=key, kind="rss", url="https://exhausted.example/feed",
                        adapter="rss_v1", item_kind="news", config_revision="test",
                        config={"max_concurrency": 1}, enabled=True, interval_minutes=60,
                        max_requests_per_hour=5)
        db.add(source)
        db.flush()
        job = FetchJob(source_id=source.id, dedupe_key=key, state="leased",
                       lease_until=now() - timedelta(minutes=1), attempts=5)
        db.add(job)
        db.commit()
        job_id = job.id
    assert runtime.claim(factory) is None
    with factory() as db:
        job = db.get(FetchJob, job_id)
        assert job.state == "failed"
        assert job.attempts == 5
        assert job.lease_until is None


def test_fetch_connection_errors_retry_without_http_status(monkeypatch):
    import httpx
    factory = session_factory()
    key = "connection-" + uuid.uuid4().hex[:12]
    with factory() as db:
        source = Source(source_key=key, kind="rss", url="https://connection.example/feed",
                        adapter="rss_v1", item_kind="news", config_revision="test",
                        config={"max_concurrency": 1}, enabled=True, interval_minutes=60,
                        max_requests_per_hour=5)
        db.add(source)
        db.flush()
        job = FetchJob(source_id=source.id, dedupe_key=key, attempts=1)
        db.add(job)
        db.commit()
        job_id = job.id

    def connection_lost(*_args):
        raise httpx.ConnectError("temporary DNS failure")
    monkeypatch.setattr(runtime, "fetch", connection_lost)
    runtime.process(factory, job_id)
    with factory() as db:
        job = db.get(FetchJob, job_id)
        assert job.state == "queued"
        assert job.available_at > job.lease_until if job.lease_until else job.available_at is not None


def test_long_source_id_job_key_fits_database(monkeypatch):
    from nous.registry import load_registry
    factory = session_factory()
    long_id = "a" + uuid.uuid4().hex + "z" * 67
    assert len(long_id) == 100
    source = load_registry("sources")[0].model_copy(update={"id": long_id})
    monkeypatch.setattr(runtime, "load_registry", lambda: [source])
    runtime.schedule_once(factory)
    with factory() as db:
        row = db.scalar(select(Source).where(Source.source_key == long_id))
        job = db.scalar(select(FetchJob).where(FetchJob.source_id == row.id))
        assert len(job.dedupe_key) == 64


def test_304_refreshes_current_record_observation(monkeypatch):
    from datetime import timedelta
    from nous.models import now
    factory = session_factory()
    key = "not-modified-" + uuid.uuid4().hex[:12]
    with factory() as db:
        source = Source(source_key=key, kind="rss", url="https://unmodified.example/feed",
                        adapter="rss_v1", item_kind="news", config_revision="test",
                        config={"max_concurrency": 1}, enabled=True, interval_minutes=60,
                        max_requests_per_hour=5)
        db.add(source)
        db.flush()
        item = Item(source_id=source.id, external_id="old", canonical_url="https://unmodified.example/old",
                    title="Known item", kind="news", state="current", last_seen_at=now() - timedelta(days=3),
                    current_version=1)
        unknown = Item(source_id=source.id, external_id="missing", canonical_url="https://unmodified.example/missing",
                       title="Unknown item", kind="news", state="unknown",
                       last_seen_at=now() - timedelta(days=3), current_version=1)
        db.add_all([item, unknown])
        db.flush()
        job = FetchJob(source_id=source.id, dedupe_key=key)
        db.add(job)
        db.commit()
        ids = (item.id, unknown.id)
        job_id = job.id
    monkeypatch.setattr(runtime, "fetch", lambda *a: (304, b"", {}, "https://unmodified.example/feed"))
    runtime.process(factory, job_id)
    with factory() as db:
        assert db.get(Item, ids[0]).last_seen_at > now() - timedelta(minutes=2)
        assert db.get(Item, ids[1]).last_seen_at < now() - timedelta(days=2)
        assert db.get(Item, ids[1]).state == "unknown"


def test_change_history_uses_version_title():
    from nous.api import changes
    from nous.models import now
    factory = session_factory()
    key = "history-" + uuid.uuid4().hex[:12]
    with factory() as db:
        source = Source(source_key=key, kind="rss", url="https://history.example/feed",
                        adapter="rss_v1", item_kind="news", config_revision="test",
                        config={"max_concurrency": 1}, enabled=True, interval_minutes=60,
                        max_requests_per_hour=5)
        db.add(source)
        db.flush()
        item = Item(source_id=source.id, external_id="a", canonical_url="https://history.example/a",
                    title="New title", kind="news", current_version=2, current_hash="hash")
        db.add(item)
        db.flush()
        db.add_all([
            ItemVersion(item_id=item.id, version=1, sha256="a" * 64,
                        attributes={"title": "Original title"}, provenance={}),
            ItemVersion(item_id=item.id, version=2, sha256="b" * 64,
                        attributes={"title": "New title"}, provenance={}),
        ])
        db.commit()
        original_id = item.id
    response = changes(since=now() - timedelta(days=1), limit=100)
    titles = [c["title"] for c in response["changes"] if c["item_id"] == original_id]
    assert titles == ["New title", "Original title"]
