"""Integration of paginated ATS collection with source versions and rate limits."""
import json
import os
import uuid
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select

from nous import runtime
from nous.db import session_factory
from nous.models import FetchAttempt, FetchJob, Item, Source, now

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="PostgreSQL required")


def _setup_lever_source(factory, *, max_pages=2, hourly=4):
    key = "lever-test-" + uuid.uuid4().hex[:12]
    with factory() as db:
        src = Source(
            source_key=key, kind="json_api", adapter="lever_jobs_v1",
            item_kind="job_posting", url="https://api.lever.co/v0/postings/example",
            config_revision="test", config={"max_pages": max_pages, "max_concurrency": 1,
                                           "interval_minutes": 360, "max_requests_per_hour": hourly},
            enabled=True, interval_minutes=360, max_requests_per_hour=hourly,
        )
        db.add(src)
        db.flush()
        runtime.store_item(
            db, src, {"id": "original", "title": "Existing Security Engineer",
                      "url": "https://jobs.lever.co/example/original"},
            src.url,
        )
        job = FetchJob(source_id=src.id, dedupe_key=key, state="leased",
                       lease_until=now(), attempts=1)
        db.add(job)
        db.commit()
        return src.id, job.id


def _hundred_unrelated():
    return [
        {"id": str(i), "text": "General Engineer", "country": "JP",
         "categories": {"location": "Tokyo"},
         "hostedUrl": "https://jobs.lever.co/example/" + str(i)}
        for i in range(100)
    ]


def test_partial_rate_limited_board_keeps_previous_items_and_counts_requests(monkeypatch):
    factory = session_factory()
    source_id, job_id = _setup_lever_source(factory)

    def fetch(path, etag=None, modified=None):
        skip = parse_qs(urlsplit(path).query)["skip"][0]
        if skip == "0":
            return 200, json.dumps(_hundred_unrelated()).encode(), {}, path
        return 429, b"", {"retry-after": "60"}, path

    monkeypatch.setattr(runtime, "fetch", fetch)
    runtime.process(factory, job_id)
    with factory() as db:
        item = db.scalar(select(Item).where(Item.source_id == source_id))
        job = db.get(FetchJob, job_id)
        attempt = db.scalar(select(FetchAttempt).where(FetchAttempt.job_id == job_id))
        assert item.external_id == "original" and item.state == "current"
        assert job.state == "queued"
        assert attempt.http_status == 429 and attempt.request_count == 2


def test_complete_board_marks_absent_items_unknown_and_stores_job_evidence(monkeypatch):
    factory = session_factory()
    source_id, job_id = _setup_lever_source(factory)

    def fetch(path, etag=None, modified=None):
        assert parse_qs(urlsplit(path).query)["skip"] == ["0"]
        return 200, json.dumps([
            {"id": "fresh", "text": "Cybersecurity Architect", "country": "JP",
             "categories": {"location": "Tokyo", "department": "Platform"},
             "hostedUrl": "https://jobs.lever.co/example/fresh"}
        ]).encode(), {}, path

    monkeypatch.setattr(runtime, "fetch", fetch)
    runtime.process(factory, job_id)
    with factory() as db:
        old = db.scalar(select(Item).where(Item.source_id == source_id,
                                          Item.external_id == "original"))
        new = db.scalar(select(Item).where(Item.source_id == source_id,
                                          Item.external_id == "fresh"))
        assert old.state == "unknown"
        assert new.state == "current"
        assert new.current_version == 1
        assert new.title == "Cybersecurity Architect"
        assert db.get(FetchJob, job_id).state == "done"
        attempt = db.scalar(select(FetchAttempt).where(FetchAttempt.job_id == job_id))
        assert attempt.request_count == 1


def test_claim_reserves_worst_case_page_budget(monkeypatch):
    factory = session_factory()
    source_id, _ = _setup_lever_source(factory, max_pages=3, hourly=4)
    with factory() as db:
        # A completed fetch that used 2 requests leaves fewer than 3 for the
        # next board snapshot; no additional URLs may be fetched this hour.
        source = db.get(Source, source_id)
        existing = FetchJob(source_id=source_id,
                            dedupe_key="old-" + uuid.uuid4().hex,
                            state="done", attempts=1)
        db.add(existing)
        db.flush()
        db.add(FetchAttempt(job_id=existing.id, started_at=now(), ended_at=now(),
                            outcome="success", request_count=2))
        current = FetchJob(source_id=source_id,
                           dedupe_key="next-" + uuid.uuid4().hex,
                           state="queued", attempts=0)
        db.add(current)
        db.commit()
        next_id = current.id
    assert runtime.claim(factory) is None
    with factory() as db:
        job = db.get(FetchJob, next_id)
        assert job.state == "queued"
        assert job.attempts == 0
        assert job.available_at > now()
