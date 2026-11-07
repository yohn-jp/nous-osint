"""Official X API opt-in author timeline: no network or charge in tests."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from nous import x_timeline
from nous.db import Base
from nous.models import FetchAttempt, FetchJob, Item, Source
from nous.registry import SourceConfig

ACCOUNT = "2244994945"  # Numeric identifier used in official X API examples.
URL = f"https://api.x.com/2/users/{ACCOUNT}/tweets"
WHEN = datetime(2026, 11, 7, 9, tzinfo=timezone.utc)


def post(tweet="2000000000000000011", author=ACCOUNT, text="Security update CVE-2026-12345"):
    return {"id": tweet, "author_id": author, "text": text,
            "created_at": "2026-11-07T08:50:00.000Z"}


def body(records, next_token=None):
    meta = {"result_count": len(records)}
    if next_token:
        meta["next_token"] = next_token
    return json.dumps({"data": records, "meta": meta}).encode()


def test_only_official_numeric_user_ids_are_accepted():
    assert x_timeline.author_id_from_url(URL) == ACCOUNT
    for url in (
        URL.replace("api.x.com", "api.evil.example"),
        URL.replace(ACCOUNT, "account_name"),
        URL.replace("https", "http"),
        URL + "?unknown=true",
        URL + "#fragment",
        URL.replace("api.x.com", "api.x.com:444"),
        "https://api.x.com/2/tweets/search/recent",
    ):
        with pytest.raises(ValueError):
            x_timeline.author_id_from_url(url)


def test_parsing_author_identity_dates_and_no_extra_content():
    posts, next_token = x_timeline.parse_x_page(body([post()]), ACCOUNT)
    assert next_token is None
    assert posts == [{"id": "2000000000000000011",
                      "url": "https://x.com/i/web/status/2000000000000000011",
                      "title": "Security update CVE-2026-12345",
                      "published": "2026-11-07T08:50:00.000Z"}]
    assert "record" not in json.dumps(posts)
    for invalid in (
        body([post(author="444")]),
        body([post(tweet="bad-post-id")]),
        json.dumps({"data": [post()], "meta": {"result_count": 2}}).encode(),
        json.dumps({"data": [post()], "errors": [{"detail": "partial"}],
                    "meta": {"result_count": 1}}).encode(),
        b"not-json",
        body([post()] * 11),
        body([post(), post()]),
    ):
        with pytest.raises(ValueError):
            x_timeline.parse_x_page(invalid, ACCOUNT)


def test_incremental_since_id_and_pagination_preserves_full_order(monkeypatch):
    monkeypatch.setenv("NOUS_X_BEARER_TOKEN", "test-token")
    monkeypatch.setenv("NOUS_X_MAX_DAILY_POST_READS", "100")
    urls = []
    calls = []
    def request(url, token):
        assert token == "test-token"
        urls.append(url)
        if len(urls) == 1:
            return 200, body([post("2000000000000000020")], "next_1"), {}, url
        return 200, body([post("2000000000000000019")]), {}, url

    status, rows, _, final_url = x_timeline.fetch_x_timeline(
        URL, since_id="2000000000000000010", max_pages=2,
        on_request=lambda: calls.append(1), request_page=request,
    )
    assert status == 200
    assert len(rows) == len(calls) == len(urls) == 2
    assert "since_id=2000000000000000010" in urls[0]
    assert "pagination_token=next_1" in urls[1]
    assert final_url == urls[-1]


def test_incomplete_page_is_rejected_not_silently_lost(monkeypatch):
    monkeypatch.setenv("NOUS_X_BEARER_TOKEN", "test-token")
    monkeypatch.setenv("NOUS_X_MAX_DAILY_POST_READS", "100")
    def request(url, token):
        return 200, body([post()], "more"), {}, url
    with pytest.raises(ValueError, match="page budget"):
        x_timeline.fetch_x_timeline(URL, since_id=None, max_pages=1,
                                    on_request=lambda: None, request_page=request)
    with pytest.raises(ValueError, match="highwater"):
        x_timeline.fetch_x_timeline(URL, since_id="bad", max_pages=1,
                                    on_request=lambda: None, request_page=request)


def test_http_status_returns_without_parsing_publisher_error_body(monkeypatch):
    monkeypatch.setenv("NOUS_X_BEARER_TOKEN", "test-token")
    monkeypatch.setenv("NOUS_X_MAX_DAILY_POST_READS", "100")
    def rate_limit(url, token):
        return 429, b"not-json-or-credential", {"retry-after": "900"}, url
    status, posts, headers, _ = x_timeline.fetch_x_timeline(
        URL, since_id=None, max_pages=1, on_request=lambda: None,
        request_page=rate_limit,
    )
    assert status == 429 and posts == [] and headers["retry-after"] == "900"


def test_source_contract_restricts_x_to_official_public_timeline():
    source = {
        "id": "x-researcher-sample", "kind": "json_api", "url": URL,
        "adapter": "x_user_posts_v1", "item_kind": "news",
        "category": "threat_research", "organization": "Example researcher",
        "interval_minutes": 15, "max_requests_per_hour": 4,
        "max_concurrency": 1, "max_pages": 2, "enabled": False,
        "policy": {"reviewed_at": "2026-11-07",
                   "content_storage": "metadata_only", "note": "Reviewed X API."},
    }
    cfg = SourceConfig.model_validate(source)
    assert cfg.enabled is False and cfg.max_pages == 2
    for changes in ({"url": "https://nitter.example/researcher"},
                    {"max_pages": 4}, {"max_requests_per_hour": 1},
                    {"item_kind": "vulnerability"},
                    {"json_path": "data"}, {"field_map": {"id": "id"}}):
        with pytest.raises(ValueError):
            SourceConfig.model_validate({**source, **changes})


def test_cost_gate_fails_closed_without_explicit_budget_or_token(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    with factory() as db:
        monkeypatch.delenv("NOUS_X_MAX_DAILY_POST_READS", raising=False)
        monkeypatch.delenv("NOUS_X_BEARER_TOKEN", raising=False)
        assert not x_timeline.x_source_allowed(db, WHEN, 1)
        monkeypatch.setenv("NOUS_X_BEARER_TOKEN", "test-token")
        assert not x_timeline.x_source_allowed(db, WHEN, 1)
        monkeypatch.setenv("NOUS_X_MAX_DAILY_POST_READS", "20")
        assert x_timeline.x_source_allowed(db, WHEN, 2)
        assert not x_timeline.x_source_allowed(db, WHEN, 3)
        source = Source(source_key="x-fixture", kind="json_api", adapter="x_user_posts_v1",
                        url=URL, item_kind="news", config_revision="r" * 64,
                        config={"max_concurrency": 1, "max_pages": 1}, enabled=True,
                        interval_minutes=15, max_requests_per_hour=4)
        db.add(source)
        db.flush()
        job = FetchJob(source_id=source.id, dedupe_key="x-fixture")
        db.add(job)
        db.flush()
        db.add(FetchAttempt(job_id=job.id, started_at=WHEN,
                            ended_at=WHEN, outcome="success", request_count=1))
        db.add(Item(source_id=source.id, external_id="2000000000000000020",
                    kind="news", title="Latest", canonical_url="https://x.com/a",
                    state="current", current_version=1, current_hash="x" * 64))
        db.commit()
        assert x_timeline.latest_post_id(db, source.id) == "2000000000000000020"
        assert x_timeline.x_source_allowed(db, WHEN + timedelta(minutes=1), 1)
        assert not x_timeline.x_source_allowed(db, WHEN + timedelta(minutes=1), 2)
    engine.dispose()
