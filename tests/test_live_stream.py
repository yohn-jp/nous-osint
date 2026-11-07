"""Live stream returns immutable observations newest-first, without polling noise."""
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from nous import api
from nous.db import Base
from nous.models import Item, ItemVersion, Source

NOW = datetime(2026, 11, 7, 6, 0, tzinfo=timezone.utc)


def test_observation_stream_is_version_ordered_and_cursor_stable(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=__import__("sqlalchemy").pool.StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    monkeypatch.setattr(api, "session_factory", lambda: factory)
    with factory() as db:
        primary = Source(
            source_key="research-example", origin="official", kind="rss",
            url="https://example.org/feed", adapter="rss_v1", item_kind="news",
            config={"category": "threat_research", "organization": "Researcher"},
            config_revision="x" * 64, enabled=True, interval_minutes=15,
            max_requests_per_hour=4,
        )
        careers = Source(
            source_key="career-example", origin="official", kind="rss",
            url="https://example.org/jobs", adapter="rss_v1", item_kind="job_posting",
            config={"category": "careers", "organization": "Recruiter"},
            config_revision="y" * 64, enabled=True, interval_minutes=15,
            max_requests_per_hour=4,
        )
        db.add_all([primary, careers])
        db.flush()
        first = Item(
            source_id=primary.id, external_id="stable-post", kind="news",
            canonical_url="https://example.org/a", title="Updated",
            state="current", current_version=2, current_hash="a" * 64,
        )
        other = Item(
            source_id=primary.id, external_id="another", kind="news",
            canonical_url="https://example.org/b", title="Independent",
            state="current", current_version=1, current_hash="b" * 64,
        )
        job = Item(
            source_id=careers.id, external_id="job", kind="job_posting",
            canonical_url="https://example.org/job", title="Careers",
            state="current", current_version=1, current_hash="c" * 64,
        )
        db.add_all([first, other, job])
        db.flush()
        def version(item, number, title):
            return ItemVersion(item_id=item.id, version=number, observed_at=NOW,
                sha256="a" * 64, attributes={
                    "title": title, "url": item.canonical_url,
                    "published": "2026-11-07T05:30:00Z",
                }, provenance={"source_url": "https://example.org/feed"})
        db.add_all([
            version(first, 1, "First observation"), version(other, 1, "Independent"),
            version(job, 1, "Careers"), version(first, 2, "Updated"),
        ])
        db.commit()

    client = TestClient(api.app)
    response = client.get("/v1/stream?limit=2")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert [row["title"] for row in payload["observations"]] == ["Updated", "Independent"]
    assert [row["change"] for row in payload["observations"]] == ["updated", "new"]
    assert payload["observations"][0]["organization"] == "Researcher"
    assert payload["observations"][0]["category"] == "threat_research"
    assert payload["observations"][0]["published_at"].startswith("2026-11-07")
    assert payload["next_cursor"] == payload["observations"][1]["observation_id"]
    second = client.get("/v1/stream", params={"cursor": payload["next_cursor"], "limit": 2})
    assert second.status_code == 200
    assert [row["title"] for row in second.json()["observations"]] == ["First observation"]
    assert second.json()["next_cursor"] is None

    scoped = client.get("/v1/stream?category=threat_research&source=research-example")
    assert scoped.status_code == 200
    assert len(scoped.json()["observations"]) == 3
    assert client.get("/v1/stream?category=careers").json()["observations"] == []
    assert len(client.get("/v1/stream?include_careers=true").json()["observations"]) == 4
    for query in ("category=unreviewed", "limit=101", "cursor=0"):
        assert client.get("/v1/stream?" + query).status_code == 422
    assert "StreamPageResponse" in api.app.openapi()["components"]["schemas"]
    engine.dispose()
