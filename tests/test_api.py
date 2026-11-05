from datetime import datetime, timezone
import os

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from nous.api import ItemResponse, VersionResponse, app


client = TestClient(app)


def test_openapi_documents_responses_and_filters():
    schema = client.get("/openapi.json").json()
    items = schema["paths"]["/v1/items"]["get"]
    assert items["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    params = {p["name"]: p for p in items["parameters"]}
    kind_schema = next(s for s in params["kind"]["schema"]["anyOf"] if "enum" in s)
    state_schema = next(s for s in params["state"]["schema"]["anyOf"] if "enum" in s)
    assert kind_schema["enum"] == [
        "job_posting", "news", "advisory", "vulnerability", "company_update"
    ]
    assert state_schema["enum"] == ["current", "unknown", "stale", "closed"]
    assert params["limit"]["schema"]["maximum"] == 100
    assert "/v1/cves/{cve_id}" in schema["paths"]
    assert schema["paths"]["/v1/cves/{cve_id}"]["get"]["responses"]["200"]


@pytest.mark.parametrize("query", [
    "kind=made-up",
    "state=deleted",
    "limit=0",
    "limit=101",
    "cursor=-1",
    "since=2026-01-01T00:00:00",
    "source=Bad_ID",
])
def test_invalid_item_filters_return_422(query):
    response = client.get("/v1/items?" + query)
    assert response.status_code == 422


@pytest.mark.parametrize("cve_id", ["NOT-CVE", "CVE-26-1234", "cve-2026-1234",
                                    "CVE-2026-123"])
def test_invalid_cve_identity_is_rejected(cve_id):
    response = client.get("/v1/cves/" + cve_id)
    assert response.status_code == 422


def test_item_response_schema_is_bounded_and_explicit():
    payload = {
        "id": 8,
        "source": "example-source",
        "kind": "advisory",
        "title": "Public advisory",
        "url": "https://example.org/advisory/8",
        "state": "current",
        "first_seen_at": datetime.now(timezone.utc),
        "last_seen_at": datetime.now(timezone.utc),
        "current_version": 1,
    }
    assert ItemResponse.model_validate(payload).id == 8
    with pytest.raises(ValidationError):
        ItemResponse.model_validate({**payload, "private_field": "must not leak"})
    with pytest.raises(ValidationError):
        ItemResponse.model_validate({**payload, "state": "removed"})


def test_version_response_requires_sha256():
    payload = {
        "version": 1,
        "observed_at": datetime.now(timezone.utc),
        "sha256": "a" * 64,
        "attributes": {"title": "Advisory"},
        "provenance": {"adapter": "rss_v1"},
    }
    assert VersionResponse.model_validate(payload).version == 1
    with pytest.raises(ValidationError):
        VersionResponse.model_validate({**payload, "sha256": "bad"})


@pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="PostgreSQL required")
def test_ready_requires_latest_schema_revision(monkeypatch):
    from nous import api
    success = client.get("/health/ready")
    assert success.status_code == 200, success.text
    monkeypatch.setattr(api, "expected_schema_head", lambda: "not-current")
    mismatch = client.get("/health/ready")
    assert mismatch.status_code == 503


@pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="PostgreSQL required")
def test_version_history_endpoint_is_bounded_without_explicit_limit():
    import uuid
    from nous.db import session_factory
    from nous.models import Item, ItemVersion, Source

    factory = session_factory()
    key = "version-bound-" + uuid.uuid4().hex[:12]
    with factory() as db:
        source = Source(
            source_key=key, kind="rss", adapter="rss_v1",
            item_kind="news", url="https://version-bound.example/rss",
            config_revision="fixture", config={}, enabled=False,
            interval_minutes=60, max_requests_per_hour=5,
        )
        db.add(source)
        db.flush()
        item = Item(
            source_id=source.id, external_id="bounded", kind="news",
            canonical_url="https://version-bound.example/story",
            title="Bounded version history", state="current",
            current_version=60, current_hash="f" * 64,
        )
        db.add(item)
        db.flush()
        item_id = item.id
        db.add_all([
            ItemVersion(
                item_id=item_id, version=number,
                sha256=f"{number:064x}",
                attributes={"title": f"Version {number}"},
                provenance={"adapter": "rss_v1"},
            )
            for number in range(1, 61)
        ])
        db.commit()

    default = client.get(f"/v1/items/{item_id}/versions")
    assert default.status_code == 200, default.text
    assert len(default.json()) == 50
    assert default.json()[0]["version"] == 60
    assert default.json()[-1]["version"] == 11
    older = client.get(f"/v1/items/{item_id}/versions?before=11&limit=50")
    assert older.status_code == 200
    assert [row["version"] for row in older.json()] == list(range(10, 0, -1))
    smaller = client.get(f"/v1/items/{item_id}/versions?limit=7")
    assert smaller.status_code == 200 and len(smaller.json()) == 7
    assert client.get(f"/v1/items/{item_id}/versions?limit=101").status_code == 422
