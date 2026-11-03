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
