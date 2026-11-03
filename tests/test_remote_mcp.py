"""Exercise the MCP tools against the canonical Nous query service and transport."""
import os
import uuid
from datetime import timedelta
from fastapi.testclient import TestClient
import pytest
from nous.db import session_factory
from nous.models import Item, ItemVersion, Source, now

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="PostgreSQL required")


@pytest.fixture
def target(monkeypatch):
    monkeypatch.setenv("CF_ACCESS_ISSUER", "https://tests.cloudflareaccess.com")
    monkeypatch.setenv("CF_ACCESS_AUDIENCE", "tests-audience")
    from nous import remote_mcp
    # Test the MCP framing against an authenticated origin. The JWT verification
    # itself is tested independently with real RSA signatures in test_access_auth.
    from nous.access_auth import AccessDenied, AccessIdentity
    def verified_identity(assertion):
        if not assertion:
            raise AccessDenied("missing assertion")
        return AccessIdentity(subject="ci-test", email=None)
    monkeypatch.setattr(remote_mcp.app.verifier, "verify", verified_identity)
    return remote_mcp


def seed():
    factory = session_factory()
    key = "mcp-record-" + uuid.uuid4().hex[:12]
    with factory() as db:
        source = Source(source_key=key, kind="rss", url="https://mcp-test.example/feed",
                        adapter="rss_v1", item_kind="news", config_revision="test",
                        config={"max_concurrency": 1}, enabled=True,
                        interval_minutes=60, max_requests_per_hour=5)
        db.add(source)
        db.flush()
        record = Item(source_id=source.id, external_id="record1",
                      canonical_url="https://mcp-test.example/record1",
                      title="Unique MCP integration title", kind="news",
                      current_version=1, current_hash="hash")
        db.add(record)
        db.flush()
        db.add(ItemVersion(item_id=record.id, version=1, sha256="a" * 64,
                           attributes={"title": "Unique MCP integration title"},
                           provenance={"source_url": source.url,
                                       "retrieved_at": now().isoformat()}))
        db.commit()
        return key, record.id


def test_read_only_tools_use_existing_api_without_default_query_sentinels(target):
    key, record_id = seed()
    found = target.search_intelligence(
        query="Unique MCP integration title", source=key, limit=10
    )
    assert [item["id"] for item in found["items"]] == [record_id]
    detail = target.get_item(record_id)
    assert detail["provenance"]["source_url"] == "https://mcp-test.example/feed"
    history = target.get_changes(since=(now() - timedelta(days=1)).isoformat(), limit=50)
    assert isinstance(history, list)
    assert any(item["item_id"] == record_id for item in history)
    status = target.get_source_status()
    assert any(source["id"] == key for source in status)


def test_mcp_http_initialize_and_tool_listing(target):
    headers = {
        "Cf-Access-Jwt-Assertion": "authenticated-by-test",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-06-18",
    }
    with TestClient(target.app, base_url="https://nous.yohn.jp") as client:
        assert client.get("/api/v1/items", headers=headers).status_code == 404
        assert client.get("/v1/items", headers={
            k: v for k, v in headers.items() if k != "Cf-Access-Jwt-Assertion"
        }).status_code == 403
        assert client.post("/mcp", json={}, headers={
            k: v for k, v in headers.items() if k != "Cf-Access-Jwt-Assertion"
        }).status_code == 403
        initialize = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "0.1"},
            },
        }, headers=headers)
        assert initialize.status_code == 200, initialize.text
        assert "result" in initialize.json()
        response = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        }, headers=headers)
        assert response.status_code == 200, response.text
        tools = {tool["name"] for tool in response.json()["result"]["tools"]}
        assert tools == {"search_intelligence", "get_item", "get_changes",
                         "get_source_status"}

        source_key, item_id = seed()
        called = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "search_intelligence",
                "arguments": {"query": "Unique MCP integration title",
                              "source": source_key, "limit": 10},
            },
        }, headers=headers)
        assert called.status_code == 200, called.text
        result = called.json()
        assert "result" in result and "error" not in result, result
        assert str(item_id) in called.text

