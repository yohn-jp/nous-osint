"""Read-only MCP transport for Nous.

Dedicated ASGI entrypoint intentionally exports no /v1/, admin, docs, or health
HTTP routes. It calls the foundation's *existing* query handlers until a
canonical query service is extracted in the foundation integration.
Requires mcp==2.3.0 in the application image.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.encoders import jsonable_encoder
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from .access_auth import AccessAssertionMiddleware, AccessConfig, AccessVerifier

mcp = MCPServer("Nous OSINT")


def _bounded(text: str | None, name: str, max_chars: int = 256) -> str | None:
    if text is not None and len(text) > max_chars:
        raise ValueError(f"{name} is too long")
    return text


def _since(value: str | None, *, required: bool = False):
    if not value:
        if required:
            raise ValueError("since is required (ISO-8601 with timezone)")
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("since must be ISO-8601") from exc
    if dt.tzinfo is None:
        raise ValueError("since must contain a timezone")
    if datetime.now(timezone.utc) - dt > timedelta(days=90):
        raise ValueError("time window is limited to 90 days")
    return dt


@mcp.tool()
def search_intelligence(
    query: str | None = None,
    kind: str | None = None,
    source: str | None = None,
    since: str | None = None,
    limit: int = 20,
    cursor: int | None = None,
) -> dict:
    """Search indexed public records. Results include stable IDs and source URLs."""
    if not 1 <= limit <= 50:
        raise ValueError("limit must be 1..50")
    if cursor is not None and cursor < 1:
        raise ValueError("cursor must be positive")
    from .api import items
    result = items(
        state=None, organization=None, published_since=None,
        kind=_bounded(kind, "kind", 40),
        source=_bounded(source, "source", 100),
        q=_bounded(query, "query"),
        since=_since(since),
        limit=limit,
        cursor=cursor,
    )
    return jsonable_encoder(result)


@mcp.tool()
def get_item(item_id: int) -> dict:
    """Retrieve a public record with its source attribution; never return raw article bodies."""
    if item_id < 1:
        raise ValueError("item_id must be positive")
    from .api import item
    record = item(item_id)
    safe_attributes = {key: value for key, value in record.get("attributes", {}).items()
                       if key in {"title", "url", "published", "updated"}}
    safe_evidence = {key: value for key, value in record.get("provenance", {}).items()
                     if key in {"source_url", "final_url", "item_url", "retrieved_at",
                                "adapter", "extraction_method"}}
    return jsonable_encoder({
        **{key: value for key, value in record.items()
           if key not in {"attributes", "provenance"}},
        "attributes": safe_attributes,
        "provenance": safe_evidence,
    })


@mcp.tool()
def get_changes(since: str, kind: str | None = None, limit: int = 20) -> list[dict]:
    """List recent observed public-record changes, limited to the last 90 days."""
    if not 1 <= limit <= 50:
        raise ValueError("limit must be 1..50")
    from .api import changes
    result = changes(since=_since(since, required=True),
                     kind=_bounded(kind, "kind", 40), limit=limit)
    return jsonable_encoder(result["changes"])


@mcp.tool()
def get_source_status() -> list[dict]:
    """Show collection freshness and source health without internal error text or secrets."""
    from .api import sources
    return jsonable_encoder([{
        "id": value["id"],
        "kind": value["kind"],
        "item_kind": value["item_kind"],
        "enabled": value["enabled"],
        "last_success_at": value["last_success_at"],
        "next_due_at": value["next_due_at"],
        "healthy": value.get("last_error") is None,
    } for value in sources()])


security = TransportSecuritySettings(
    allowed_hosts=["nous.yohn.jp", "nous.yohn.jp:443"],
    allowed_origins=["https://nous.yohn.jp"],
)
# v2 SDK runs its own lifespan when this ASGI app is served as top-level.
# The standalone process is deliberate: mounting the foundation FastAPI app
# would require restructuring its lifespan and exposing more HTTP routes.
mcp_http = mcp.streamable_http_app(
    stateless_http=True, json_response=True,
    transport_security=security, max_request_body_size=64 * 1024,
)
app = AccessAssertionMiddleware(mcp_http, AccessVerifier(AccessConfig.from_environment()))
