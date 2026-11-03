"""Access-protected static UI and read-only API ingress alongside MCP."""
from __future__ import annotations

import httpx
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse, Response
from starlette.staticfiles import StaticFiles
from urllib.parse import parse_qsl

from .access_auth import AccessAssertionMiddleware, AccessConfig, AccessVerifier, _SPA_ROUTE
from .admin import app as admin_app
from .remote_mcp import mcp_http

_API_ORIGIN = "http://nous-api:8000"
_MAX_QUERY_BYTES = 2048
_MAX_RESPONSE_BYTES = 1_048_576
_API_QUERY_KEYS = {
    "/v1/items": {"q", "kind", "source", "limit", "cursor"},
    "/v1/sources": set(),
    "/v1/changes": {"since", "kind", "limit"},
}


def _query_keys(path: str) -> set[str] | None:
    if path in _API_QUERY_KEYS:
        return _API_QUERY_KEYS[path]
    if AccessAssertionMiddleware._allowed_path(path, "GET") and path.startswith("/v1/items/"):
        if path.endswith("/versions"):
            return {"limit"}
        return set()
    return None


def _query_pairs(path: str, raw_query: bytes) -> list[tuple[str, str]] | None:
    allowed = _query_keys(path)
    if allowed is None or len(raw_query) > _MAX_QUERY_BYTES:
        return None
    try:
        pairs = parse_qsl(raw_query.decode("ascii"), keep_blank_values=True, max_num_fields=16)
    except (UnicodeError, ValueError):
        return None
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)) or any(key not in allowed for key in keys):
        return None
    return pairs


class RemoteGateway:
    """Dispatch only the MCP transport, static UI, and bounded GET API routes."""

    def __init__(self, ui_directory: str = "/app/ui", api_transport=None):
        self.ui = StaticFiles(directory=ui_directory, html=True, check_dir=False)
        self.api_transport = api_transport

    async def _api(self, scope, send):
        path = scope["path"]
        query = _query_pairs(path, scope.get("query_string", b""))
        if query is None:
            return await JSONResponse({"detail": "invalid or unsupported query"}, status_code=400)(
                scope, _empty_receive, send
            )

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False,
                                         trust_env=False, transport=self.api_transport) as client:
                upstream = await client.get(_API_ORIGIN + path, params=query,
                                            headers={"Accept": "application/json",
                                                     "Accept-Encoding": "identity"})
        except httpx.HTTPError:
            return await JSONResponse({"detail": "API unavailable"}, status_code=502)(
                scope, _empty_receive, send
            )

        if (len(upstream.content) > _MAX_RESPONSE_BYTES or
                upstream.headers.get("content-type", "").split(";", 1)[0].lower()
                != "application/json"):
            return await JSONResponse({"detail": "invalid API response"}, status_code=502)(
                scope, _empty_receive, send
            )
        response = Response(
            upstream.content,
            status_code=upstream.status_code,
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )
        await response(scope, _empty_receive, send)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await mcp_http(scope, receive, send)
        path = scope.get("path", "")
        if path in ("/mcp", "/mcp/"):
            return await mcp_http(scope, receive, send)
        if path.startswith("/v1/admin/"):
            return await admin_app(scope, receive, send)
        if path.startswith("/v1/") or path == "/v1/items":
            return await self._api(scope, send)
        # StaticFiles is used as a bare ASGI app, so handle its missing-file
        # exception locally. Only known SPA routes may fall back to index.html.
        ui_scope = scope
        if _SPA_ROUTE.fullmatch(path):
            ui_scope = {**scope, "path": "/index.html", "raw_path": b"/index.html",
                        "query_string": b""}
        try:
            return await self.ui(ui_scope, receive, send)
        except HTTPException:
            return await JSONResponse({"detail": "not found"}, status_code=404)(
                scope, _empty_receive, send
            )


async def _empty_receive():
    return {"type": "http.request", "body": b"", "more_body": False}


app = AccessAssertionMiddleware(RemoteGateway(), AccessVerifier(AccessConfig.from_environment()))
