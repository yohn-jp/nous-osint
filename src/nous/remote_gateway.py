"""Access-protected static UI and read-only API ingress alongside MCP."""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat

import httpx
from starlette.exceptions import HTTPException
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.staticfiles import StaticFiles
from urllib.parse import parse_qsl

from .access_auth import AccessAssertionMiddleware, AccessConfig, AccessVerifier, _SPA_ROUTE
from .admin import app as admin_app
from .remote_mcp import mcp_http

_API_ORIGIN = "http://nous-api:8000"
_MAX_QUERY_BYTES = 2048
_MAX_RESPONSE_BYTES = 1_048_576
_REPORT_SITE_DEFAULT = "/var/lib/nous-reports/site"
_REPORT_INDEX_PATH = re.compile(r"^/reports/$")
_REPORT_ARTICLE_PATH = re.compile(
    r"^/reports/(security|cve)/(?=[a-z0-9-]{1,128}/)"
    r"([a-z0-9]+(?:-[a-z0-9]+)*)/$"
)
_REPORT_ASSET_PATH = re.compile(
    r"^/reports/_astro/([A-Za-z0-9_-][A-Za-z0-9._-]{0,127}[.-]"
    r"[A-Za-z0-9_-]{8,64}\.(?:css|woff2?|png|webp))$"
)
_REPORT_ASSET_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".png": "image/png",
    ".webp": "image/webp",
}
_API_QUERY_KEYS = {
    "/v1/items": {"q", "kind", "source", "limit", "cursor"},
    "/v1/sources": set(),
    "/v1/changes": {"since", "kind", "limit"},
}


def _query_keys(path: str) -> set[str] | None:
    if path in _API_QUERY_KEYS:
        return _API_QUERY_KEYS[path]
    if AccessAssertionMiddleware._allowed_path(path, "GET") and path.startswith("/v1/cves/"):
        return set()
    if AccessAssertionMiddleware._allowed_path(path, "GET") and path.startswith("/v1/items/"):
        if path.endswith("/versions"):
            return {"limit", "before"}
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

    def __init__(self, ui_directory: str = "/app/ui", api_transport=None,
                 report_site_directory: str | Path | None = None):
        self.ui = StaticFiles(directory=ui_directory, html=True, check_dir=False)
        self.api_transport = api_transport
        self.report_site_directory = report_site_directory

    def _report_site_root(self) -> Path:
        configured = self.report_site_directory or os.getenv(
            "NOUS_REPORT_SITE_DIR", _REPORT_SITE_DEFAULT
        )
        root = Path(configured).resolve(strict=True)
        if not root.is_dir():
            raise OSError("report site root is not a directory")
        return root

    @staticmethod
    def _regular_file(path: Path, root: Path) -> Path | None:
        try:
            if path.is_symlink():
                return None
            resolved = path.resolve(strict=True)
            if resolved.parent != root or not stat.S_ISREG(resolved.lstat().st_mode):
                return None
            return resolved
        except (OSError, RuntimeError):
            return None

    def _current_release(self, site_root: Path) -> Path | None:
        releases = site_root / "releases"
        current = site_root / "current"
        try:
            if (releases.is_symlink() or not releases.is_dir() or
                    releases.resolve(strict=True) != releases or not current.is_symlink()):
                return None
            target = os.readlink(current)
            match = re.fullmatch(r"releases/([a-f0-9]{64})", target)
            if match is None:
                return None
            release = releases / match.group(1)
            resolved = release.resolve(strict=True)
            if (release.is_symlink() or resolved != release or
                    resolved.parent != releases or not resolved.is_dir()):
                return None
            return resolved
        except (OSError, RuntimeError):
            return None

    def _report_file(self, path: str) -> tuple[Path, str] | None:
        """Resolve only explicit immutable HTML routes or fingerprinted assets."""
        try:
            site_root = self._report_site_root()
        except (OSError, RuntimeError, ValueError):
            return None

        asset = _REPORT_ASSET_PATH.fullmatch(path)
        if asset:
            asset_root = site_root / "_astro"
            try:
                if (asset_root.is_symlink() or not asset_root.is_dir() or
                        asset_root.resolve(strict=True) != asset_root):
                    return None
            except (OSError, RuntimeError):
                return None
            file_path = self._regular_file(asset_root / asset.group(1), asset_root)
            if file_path is None:
                return None
            return file_path, _REPORT_ASSET_TYPES[file_path.suffix]

        release = self._current_release(site_root)
        if release is None:
            return None
        if _REPORT_INDEX_PATH.fullmatch(path):
            relative_parts = ("index.html",)
        else:
            article = _REPORT_ARTICLE_PATH.fullmatch(path)
            if article is None:
                return None
            relative_parts = (article.group(1), article.group(2), "index.html")

        directory = release
        try:
            for part in relative_parts[:-1]:
                child = directory / part
                resolved = child.resolve(strict=True)
                if (child.is_symlink() or resolved.parent != directory or
                        not resolved.is_dir()):
                    return None
                directory = resolved
            file_path = self._regular_file(directory / relative_parts[-1], directory)
        except (OSError, RuntimeError):
            return None
        if file_path is None:
            return None
        return file_path, "text/html; charset=utf-8"

    async def _report(self, scope, receive, send):
        path = scope.get("path", "")
        raw_path = scope.get("raw_path")
        try:
            canonical_path = path.encode("ascii")
        except UnicodeEncodeError:
            canonical_path = b""
        if (scope.get("method", "").upper() not in ("GET", "HEAD") or
                raw_path != canonical_path or scope.get("query_string", b"")):
            return await _report_not_found(scope, receive, send)
        resolved = self._report_file(path)
        if resolved is None:
            return await _report_not_found(scope, receive, send)
        file_path, media_type = resolved
        return await FileResponse(
            file_path,
            media_type=media_type,
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
            method=scope.get("method", "GET"),
        )(scope, receive, send)

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
        if path == "/reports" or path.startswith("/reports/"):
            return await self._report(scope, receive, send)
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


async def _report_not_found(scope, receive, send):
    return await Response(
        "Not Found\n",
        status_code=404,
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )(scope, _empty_receive, send)


app = AccessAssertionMiddleware(RemoteGateway(), AccessVerifier(AccessConfig.from_environment()))
