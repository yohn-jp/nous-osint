"""Authenticated UI and narrowly allowlisted API gateway tests."""
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture
def gateway(monkeypatch, tmp_path):
    monkeypatch.setenv("CF_ACCESS_ISSUER", "https://tests.cloudflareaccess.com")
    monkeypatch.setenv("CF_ACCESS_AUDIENCE", "tests-audience")
    from nous import remote_gateway
    from nous.access_auth import AccessDenied, AccessIdentity

    def verify(assertion):
        if assertion != "test-assertion":
            raise AccessDenied("invalid test assertion")
        return AccessIdentity(subject="gateway-test", email=None)

    monkeypatch.setattr(remote_gateway.app.verifier, "verify", verify)
    remote_gateway.app.app.ui.directory = str(tmp_path)
    remote_gateway.app.app.ui.all_directories = [str(tmp_path)]
    (tmp_path / "index.html").write_text("<main>Nous UI</main>")
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "app-123.js").write_text("window.nous = true")
    (assets / "index-0123456789.js").write_text("window.compiled = true")
    return remote_gateway


def test_static_ui_requires_assertion_and_unknown_routes_stay_hidden(gateway):
    client = TestClient(gateway.app, base_url="https://nous.yohn.jp")
    unauthenticated = client.get("/")
    assert unauthenticated.status_code == 403
    assert unauthenticated.headers["cache-control"] == "no-store"
    headers = {"Cf-Access-Jwt-Assertion": "test-assertion"}
    page = client.get("/", headers=headers)
    assert page.text == "<main>Nous UI</main>"
    assert page.headers["cache-control"] == "no-store"
    for route in ("/explore", "/changes", "/sources", "/sources/new", "/admin/reports",
                  "/admin/sources", "/admin/sources/new",
                  "/admin/sources/example/edit", "/items/3", "/cves/CVE-2026-1234"):
        page = client.get(route, headers=headers)
        assert page.status_code == 200 and page.text == "<main>Nous UI</main>"
        assert page.headers["cache-control"] == "no-store"
    unknown_screen = client.get("/missing-screen", headers=headers)
    assert unknown_screen.status_code == 404
    assert unknown_screen.text == "<main>Nous UI</main>"
    assert unknown_screen.headers["content-type"].startswith("text/html")
    assert client.get("/missing-screen").status_code == 403
    asset = client.get("/assets/app-123.js", headers=headers)
    assert asset.status_code == 200 and "window.nous" in asset.text
    assert asset.headers["cache-control"] == "no-store"
    immutable = client.get("/assets/index-0123456789.js", headers=headers)
    assert immutable.status_code == 200
    assert immutable.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert client.get("/assets/missing-0123456789.js", headers=headers).headers["cache-control"] == "no-store"
    for path in ("/health/ready", "/admin", "/api/v1/items", "/v1/status",
                 "/v1/admin/not-allowed", "/assets/missing-12345678.js"):
        assert client.get(path, headers=headers).status_code == 404
    assert client.get("/health/ready", headers=headers).headers["content-type"].startswith(
        "application/json"
    )
    assert client.get("/%65xplore", headers=headers).status_code == 404
    assert client.post("/v1/items", headers=headers).status_code == 404
    assert client.get("/", headers={**headers, "Host": "other.example"}).status_code == 404


def test_private_reports_are_exact_read_only_routes(gateway, tmp_path, monkeypatch):
    report_root = tmp_path / "private-report-site"
    digest = "a" * 64
    release = report_root / "releases" / digest
    (release / "security" / "daily-summary").mkdir(parents=True)
    (release / "index.html").write_text("<main>Private reports</main>")
    (release / "404.html").write_text(
        '<main>Report not found <a href="/reports/">All reports</a></main>'
    )
    (release / "security" / "daily-summary" / "index.html").write_text(
        "<article>Private daily report</article>"
    )
    (release / "security" / "escape").symlink_to(tmp_path / "outside", target_is_directory=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "index.html").write_text("<main>Must remain private</main>")
    (report_root / "_astro").mkdir(parents=True)
    for filename in (
        "site-0123456789abcdef.css",
        "book-abcdef0123456789.woff2",
        "cover-0123456789abcdef.png",
        "cover-abcdef0123456789.webp",
        "icon-0123456789abcdef.svg",
        "plain.css",
        "manifest-0123456789abcdef.json",
    ):
        (report_root / "_astro" / filename).write_text("static asset")
    (report_root / "current").symlink_to(Path("releases") / digest, target_is_directory=True)
    monkeypatch.setattr(gateway.app.app, "report_site_directory", None)
    monkeypatch.setenv("NOUS_REPORT_SITE_DIR", str(report_root))

    client = TestClient(gateway.app, base_url="https://nous.yohn.jp")
    headers = {"Cf-Access-Jwt-Assertion": "test-assertion"}
    denied = client.get("/reports/")
    assert denied.status_code == 403
    assert denied.headers["cache-control"] == "no-store"
    assert "script-src 'none'" in denied.headers["content-security-policy"]
    assert denied.headers["x-content-type-options"] == "nosniff"

    canonical = client.get("/reports", headers=headers, follow_redirects=False)
    assert canonical.status_code == 308
    assert canonical.headers["location"] == "/reports/"
    assert client.get("/reports").status_code == 403

    index = client.get("/reports/", headers=headers)
    assert index.status_code == 200
    assert index.text == "<main>Private reports</main>"
    assert index.headers["content-type"].startswith("text/html")
    assert index.headers["cache-control"] == "no-store"
    assert "style-src 'self'" in index.headers["content-security-policy"]
    article = client.get("/reports/security/daily-summary/", headers=headers)
    assert article.status_code == 200
    assert article.text == "<article>Private daily report</article>"
    head = client.head("/reports/security/daily-summary/", headers=headers)
    assert head.status_code == 200 and head.content == b""
    missing_article = client.get("/reports/security/not-published-yet/", headers=headers)
    assert missing_article.status_code == 404
    assert "Report not found" in missing_article.text
    assert 'href="/reports/"' in missing_article.text
    assert missing_article.headers["content-type"].startswith("text/html")

    for filename in (
        "site-0123456789abcdef.css",
        "book-abcdef0123456789.woff2",
        "cover-0123456789abcdef.png",
        "cover-abcdef0123456789.webp",
    ):
        asset = client.get("/reports/_astro/" + filename, headers=headers)
        assert asset.status_code == 200 and asset.text == "static asset"
        assert asset.headers["cache-control"] == "no-store"
    assert client.head("/reports/_astro/site-0123456789abcdef.css", headers=headers).status_code == 200

    invalid = (
        "/reports/current/",
        "/reports/current/index.html",
        "/reports/security/daily-summary/index.html",
        "/reports/other/daily-summary/",
        "/reports/security/" + "a" * 129 + "/",
        "/reports/security/escape/",
        "/reports/_astro/icon-0123456789abcdef.svg",
        "/reports/_astro/plain.css",
        "/reports/_astro/manifest-0123456789abcdef.json",
        "/reports/security/%2e%2e/current/",
        "/reports/%73ecurity/daily-summary/",
    )
    for path in invalid:
        response = client.get(path, headers=headers)
        assert response.status_code == 404, path
        assert response.headers["cache-control"] == "no-store"
        assert "script-src 'none'" in response.headers["content-security-policy"]
    assert client.get("/reports/?unexpected=yes", headers=headers).status_code == 404
    assert client.post("/reports/", headers=headers).status_code == 404
    assert client.get("/reports/", headers={**headers, "Host": "other.example"}).status_code == 404

    current = report_root / "current"
    current.unlink()
    current.symlink_to(outside, target_is_directory=True)
    assert client.get("/reports/", headers=headers).status_code == 404


def test_api_proxy_forwards_only_bounded_read_queries(gateway):
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json={"items": [], "next_cursor": None})

    gateway.app.app.api_transport = httpx.MockTransport(handle)
    headers = {"Cf-Access-Jwt-Assertion": "test-assertion"}
    client = TestClient(gateway.app, base_url="https://nous.yohn.jp")
    response = client.get("/v1/items?q=security&limit=20", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"items": [], "next_cursor": None}
    assert response.headers["cache-control"] == "no-store"
    assert requests[0].url.path == "/v1/items"
    assert dict(requests[0].url.params) == {"q": "security", "limit": "20"}

    assert client.get("/v1/items?state=current", headers=headers).status_code == 400
    assert client.get("/v1/items?q=first&q=second", headers=headers).status_code == 400
    assert client.get("/v1/items?q=" + "x" * 2100, headers=headers).status_code == 400
    assert len(requests) == 1
    history = client.get("/v1/items/42/versions?limit=25&before=11", headers=headers)
    assert history.status_code == 200
    assert requests[-1].url.path == "/v1/items/42/versions"
    assert dict(requests[-1].url.params) == {"limit": "25", "before": "11"}
    assert client.get("/v1/items/42/versions?secret=1", headers=headers).status_code == 400
    cve = client.get("/v1/cves/CVE-2026-1234", headers=headers)
    assert cve.status_code == 200
    assert requests[-1].url.path == "/v1/cves/CVE-2026-1234"
    assert client.get("/v1/cves/CVE-2026-1234?secret=yes", headers=headers).status_code == 400
    assert client.get("/v1/cves/not-a-cve", headers=headers).status_code == 404
