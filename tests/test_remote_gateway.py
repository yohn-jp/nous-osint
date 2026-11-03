"""Authenticated UI and narrowly allowlisted API gateway tests."""
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
    remote_gateway.app.app.ui.all_directories = [str(tmp_path)]
    (tmp_path / "index.html").write_text("<main>Nous UI</main>")
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "app-123.js").write_text("window.nous = true")
    return remote_gateway


def test_static_ui_requires_assertion_and_unknown_routes_stay_hidden(gateway):
    client = TestClient(gateway.app, base_url="https://nous.yohn.jp")
    assert client.get("/").status_code == 403
    headers = {"Cf-Access-Jwt-Assertion": "test-assertion"}
    assert client.get("/", headers=headers).text == "<main>Nous UI</main>"
    asset = client.get("/assets/app-123.js", headers=headers)
    assert asset.status_code == 200 and "window.nous" in asset.text
    for path in ("/docs", "/health/ready", "/admin", "/api/v1/items", "/v1/status"):
        assert client.get(path, headers=headers).status_code == 404
    assert client.post("/v1/items", headers=headers).status_code == 404
    assert client.get("/", headers={**headers, "Host": "other.example"}).status_code == 404


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
