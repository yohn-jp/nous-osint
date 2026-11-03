import socket
from types import SimpleNamespace
import pytest
import httpx
from nous.adapters import extract
from nous.fetch import validate_url
import nous.fetch as fetch_module
from nous.registry import SourceConfig, load_registry
from nous.runtime import parse_timestamp

def test_registry_valid_and_duplicate(tmp_path):
    source = load_registry("sources")[0]
    assert source.enabled
    (tmp_path / "a.yaml").write_text(source.model_dump_json())
    (tmp_path / "b.yaml").write_text(source.model_dump_json())
    with pytest.raises(ValueError, match="duplicate"):
        load_registry(tmp_path)

def test_registry_rejects_unsafe_url():
    data = load_registry("sources")[0].model_dump()
    data["url"] = "http://localhost/private"
    with pytest.raises(ValueError):
        SourceConfig.model_validate(data)
    data = load_registry("sources")[0].model_dump()
    data["url"] = "https://user:password@example.com/feed"
    with pytest.raises(ValueError):
        SourceConfig.model_validate(data)
    data = load_registry("sources")[0].model_dump()
    data["policy"]["reviewed_at"] = "invalid"
    with pytest.raises(ValueError):
        SourceConfig.model_validate(data)


def test_json_mapping():
    source = next(s for s in load_registry("sources") if s.id == "github-advisories")
    runtime_source = SimpleNamespace(kind=source.kind, config=source.model_dump())
    output = extract(runtime_source, b'[{"ghsa_id":"GHSA-1","html_url":"https://github.com/advisories/GHSA-1","summary":"Test"}]', source.url)
    assert output[0]["id"] == "GHSA-1"
    assert output[0]["title"] == "Test"

@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1"])
def test_private_destination_blocked(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", (address, 443))])
    with pytest.raises(ValueError, match="blocked"):
        validate_url("https://example.com/")

def test_unsafe_scheme_blocked():
    with pytest.raises(ValueError, match="unsafe"):
        validate_url("file:///etc/passwd")

def test_304_is_not_redirect(monkeypatch):
    original_client = httpx.Client
    transport = httpx.MockTransport(lambda request: httpx.Response(304, request=request))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("8.8.8.8", 443))])
    monkeypatch.setattr(fetch_module.httpx, "Client", lambda **kwargs: original_client(transport=transport))
    status, body, _, _ = fetch_module.fetch("https://example.com/feed", etag='"abc"')
    assert status == 304
    assert body == b""

def test_connection_is_pinned_to_checked_address(monkeypatch):
    original_client = httpx.Client
    seen = {}
    def handler(request):
        seen["host"] = request.headers["host"]
        seen["address"] = request.url.host
        seen["sni"] = request.extensions["sni_hostname"]
        return httpx.Response(200, content=b"ok", request=request)
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("8.8.8.8", 443))])
    monkeypatch.setattr(fetch_module.httpx, "Client", lambda **kwargs: original_client(transport=transport))
    status, _, _, final = fetch_module.fetch("https://example.com/feed")
    assert status == 200
    assert final == "https://example.com/feed"
    assert seen == {"host": "example.com", "address": "8.8.8.8", "sni": "example.com"}

def test_redirect_to_private_address_blocked(monkeypatch):
    original_client = httpx.Client
    transport = httpx.MockTransport(
        lambda request: httpx.Response(302, headers={"Location": "https://private.example/"},
                                       request=request)
    )
    def resolver(host, *args, **kwargs):
        ip = "10.0.0.1" if host == "private.example" else "8.8.8.8"
        return [(0, 0, 0, "", (ip, 443))]
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    monkeypatch.setattr(fetch_module.httpx, "Client", lambda **kwargs: original_client(transport=transport))
    with pytest.raises(ValueError, match="blocked destination"):
        fetch_module.fetch("https://example.com/feed")

def test_publisher_dates_require_timezone():
    assert parse_timestamp("2026-11-03T09:00:00Z").isoformat() == "2026-11-03T09:00:00+00:00"
    assert parse_timestamp("Tue, 03 Nov 2026 09:00:00 GMT").isoformat() == "2026-11-03T09:00:00+00:00"
    assert parse_timestamp("2026-11-03T09:00:00") is None

def test_automattic_html_adapter():
    source = next(s for s in load_registry("sources") if s.id == "automattic-jobs")
    runtime_source = SimpleNamespace(kind=source.kind, adapter=source.adapter,
                                     config=source.model_dump())
    html = b'<script id="wwu-positions-wwu-positions-view-script-js-before">const ghJobsData = [{"id":42,"title":"Engineer","href":"https://automattic.com/work-with-us/job/engineer/","type":"job"}];</script>'
    records = extract(runtime_source, html, source.url)
    assert records == [{"id": "42", "url": "https://automattic.com/work-with-us/job/engineer/",
                        "title": "Engineer"}]

def test_new_official_catalog_sources_are_disabled_and_rights_explicit():
    expected = {
        "debian-security-advisories", "debian-lts-advisories",
        "ubuntu-security-notices", "aws-security-bulletins",
        "gitlab-patch-releases", "google-cloud-security-bulletins",
        "cloudflare-security-research", "fortinet-psirt", "sie-japan-careers",
    }
    configs = {source.id: source for source in load_registry("sources")}
    assert expected <= configs.keys()
    for name in expected:
        source = configs[name]
        assert not source.enabled, name
        assert source.policy.license_id == "NOASSERTION"
        assert source.policy.attribution and source.policy.attribution.strip()
        assert source.policy.content_storage == "metadata_only"
    sie = configs["sie-japan-careers"]
    assert sie.adapter == "json_v1" and sie.json_path == "jobs"
    assert sie.field_map["url"] == "absolute_url"
    assert all(config.policy.license_id for config in configs.values())
