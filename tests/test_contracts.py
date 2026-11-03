import socket
from types import SimpleNamespace
import pytest
import httpx
from nous.adapters import extract
from nous.fetch import validate_url
import nous.fetch as fetch_module
from nous.registry import SourceConfig, load_registry

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
