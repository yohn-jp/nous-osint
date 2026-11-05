"""Focused cryptographic and ASGI rejection tests for the new remote ingress."""
import base64
import json
import time

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from starlette.testclient import TestClient

from nous.access_auth import (
    AccessAssertionMiddleware, AccessConfig, AccessDenied, AccessVerifier,
)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt(key, claims, *, kid="key-1", alg="RS256"):
    h = b64(json.dumps({"alg": alg, "kid": kid}).encode())
    c = b64(json.dumps(claims).encode())
    signed = f"{h}.{c}".encode()
    signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{c}.{b64(signature)}"


@pytest.fixture
def auth():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_numbers()
    jwks = {"keys": [{"kty": "RSA", "kid": "key-1", "alg": "RS256", "use": "sig",
                      "n": b64(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")),
                      "e": b64(pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big"))}]}
    calls = []

    def getter(url, **kwargs):
        calls.append(url)
        return httpx.Response(200, json=jwks, request=httpx.Request("GET", url))

    verifier = AccessVerifier(AccessConfig("https://example.cloudflareaccess.com", "aud-1"),
                              http_get=getter)
    claims = {"iss": "https://example.cloudflareaccess.com", "aud": ["aud-1"],
              "sub": "subject-1", "email": "TEST@EXAMPLE.COM",
              "exp": time.time() + 3600, "nbf": time.time() - 30}
    return key, claims, verifier, calls


def test_valid_signed_assertion_and_cache(auth):
    key, claims, verifier, calls = auth
    assert verifier.verify(jwt(key, claims)).email == "test@example.com"
    assert verifier.verify(jwt(key, claims)).subject == "subject-1"
    assert len(calls) == 1


@pytest.mark.parametrize("patch", [
    {"aud": ["another"]},
    {"iss": "https://other.cloudflareaccess.com"},
    {"sub": ""},
    {"exp": 0},
    {"nbf": time.time() + 500},
])
def test_rejects_invalid_claims(auth, patch):
    key, claims, verifier, _ = auth
    with pytest.raises(AccessDenied):
        verifier.verify(jwt(key, {**claims, **patch}))


def test_forged_assertion_or_wrong_algorithm_is_rejected(auth):
    key, claims, verifier, _ = auth
    imposter = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AccessDenied):
        verifier.verify(jwt(imposter, claims))
    with pytest.raises(AccessDenied):
        verifier.verify(jwt(key, claims, alg="none"))
    with pytest.raises(AccessDenied):
        verifier.verify(None)


def test_untrusted_issuer_rejected():
    with pytest.raises(ValueError):
        AccessConfig("http://127.0.0.1", "aud")
    with pytest.raises(ValueError):
        AccessConfig("https://example.com", "aud")


def test_expired_cache_fails_closed_on_jwks_error(auth):
    key, claims, verifier, calls = auth
    verifier.verify(jwt(key, claims))
    verifier._expires_at = 0
    def fail(url, **kw):
        raise httpx.ConnectError("down", request=httpx.Request("GET", url))
    verifier._get = fail
    with pytest.raises(AccessDenied):
        verifier.verify(jwt(key, claims))


def test_middleware_only_exposes_mcp_ui_and_allowlisted_read_api(auth):
    key, claims, verifier, _ = auth
    async def upstream(scope, receive, send):
        from starlette.responses import JSONResponse
        await JSONResponse({"subject": scope["state"]["access_identity"].subject})(
            scope, receive, send
        )
    app = AccessAssertionMiddleware(upstream, verifier)
    # No fake lifespan service is installed on the local test double.
    client = TestClient(app, base_url="https://nous.yohn.jp")
    assert client.get("/api/v1/items").status_code == 404
    assert client.get("/v1/status").status_code == 404
    assert client.get("/v1/cves/not-a-cve").status_code == 404
    assert client.get("/").status_code == 403
    assert client.get("/missing-screen").status_code == 403
    assert client.post("/mcp").status_code == 403
    response = client.post("/mcp", headers={
        "Cf-Access-Jwt-Assertion": jwt(key, claims),
    })
    assert response.status_code == 200
    assert response.json()["subject"] == "subject-1"
    unknown_screen = client.get("/missing-screen", headers={
        "Cf-Access-Jwt-Assertion": jwt(key, claims),
    })
    assert unknown_screen.status_code == 200
    assert unknown_screen.json()["subject"] == "subject-1"


def test_report_routes_require_access_and_have_exact_path_and_method_allowlist(auth):
    key, claims, verifier, _ = auth
    async def upstream(scope, receive, send):
        from starlette.responses import Response
        response = Response("served")
        await response(scope, receive, send)

    app = AccessAssertionMiddleware(upstream, verifier)
    client = TestClient(app, base_url="https://nous.yohn.jp")
    assertion = jwt(key, claims)
    allowed = (
        ("/reports", "GET"),
        ("/reports", "HEAD"),
        ("/reports/", "GET"),
        ("/reports/", "HEAD"),
        ("/reports/security/daily-summary/", "GET"),
        ("/reports/cve/cve-2026-1234/", "GET"),
        ("/reports/current/", "GET"),
        ("/reports/other/daily-summary/", "GET"),
        ("/reports/_astro/site-0123456789abcdef.css", "GET"),
    )
    for path, method in allowed:
        assert client.request(method, path).status_code == 403
        response = client.request(method, path, headers={"Cf-Access-Jwt-Assertion": assertion})
        assert response.status_code == 200, (method, path)

    denied = (
        ("GET", "/reports/current/index.html"),
        ("GET", "/reports/security/daily-summary/index.html"),
        ("GET", "/reports/security/" + "a" * 129 + "/"),
        ("GET", "/reports/_astro/site-0123456789abcdef.svg"),
        ("GET", "/reports/_astro/plain.css"),
        ("GET", "/reports/?unexpected=yes"),
        ("POST", "/reports/"),
    )
    for method, path in denied:
        response = client.request(method, path, headers={"Cf-Access-Jwt-Assertion": assertion})
        assert response.status_code == 404, (method, path)
        assert response.headers["cache-control"] == "no-store"
        assert "script-src 'none'" in response.headers["content-security-policy"]
    assert client.get("/reports/", headers={
        "Cf-Access-Jwt-Assertion": assertion, "Host": "other.example",
    }).status_code == 404
