"""Report administration is reachable only through a valid Access JWT."""
import base64
from datetime import datetime, timezone
import json

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from nous.access_auth import AccessConfig, AccessVerifier
from nous.db import Base


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _signed_assertion(key, issuer: str, audience: str, subject: str = "report-admin") -> str:
    header = _b64(json.dumps({"alg": "RS256", "kid": "report-test"}).encode())
    claims = _b64(json.dumps({
        "iss": issuer, "aud": audience, "sub": subject,
        "exp": datetime.now(timezone.utc).timestamp() + 3600,
    }).encode())
    signed = f"{header}.{claims}".encode("ascii")
    signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{claims}.{_b64(signature)}"


def test_authenticated_gateway_allows_report_admin_api_and_spa(tmp_path, monkeypatch):
    issuer = "https://reports.cloudflareaccess.com"
    audience = "report-admin-test"
    monkeypatch.setenv("CF_ACCESS_ISSUER", issuer)
    monkeypatch.setenv("CF_ACCESS_AUDIENCE", audience)
    monkeypatch.setenv("NOUS_ADMIN_SUBJECTS", "report-admin")

    from nous import remote_gateway

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_numbers()
    jwks = {"keys": [{
        "kty": "RSA", "kid": "report-test", "alg": "RS256", "use": "sig",
        "n": _b64(public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")),
        "e": _b64(public.e.to_bytes((public.e.bit_length() + 7) // 8, "big")),
    }]}

    def get_jwks(url, **kwargs):
        return httpx.Response(200, json=jwks, request=httpx.Request("GET", url))

    monkeypatch.setattr(remote_gateway.app, "verifier", AccessVerifier(
        AccessConfig(issuer, audience), http_get=get_jwks,
    ))
    monkeypatch.setattr(remote_gateway.app.app.ui, "directory", str(tmp_path))
    monkeypatch.setattr(remote_gateway.app.app.ui, "all_directories", [str(tmp_path)])
    (tmp_path / "index.html").write_text("<main>Nous UI</main>", encoding="utf-8")

    database_path = tmp_path / "admin.db"
    engine = create_engine("sqlite:///" + str(database_path))
    Base.metadata.create_all(engine)
    secret_path = tmp_path / "admin-dsn"
    secret_path.write_text("sqlite:///" + str(database_path), encoding="utf-8")
    monkeypatch.setenv("NOUS_ADMIN_DATABASE_URL_FILE", str(secret_path))

    assertion = _signed_assertion(key, issuer, audience)
    headers = {
        "Cf-Access-Jwt-Assertion": assertion,
        "Origin": "https://nous.yohn.jp",
        "X-Nous-Admin-Action": "1",
    }
    client = TestClient(remote_gateway.app, base_url="https://nous.yohn.jp")

    # This is a direct browser reload, which must use the explicit SPA fallback.
    page = client.get("/admin/reports", headers=headers)
    assert page.status_code == 200
    assert page.text == "<main>Nous UI</main>"

    templates = client.get("/v1/admin/report-templates", headers=headers)
    assert templates.status_code == 200, templates.text
    assert {row["id"] for row in templates.json()} == {
        "security-daily", "cve-kev-deep-dive",
    }

    create_run = client.post("/v1/admin/report-runs", headers=headers, json={
        "template_id": "security-daily",
        "parameters": {
            "target_date": datetime.now(timezone.utc).date().isoformat(),
            "timezone": "UTC",
        },
        "idempotency_key": "gateway-report-run",
    })
    assert create_run.status_code == 202, create_run.text
    run_id = create_run.json()["run_id"]
    assert client.get("/v1/admin/report-runs?limit=10", headers=headers).status_code == 200
    assert client.get(f"/v1/admin/report-runs/{run_id}", headers=headers).status_code == 200

    create_schedule = client.post("/v1/admin/report-schedules", headers=headers, json={
        "template_id": "security-daily", "parameters": {"category": "advisory"},
        "timezone": "America/Los_Angeles", "cadence": "daily", "local_time": "09:00",
    })
    assert create_schedule.status_code == 201, create_schedule.text
    schedule_id = create_schedule.json()["id"]
    update_schedule = client.patch(
        f"/v1/admin/report-schedules/{schedule_id}", headers=headers,
        json={"enabled": False},
    )
    assert update_schedule.status_code == 200, update_schedule.text
    assert client.get("/v1/admin/report-schedules", headers=headers).status_code == 200

    # Authenticated readers can discover their role without a second login,
    # but must not acquire administrative capabilities.
    reader_headers = {**headers, "Cf-Access-Jwt-Assertion": _signed_assertion(
        key, issuer, audience, subject="ordinary-reader")}
    assert client.get("/v1/admin/session", headers=reader_headers).json() == {"allowed": False}
    assert client.get("/v1/admin/report-templates", headers=reader_headers).status_code == 403
    assert client.get("/v1/admin/session").status_code == 403

    # Keep the route/method allowlist exact, even for a valid Access identity.
    assert client.post("/v1/admin/report-templates", headers=headers).status_code == 404
    assert client.put("/v1/admin/report-runs", headers=headers).status_code == 404
