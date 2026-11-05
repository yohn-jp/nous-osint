"""Administration requires an Access identity, an operator allowlist and CSRF intent."""
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from nous.admin import app
from nous.db import Base
from nous.models import Source, SourceAudit
from nous.registry import load_registry, sync


class InjectIdentity:
    def __init__(self, subject, email=None):
        self.subject = subject
        self.email = email

    async def __call__(self, scope, receive, send):
        scope = {**scope, "state": {"access_identity": SimpleNamespace(
            subject=self.subject, email=self.email
        )}} if self.subject else {**scope, "state": {}}
        await app(scope, receive, send)


@pytest.fixture
def managed(tmp_path, monkeypatch):
    dsn = "sqlite:///" + str(tmp_path / "admin.db")
    engine = create_engine(dsn)
    Base.metadata.create_all(engine)
    secret = tmp_path / "admin_db_url"
    secret.write_text(dsn)
    monkeypatch.setenv("NOUS_ADMIN_DATABASE_URL_FILE", str(secret))
    monkeypatch.setenv("NOUS_ADMIN_SUBJECTS", "owner")
    monkeypatch.setenv("NOUS_PUBLIC_HOST", "nous.yohn.jp")
    client = TestClient(InjectIdentity("owner"), base_url="https://nous.yohn.jp")
    return client, sessionmaker(engine)


def write(client, method, path, payload=None, *, origin="https://nous.yohn.jp"):
    return client.request(method, path, json=payload or {},
                          headers={"Origin": origin, "X-Nous-Admin-Action": "1"})


def candidate():
    config = load_registry("sources")[0].model_dump()
    config.update({"id": "custom-sample", "enabled": False, "url": "https://example.org/feed"})
    return config


def test_admin_denies_anonymous_and_non_admin(managed):
    client, factory = managed
    anonymous = TestClient(InjectIdentity(None))
    non_admin = TestClient(InjectIdentity("someone-else"))
    assert anonymous.get("/v1/admin/session").status_code == 403
    assert anonymous.get("/v1/admin/catalog").status_code == 403
    assert non_admin.get("/v1/admin/session").json() == {"allowed": False}
    assert non_admin.get("/v1/admin/catalog").status_code == 403
    assert client.get("/v1/admin/session").json() == {"allowed": True}


def test_admin_reuses_verified_access_email_without_second_login(managed, monkeypatch):
    monkeypatch.setenv("NOUS_ADMIN_SUBJECTS", "")
    monkeypatch.setenv("NOUS_ADMIN_EMAILS", " Owner@Example.org ")
    operator = TestClient(InjectIdentity("access-stable-sub", "owner@example.org"))
    other = TestClient(InjectIdentity("access-other-sub", "other@example.org"))
    assert operator.get("/v1/admin/session").json() == {"allowed": True}
    assert operator.get("/v1/admin/catalog").status_code == 200
    assert other.get("/v1/admin/session").json() == {"allowed": False}
    assert other.get("/v1/admin/catalog").status_code == 403
    assert TestClient(InjectIdentity("access-stable-sub")).get("/v1/admin/session").json() == {"allowed": False}
    monkeypatch.setenv("NOUS_ADMIN_EMAILS", "")
    assert operator.get("/v1/admin/session").json() == {"allowed": False}


def test_custom_source_survives_catalog_sync_and_audits_changes(managed):
    client, factory = managed
    assert client.post("/v1/admin/sources", json=candidate()).status_code == 403
    assert write(client, "POST", "/v1/admin/sources", candidate(),
                 origin="https://attacker.invalid").status_code == 403
    created = write(client, "POST", "/v1/admin/sources", candidate())
    assert created.status_code == 201, created.text
    assert created.json()["origin"] == "custom"
    assert write(client, "POST", "/v1/admin/sources", candidate()).status_code == 409

    change = write(client, "PATCH", "/v1/admin/sources/custom-sample/settings",
                   {"enabled": True, "interval_minutes": 180})
    assert change.status_code == 200, change.text
    assert change.json()["enabled"] is True
    with factory() as session:
        sync(session, load_registry("sources"))
        row = session.scalar(select(Source).where(Source.source_key == "custom-sample"))
        assert row.enabled is True
        assert row.interval_minutes == 180
        assert row.origin == "custom"
        audits = session.scalars(select(SourceAudit).where(SourceAudit.source_id == row.id)).all()
        assert [a.action for a in audits] == ["create", "settings"]


def test_official_catalog_updates_preserve_instance_overrides(managed):
    client, factory = managed
    cfg = next(c for c in load_registry("sources") if c.id == "jpcert-alerts")
    assert cfg.enabled is False
    with factory() as session:
        sync(session, load_registry("sources"))
    settings = write(client, "PATCH", "/v1/admin/sources/jpcert-alerts/settings",
                     {"enabled": True, "interval_minutes": 240})
    assert settings.status_code == 200, settings.text
    after = settings.json()
    assert after["origin"] == "official"
    assert after["overrides"] == {"enabled": True, "interval_minutes": 240}

    with factory() as session:
        sync(session, load_registry("sources"))
        row = session.scalar(select(Source).where(Source.source_key == "jpcert-alerts"))
        assert row.enabled is True and row.interval_minutes == 240
        assert row.config["url"] == cfg.url
    assert write(client, "PUT", "/v1/admin/sources/jpcert-alerts", cfg.model_dump()).status_code == 409
    assert write(client, "POST", "/v1/admin/sources", {**cfg.model_dump(), "enabled": False}).status_code == 409


def test_admin_payload_validation_and_audit_endpoint(managed):
    client, factory = managed
    bad = {**candidate(), "url": "http://127.0.0.1/secret"}
    assert write(client, "POST", "/v1/admin/sources", bad).status_code == 422
    assert write(client, "POST", "/v1/admin/sources", candidate()).status_code == 201
    patch = write(client, "PATCH", "/v1/admin/sources/custom-sample/settings", {"enabled": None})
    assert patch.status_code == 422
    patch = write(client, "PATCH", "/v1/admin/sources/custom-sample/settings", {"max_concurrency": 999})
    assert patch.status_code == 422
    rows = client.get("/v1/admin/sources").json()
    assert rows[0]["id"] == "custom-sample"
    assert len(client.get("/v1/admin/audits").json()) == 1
