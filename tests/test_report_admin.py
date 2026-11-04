from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from nous.admin import app
from nous.db import Base
from nous.models import Report, ReportRun
from nous.report_templates import resolve_template


class InjectIdentity:
    def __init__(self, subject="owner"):
        self.subject = subject

    async def __call__(self, scope, receive, send):
        state = {"access_identity": SimpleNamespace(subject=self.subject, email=None)}
        await app({**scope, "state": state}, receive, send)


@pytest.fixture
def managed(tmp_path, monkeypatch):
    dsn = "sqlite:///" + str(tmp_path / "reports-admin.db")
    engine = create_engine(dsn)
    Base.metadata.create_all(engine)
    secret = tmp_path / "admin-db-url"
    secret.write_text(dsn)
    monkeypatch.setenv("NOUS_ADMIN_DATABASE_URL_FILE", str(secret))
    monkeypatch.setenv("NOUS_ADMIN_SUBJECTS", "owner")
    monkeypatch.setenv("NOUS_PUBLIC_HOST", "nous.yohn.jp")
    return TestClient(InjectIdentity(), base_url="https://nous.yohn.jp"), sessionmaker(engine)


def write(client, method, path, payload):
    return client.request(method, path, json=payload, headers={
        "Origin": "https://nous.yohn.jp", "X-Nous-Admin-Action": "1",
    })


def test_manual_run_idempotency_detail_and_templates(managed):
    client, factory = managed
    templates = client.get("/v1/admin/report-templates")
    assert templates.status_code == 200
    assert {row["id"] for row in templates.json()} == {
        "security-daily", "cve-kev-deep-dive",
    }

    target = datetime.now(timezone.utc).astimezone().date().isoformat()
    body = {
        "template_id": "security-daily",
        "parameters": {"target_date": target, "timezone": "Asia/Tokyo"},
        "idempotency_key": "fixture-run-1",
    }
    created = write(client, "POST", "/v1/admin/report-runs", body)
    assert created.status_code == 202, created.text
    run_id = created.json()["run_id"]
    assert write(client, "POST", "/v1/admin/report-runs", body).json()["run_id"] == run_id
    mismatch = {**body, "parameters": {"target_date": "2026-11-01", "timezone": "UTC"}}
    assert write(client, "POST", "/v1/admin/report-runs", mismatch).status_code == 409

    with factory() as db:
        row = db.get(ReportRun, run_id)
        row.stage = "fact_check"
        row.stage_artifacts = {"plan": {"private": "must not be returned"}}
        row.state = "running"
        db.commit()
    detail = client.get(f"/v1/admin/report-runs/{run_id}")
    assert detail.status_code == 200
    assert detail.json()["stages"] == {"plan": "complete", "fact_check": "running"}
    assert "private" not in detail.text
    assert detail.json()["parameters"]["target_date"] == target
    assert client.get("/v1/admin/report-runs?limit=10").json()["runs"][0]["run_id"] == run_id


@pytest.mark.parametrize("payload", [
    {"template_id": "security-daily", "parameters": {"target_date": "2099-01-01"}},
    {"template_id": "security-daily", "parameters": {"target_date": "2026-11-01", "arbitrary": "x"}},
    {"template_id": "cve-kev-deep-dive", "parameters": {"cve_id": "CVE-2024-1234", "free_prompt": "x"}},
])
def test_manual_run_rejects_invalid_or_open_ended_parameters(managed, payload):
    client, _ = managed
    assert write(client, "POST", "/v1/admin/report-runs", payload).status_code == 422


def test_schedule_create_toggle_and_strict_validation(managed):
    client, factory = managed
    body = {
        "template_id": "security-daily", "parameters": {"category": "advisory"},
        "timezone": "Asia/Tokyo", "cadence": "daily", "local_time": "08:30",
    }
    created = write(client, "POST", "/v1/admin/report-schedules", body)
    assert created.status_code == 201, created.text
    schedule = created.json()
    assert schedule["parameters"] == {"category": "advisory"}
    assert schedule["enabled"] is True
    updated = write(client, "PATCH", f"/v1/admin/report-schedules/{schedule['id']}",
                    {"enabled": False})
    assert updated.status_code == 200 and updated.json()["enabled"] is False
    assert client.get("/v1/admin/report-schedules").json()["schedules"][0]["enabled"] is False
    assert write(client, "POST", "/v1/admin/report-schedules", {
        **body, "timezone": "UTC", "parameters": {"category": "https://evil.example"},
    }).status_code == 422
    assert write(client, "POST", "/v1/admin/report-schedules", {
        **body, "template_id": "cve-kev-deep-dive",
    }).status_code == 422


def test_run_detail_publication_url_only_for_validated_report(managed):
    client, factory = managed
    template = resolve_template("security-daily")
    run_id, report_id = "563b9494-f5b2-4ad0-b345-44da1b2e6a85", "7f3b9494-f5b2-4ad0-b345-44da1b2e6a85"
    current = datetime.now(timezone.utc)
    with factory() as db:
        db.add(ReportRun(
            id=run_id, trigger="manual", created_by="owner", template_id=template["id"],
            template_revision=template["revision_key"], template_snapshot=template,
            parameters={"target_date": "2026-11-01"}, idempotency_key="pub-run",
            state="published", stage="published", attempts=1, available_at=current,
            stage_artifacts={}, report_id=report_id, created_at=current,
        ))
        db.flush()
        db.add(Report(
            id=report_id, run_id=run_id, slug="2026-11-01-security-daily-563b9494f5b2",
            category="security", template_id=template["id"], article_schema_version=1,
            article={"title": "verified fixture"}, headline="verified fixture", summary=[],
            published_at=current, artifact_digest="a" * 64,
            artifact_path="releases/" + "a" * 64, supersedes_id=None,
            model=None, harness_version="fixture", input_digest="b" * 64,
        ))
        db.commit()
    detail = client.get(f"/v1/admin/report-runs/{run_id}")
    assert detail.json()["published_url"] == "/reports/security/2026-11-01-security-daily-563b9494f5b2/"
