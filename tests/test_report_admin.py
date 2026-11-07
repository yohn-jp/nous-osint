from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from nous.admin import app
from nous.db import Base
from nous.models import Report, ReportRun, ReportRunEvent
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


def test_cve_idempotency_reuses_normalized_window_across_retry(managed, monkeypatch):
    from nous import admin

    client, factory = managed
    first = datetime(2026, 11, 4, 1, tzinfo=timezone.utc)
    later = datetime(2026, 11, 5, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(admin, "now", lambda: first)
    body = {
        "template_id": "cve-kev-deep-dive",
        "parameters": {"cve_id": "CVE-2026-12345", "period_days": 30},
        "idempotency_key": "cve-stable-window",
    }
    created = write(client, "POST", "/v1/admin/report-runs", body)
    assert created.status_code == 202
    with factory() as db:
        original_window = db.get(ReportRun, created.json()["run_id"]).parameters

    monkeypatch.setattr(admin, "now", lambda: later)
    retry = write(client, "POST", "/v1/admin/report-runs", body)
    assert retry.status_code == 202
    assert retry.json()["run_id"] == created.json()["run_id"]
    with factory() as db:
        assert db.get(ReportRun, created.json()["run_id"]).parameters == original_window
    changed = {**body, "parameters": {"cve_id": "CVE-2026-12345", "period_days": 29}}
    assert write(client, "POST", "/v1/admin/report-runs", changed).status_code == 409


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
                    {"enabled": False, "cadence": "weekly", "timezone": "UTC",
                     "local_time": "09:15", "parameters": {"category": "vulnerability"}})
    assert updated.status_code == 200 and updated.json()["enabled"] is False
    assert updated.json()["cadence"] == "weekly"
    assert updated.json()["timezone"] == "UTC"
    assert updated.json()["local_time"] == "09:15"
    assert updated.json()["parameters"] == {"category": "vulnerability"}
    assert client.get("/v1/admin/report-schedules").json()["schedules"][0]["enabled"] is False
    assert write(client, "POST", "/v1/admin/report-schedules", {
        **body, "timezone": "UTC", "parameters": {"category": "https://evil.example"},
    }).status_code == 422
    assert write(client, "POST", "/v1/admin/report-schedules", {
        **body, "template_id": "cve-kev-deep-dive",
    }).status_code == 422
    assert write(client, "PATCH", f"/v1/admin/report-schedules/{schedule['id']}",
                 {"timezone": "../etc"}).status_code == 422


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


def test_run_detail_exposes_bounded_safe_event_timeline(managed):
    client, factory = managed
    template = resolve_template("security-daily")
    run_id = "563b9494-f5b2-4ad0-b345-44da1b2e6a85"
    current = datetime.now(timezone.utc)
    with factory() as db:
        db.add(ReportRun(
            id=run_id, trigger="manual", created_by="owner", template_id=template["id"],
            template_revision=template["revision_key"], template_snapshot=template,
            parameters={"target_date": "2026-11-01"}, idempotency_key="timeline-run",
            state="failed", stage="claim_review", failed_stage="claim_review",
            error_code="codex_auth", attempts=2, available_at=current,
            stage_artifacts={}, created_at=current,
        ))
        for seq in range(105):
            db.add(ReportRunEvent(
                run_id=run_id, attempt=1 + seq // 100, seq=seq % 100,
                created_at=current, stage="claim_review", event_type="codex_stage_failed",
                error_code="codex_auth" if seq == 104 else None,
                exit_status=1 if seq == 104 else None,
                elapsed_ms=1354 if seq == 104 else 20,
                usage={"input_tokens": 42, "output_tokens": 7, "unsafe": "secret"},
                artifact_sha256="a" * 64,
                diagnostic_ref="runs/example/attempts/2/claim_review/diagnostic.json",
                retryable=False,
            ))
        db.commit()

    detail = client.get(f"/v1/admin/report-runs/{run_id}")
    assert detail.status_code == 200
    result = detail.json()
    assert result["failed_stage"] == "claim_review"
    assert result["attempts"] == 2
    assert len(result["events"]) == 100
    assert result["events"][0]["attempt"] == 1
    assert result["events"][-1]["error_code"] == "codex_auth"
    assert result["events"][-1]["usage"] == {"input_tokens": 42, "output_tokens": 7}
    assert "secret" not in detail.text
    assert "stderr" not in detail.text


def test_run_timeline_requires_access_identity(managed):
    client, _ = managed
    response = TestClient(app).get("/v1/admin/report-runs/563b9494-f5b2-4ad0-b345-44da1b2e6a85")
    assert response.status_code == 403


def test_schedule_create_rejects_nonexistent_spring_forward_time(managed, monkeypatch):
    import nous.admin as admin

    client, _ = managed
    # New York jumps from 01:59:59 to 03:00 on 2026-03-08.
    monkeypatch.setattr(
        admin, "now",
        lambda: datetime(2026, 3, 8, 6, 30, tzinfo=timezone.utc),
    )
    result = write(client, "POST", "/v1/admin/report-schedules", {
        "template_id": "security-daily", "parameters": {"category": None},
        "timezone": "America/New_York", "cadence": "daily",
        "local_time": "02:30",
    })
    assert result.status_code == 422
    assert result.json()["detail"] == "local time does not exist in the selected timezone"


def test_schedule_list_paginates_more_than_one_hundred_active_entries(managed):
    import uuid
    from datetime import timedelta
    from nous.models import ReportSchedule

    client, factory = managed
    template = resolve_template("security-daily")
    base = datetime(2026, 11, 1, tzinfo=timezone.utc)
    with factory() as db:
        for number in range(103):
            created = base + timedelta(minutes=number)
            db.add(ReportSchedule(
                id=str(uuid.uuid4()), template_id=template["id"],
                template_revision=template["revision_key"],
                template_snapshot=template, parameters={"category": None},
                timezone="Asia/Tokyo", cadence="daily", local_time="09:00",
                next_slot_at=base + timedelta(days=1), enabled=True,
                created_by="owner", created_at=created, updated_at=created,
            ))
        db.commit()

    seen = []
    cursor = None
    while True:
        query = "?limit=50" + (f"&cursor={cursor}" if cursor else "")
        response = client.get("/v1/admin/report-schedules" + query)
        assert response.status_code == 200, response.text
        page = response.json()
        seen.extend(item["id"] for item in page["schedules"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert len(seen) == len(set(seen)) == 103
    assert client.get("/v1/admin/report-schedules?limit=101").status_code == 422
    assert client.get("/v1/admin/report-schedules?cursor=not-a-uuid").status_code == 422
