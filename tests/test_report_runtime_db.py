"""PostgreSQL DB-to-Astro publication fixture; no Codex process or auth is used."""
import hashlib
import json
import os
import uuid
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

import nous.report_worker as worker
from nous.db import Base
from nous.models import Item, ItemVersion, Report, ReportEvidence, ReportRun, Source, now
from nous.report_templates import normalize_parameters, resolve_template


class FixtureRunner:
    version = "fixture-harness"
    model = "fixture-only"

    def __init__(self, *, workdir):
        self.workdir = workdir

    def run(self, stage, payload, *, run_id, timeout=240):
        if stage == "claims":
            evidence_id = payload["bundle"]["evidence"][0]["evidence_id"]
            return {"decision": "publish", "theme": "当日に掲載された更新情報",
                    "claims": [{
                        "claim_id": "C001",
                        "text": "公表元による更新情報の掲載が観測されました。",
                        "classification": "observed", "evidence_ids": [evidence_id],
                        "section": "primary_observations", "importance": "normal",
                    }]}
        if stage == "claim_review":
            evidence_id = payload["bundle"]["evidence"][0]["evidence_id"]
            return {"reviews": [{"claim_id": "C001", "decision": "accepted",
                                 "evidence_ids": [evidence_id],
                                 "reason_code": "supported"}]}
        raise AssertionError(f"unexpected stage {stage}")


@pytest.fixture
def postgres_runtime(tmp_path, monkeypatch):
    dsn = (os.getenv("NOUS_REPORT_TEST_DATABASE_URL") or
           os.getenv("DATABASE_URL"))
    if not dsn:
        pytest.skip("NOUS_REPORT_TEST_DATABASE_URL is not set")
    admin_engine = create_engine(dsn)
    schema = "report_fixture_" + uuid.uuid4().hex[:12]
    with admin_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(dsn, connect_args={"options": f"-csearch_path={schema}"})
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    site_root = tmp_path / "site"
    private_root = tmp_path / "private"
    codex_root = tmp_path / "codex-work"
    monkeypatch.setenv("NOUS_REPORT_SITE_DIR", str(site_root))
    monkeypatch.setenv("NOUS_REPORT_PRIVATE_DIR", str(private_root))
    monkeypatch.setenv("NOUS_CODEX_WORK_ROOT", str(codex_root))
    monkeypatch.setattr(worker, "CodexRunner", FixtureRunner)
    try:
        yield factory, site_root, private_root
    finally:
        engine.dispose()
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin_engine.dispose()


def test_postgres_fixture_runs_db_to_astro_to_publication(postgres_runtime):
    factory, site_root, private_root = postgres_runtime
    current = now()
    zone = ZoneInfo("Asia/Tokyo")
    target = current.astimezone(zone).date()
    source_url = "https://publisher.example/security/advisory-1"
    title = "公式アドバイザリは影響対象の更新を説明する試験用タイトルです。"
    attributes = {"title": title, "url": source_url,
                  "published": current.isoformat(), "updated": None}
    sha256 = hashlib.sha256(json.dumps(attributes, sort_keys=True,
                                       ensure_ascii=False).encode()).hexdigest()
    template = resolve_template("security-daily")
    parameters = normalize_parameters("security-daily", {
        "target_date": target.isoformat(), "timezone": "Asia/Tokyo",
    }, now=current)
    run_id = str(uuid.uuid4())
    with factory() as db:
        source = Source(
            source_key="fixture-advisory", kind="rss", url="https://publisher.example/feed",
            adapter="rss_v1", item_kind="advisory", config_revision="a" * 64,
            config={"policy": {"content_storage": "metadata_only", "license_id": "NOASSERTION"}},
            enabled=True, interval_minutes=60, max_requests_per_hour=10, origin="official",
            overrides={}, next_due_at=current, last_success_at=current,
        )
        db.add(source)
        db.flush()
        item = Item(
            source_id=source.id, external_id=source_url, canonical_url=source_url,
            kind="advisory", title=title, state="current", first_seen_at=current,
            last_seen_at=current, current_version=1, current_hash=sha256,
        )
        db.add(item)
        db.flush()
        version = ItemVersion(
            item_id=item.id, version=1, observed_at=current, sha256=sha256,
            attributes=attributes,
            provenance={"source_url": source.url, "final_url": source.url,
                        "item_url": source_url, "retrieved_at": current.isoformat(),
                        "adapter": source.adapter, "extraction_method": "fixture"},
        )
        db.add(version)
        db.add(ReportRun(
            id=run_id, trigger="manual", created_by="fixture-owner",
            template_id=template["id"], template_revision=template["revision_key"],
            template_snapshot=template, parameters=parameters, idempotency_key=run_id,
            state="queued", stage="queued", attempts=0, available_at=current,
            stage_artifacts={}, created_at=current,
        ))
        db.commit()
        item_id, version_id = item.id, version.id

    assert worker.run_once(factory) is True
    with factory() as db:
        run = db.get(ReportRun, run_id)
        report = db.scalar(select(Report).where(Report.run_id == run_id))
        evidence = db.scalars(select(ReportEvidence).where(
            ReportEvidence.report_id == report.id)).all()
        version = db.get(ItemVersion, version_id)
        assert run.state == "published"
        assert run.report_id == report.id
        assert report.article["claims"][0]["classification"] == "observed"
        assert len(evidence) == 1
        assert evidence[0].item_id == item_id
        assert evidence[0].item_version_id == version_id
        assert evidence[0].item_version_sha256 == version.sha256
        assert report.artifact_digest == worker._current_digest(site_root)
        assert (site_root / "current" / "index.html").is_file()
        assert (site_root / "current" / "security" / report.slug / "index.html").is_file()
        assert run.stage_artifacts.keys() == {"claims", "claim_review", "article"}
    assert not list(private_root.glob("runs/*/workspace"))
