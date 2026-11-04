from datetime import datetime, timedelta, timezone
import hashlib
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

import nous.report_worker as worker
from nous.db import Base
from nous.models import ReportRun, ReportSiteState
from nous.report_templates import normalize_parameters, resolve_template


def fake_static_build(articles, staging_root):
    staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    dist = staging_root / ("fixture-dist-" + uuid.uuid4().hex)
    dist.mkdir(mode=0o700)
    pages = {"index.html": "<html><body>fixture index</body></html>"}
    for article in articles:
        if article.get("slug"):
            path = f"{article['category']}/{article['slug']}/index.html"
            pages[path] = "<html><body>fixture report</body></html>"
    digest = hashlib.sha256()
    for relative, content in sorted(pages.items()):
        path = dist / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        data = content.encode()
        path.write_bytes(data)
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return dist, [], digest.hexdigest()


@pytest.fixture
def publication(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///" + str(tmp_path / "publication.db"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    monkeypatch.setenv("NOUS_REPORT_PRIVATE_DIR", str(tmp_path / "private"))
    monkeypatch.setenv("NOUS_REPORT_SITE_DIR", str(tmp_path / "site"))
    monkeypatch.setattr(worker, "build_static_release", fake_static_build)
    template = resolve_template("security-daily")
    run_id = str(uuid.uuid4())
    parameters = normalize_parameters("security-daily", {
        "target_date": "2026-11-03", "timezone": "Asia/Tokyo",
    }, now=datetime(2026, 11, 4, tzinfo=timezone.utc))
    with factory() as db:
        db.add(ReportRun(
            id=run_id, trigger="manual", created_by="fixture", template_id=template["id"],
            template_revision=template["revision_key"], template_snapshot=template,
            parameters=parameters, idempotency_key=run_id, state="running", stage="article",
            attempts=1, available_at=datetime.now(timezone.utc),
            lease_until=datetime.now(timezone.utc) + timedelta(minutes=5),
            lease_token="lease-valid", stage_artifacts={}, created_at=datetime.now(timezone.utc),
        ))
        db.commit()
    assert worker.ensure_current_release(factory)
    claim = {
        "id": run_id, "lease_token": "lease-valid", "template_id": template["id"],
        "template_revision": template["revision_key"], "template_snapshot": template,
        "parameters": parameters,
    }
    bundle = {"sha256": "a" * 64}
    article = {"title": "verified fixture claim", "summary": ["verified fixture claim"]}
    return factory, claim, bundle, article


def test_stale_lease_never_promotes_a_built_candidate(publication, monkeypatch):
    factory, claim, bundle, article = publication
    site_root = worker.public_root()
    before = worker._current_digest(site_root)
    stale = {**claim, "lease_token": "stale-token"}

    with pytest.raises(worker.LeaseLost):
        worker._publish_candidate(factory, stale, stale["lease_token"], bundle,
                                  article, "fixture-only", "fixture-harness")

    assert worker._current_digest(site_root) == before
    with factory() as db:
        state = db.get(ReportSiteState, 1)
        assert state.active_digest == before
        assert state.pending_digest is None
        assert state.pending_run_id is None


def test_database_failure_after_promotion_restores_previous_release(publication, monkeypatch):
    factory, claim, bundle, article = publication
    site_root = worker.public_root()
    before = worker._current_digest(site_root)
    monkeypatch.setattr(worker, "_evidence_db_rows", lambda *_args: [])
    original_commit = Session.commit
    commit_count = 0

    def fail_publication_commit(session):
        nonlocal commit_count
        commit_count += 1
        # First commit records the durable intent; fail the DB publication
        # transaction after the current symlink has been promoted.
        if commit_count == 2:
            raise RuntimeError("injected publication commit failure")
        return original_commit(session)

    monkeypatch.setattr(Session, "commit", fail_publication_commit)
    with pytest.raises(RuntimeError, match="injected publication commit failure"):
        worker._publish_candidate(factory, claim, claim["lease_token"], bundle,
                                  article, "fixture-only", "fixture-harness")

    assert commit_count == 3  # intent, injected failure, intent cleanup
    assert worker._current_digest(site_root) == before
    with factory() as db:
        state = db.get(ReportSiteState, 1)
        assert state.active_digest == before
        assert state.pending_digest is None
        assert state.pending_run_id is None
