from datetime import datetime, timedelta, timezone
import hashlib
import uuid

import pytest
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session, sessionmaker

import nous.report_worker as worker
from nous.db import Base
from nous.models import (
    CveItemLink,
    CveItemVersionLink,
    Item,
    ItemVersion,
    Report,
    ReportRun,
    ReportSiteState,
    Source,
)
from nous.report_templates import normalize_parameters, resolve_template


def fake_static_build(articles, staging_root):
    staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    dist = staging_root / ("fixture-dist-" + uuid.uuid4().hex)
    dist.mkdir(mode=0o700)
    pages = {
        "index.html": "<html><body>fixture index</body></html>",
        "404.html": "<html><body>fixture 404 <a href=\"/reports/\">All reports</a></body></html>",
    }
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


def test_corrupt_active_release_is_rebuilt_at_the_same_digest(publication):
    factory, _claim, _bundle, _article = publication
    site_root = worker.public_root()
    digest = worker._current_digest(site_root)
    index = site_root / "releases" / digest / "index.html"
    index.chmod(0o644)
    index.write_text("<html>corrupted</html>", encoding="utf-8")
    assert not worker._verify_release(site_root, digest)

    repaired = worker.ensure_current_release(factory)

    assert repaired == digest
    assert worker._current_digest(site_root) == digest
    assert worker._verify_release(site_root, digest)
    assert index.read_text(encoding="utf-8") == "<html><body>fixture index</body></html>"


@pytest.mark.parametrize("include_published_article", [False, True])
def test_legacy_release_without_404_page_is_rebuilt_from_published_archive(
        publication, tmp_path, monkeypatch, include_published_article):
    factory, claim, _bundle, _article = publication
    site_root = worker.public_root()

    if include_published_article:
        with factory() as db:
            db.add(Report(
                id=str(uuid.uuid4()), run_id=claim["id"], slug="previous-published-report",
                category="security", template_id="security-daily",
                article={"title": "Published", "summary": ["Published"],
                         "claims": [], "sections": []},
                headline="Published", summary=["Published"],
                published_at=datetime.now(timezone.utc), artifact_digest="a" * 64,
                artifact_path="releases/" + "a" * 64, harness_version="fixture",
                input_digest="b" * 64,
            ))
            db.commit()

    # Model a pre-404 release whose index and manifest are otherwise valid.
    legacy_dist = tmp_path / "legacy-dist"
    legacy_dist.mkdir()
    (legacy_dist / "index.html").write_text(
        "<html><body>legacy index</body></html>", encoding="utf-8"
    )
    legacy_hash = hashlib.sha256()
    legacy_hash.update(b"index.html")
    legacy_hash.update(b"\0")
    legacy_hash.update((legacy_dist / "index.html").read_bytes())
    legacy_hash.update(b"\0")
    legacy_digest = legacy_hash.hexdigest()
    worker._write_release(site_root, legacy_dist, [], legacy_digest)
    worker._promote(site_root, legacy_digest)
    worker._persist_site_state(factory, legacy_digest)
    assert worker._verify_release(site_root, legacy_digest)
    assert not worker._release_has_404_page(site_root, legacy_digest)

    builds = []

    def record_build(articles, staging_root):
        builds.append(articles)
        return fake_static_build(articles, staging_root)

    monkeypatch.setattr(worker, "build_static_release", record_build)
    repaired = worker.ensure_current_release(factory)

    assert len(builds) == 1
    assert repaired != legacy_digest
    repaired_release = site_root / "releases" / repaired
    assert (repaired_release / "404.html").is_file()
    assert worker._current_digest(site_root) == repaired
    assert worker._is_current_contract_release(site_root, repaired)
    assert (site_root / "releases" / legacy_digest / "index.html").is_file()
    if include_published_article:
        assert (repaired_release / "security" / "previous-published-report" / "index.html").is_file()
        assert builds[0][0]["slug"] == "previous-published-report"
    else:
        assert builds[0] == []
    with factory() as db:
        state = db.get(ReportSiteState, 1)
        assert state.active_digest == repaired
        assert state.pending_digest is None
        assert state.pending_run_id is None


def test_saved_bundle_evidence_uses_immutable_version_link_after_current_link_changes(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "saved-evidence.db"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    observed_at = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)
    cve_id = "CVE-2026-12345"
    with factory() as db:
        source = Source(
            source_key="legacy-advisories", kind="rss", adapter="json_v1",
            item_kind="advisory", url="https://publisher.example/feed",
            config_revision="fixture", config={}, enabled=True,
            interval_minutes=60, max_requests_per_hour=10,
        )
        db.add(source)
        db.flush()
        item = Item(
            source_id=source.id, external_id="advisory-1",
            canonical_url="https://publisher.example/advisory-1#section", kind="advisory",
            title="Advisory references CVE-2026-12345", state="current",
            first_seen_at=observed_at, last_seen_at=observed_at,
            current_version=2, current_hash="b" * 64,
        )
        db.add(item)
        db.flush()
        version = ItemVersion(
            item_id=item.id, version=1, observed_at=observed_at,
            sha256="a" * 64,
            attributes={
                "title": "Advisory references CVE-2026-12345",
                "url": "https://publisher.example/advisory-1#section",
                "cve_relations": {cve_id: "title_mention"},
            },
            provenance={"adapter": "rss_v1", "item_url": "https://publisher.example/advisory-1#section"},
        )
        db.add(version)
        db.flush()
        db.add_all([
            CveItemVersionLink(item_version_id=version.id, cve_id=cve_id,
                               relation="title_mention"),
            CveItemLink(item_id=item.id, cve_id=cve_id, relation="title_mention"),
        ])
        db.commit()
        evidence = {
            "E001": {
                "evidence_id": "E001", "item_id": item.id,
                "item_version_id": version.id, "item_version_sha256": version.sha256,
                "source_key": source.source_key,
                "publisher_url": "https://publisher.example/advisory-1",
                "observed_at": observed_at.isoformat(),
                "relation": "title_mention",
            }
        }
        bundle = {"parameters": {"cve_id": cve_id}, "evidence": list(evidence.values())}
        article = {"sections": [{"blocks": [{"type": "paragraph",
                                               "evidence_ids": ["E001"]}]}]}

        # A later observation retires the mutable current CVE link after the
        # saved bundle already captured its version id and relation.
        db.execute(delete(CveItemLink).where(CveItemLink.item_id == item.id))
        db.commit()
        first_attempt = worker._evidence_db_rows(db, "report-1", article, bundle)
        retry_attempt = worker._evidence_db_rows(db, "report-1", article, bundle)

        assert len(first_attempt) == len(retry_attempt) == 1
        assert first_attempt[0].item_version_id == retry_attempt[0].item_version_id == version.id
        assert first_attempt[0].relation == retry_attempt[0].relation == "title_mention"
        assert first_attempt[0].publisher_url == "https://publisher.example/advisory-1"
        assert version.attributes["url"] == "https://publisher.example/advisory-1#section"
        assert version.provenance["item_url"] == "https://publisher.example/advisory-1#section"
        assert version.sha256 == "a" * 64

        version.attributes = {**version.attributes, "url": "https://publisher.example/changed#section"}
        db.commit()
        with pytest.raises(worker.ReportError, match="evidence_source_identity_mismatch"):
            worker._evidence_db_rows(db, "report-1", article, bundle)


def test_archive_capacity_rejects_candidate_without_breaking_recovery(publication, monkeypatch):
    """The N+1 release must not be persisted, leaving N safe to serve."""
    factory, claim, bundle, article = publication
    before = worker._current_digest(worker.public_root())
    monkeypatch.setattr(worker, "_MAX_ARCHIVE_REPORTS", 1)
    with factory() as db:
        db.add(Report(
            id=str(uuid.uuid4()), run_id=claim["id"], slug="prior-report",
            category="security", template_id="security-daily",
            article={"title": "Prior", "summary": ["Prior"], "claims": [],
                     "sections": []},
            headline="Prior", summary=["Prior"],
            published_at=datetime.now(timezone.utc),
            artifact_digest=before, artifact_path=f"releases/{before}",
            harness_version="fixture", input_digest="b" * 64,
        ))
        db.commit()

    with pytest.raises(worker.ReportError, match="report_archive_limit_exceeded"):
        worker._publish_candidate(factory, claim, claim["lease_token"],
                                  bundle, article, "fixture", "fixture")
    assert worker.ensure_current_release(factory) == before
    with factory() as db:
        assert db.get(ReportSiteState, 1).pending_digest is None
        assert len(db.query(Report).all()) == 1
