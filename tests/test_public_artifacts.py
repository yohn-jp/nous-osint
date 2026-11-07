"""Repository CVE reference snapshots: no payload fetch, no false PoC assertions."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from nous import public_artifacts as pub
from nous.api import CveResponse
from nous.cve_queries import query_cve
from nous.db import Base
from nous.models import (CveItemLink, Item, PublicArtifactContent,
                         PublicArtifactObservation, PublicArtifactPollState, Source)

CVE = "CVE-2026-12345"
OTHER = "CVE-2026-12346"
T0 = datetime(2026, 11, 7, 10, tzinfo=timezone.utc)
SHA_A, SHA_B, SHA_C, SHA_D, SHA_E = ("a" * 40, "b" * 40, "c" * 40, "d" * 40, "e" * 40)


def entry(name, kind, sha, mode=None):
    return {"path": name, "type": kind, "sha": sha,
            "mode": mode or ("040000" if kind == "tree" else "100644")}


def tree(sha, children, truncated=False):
    return {"sha": sha, "tree": children, "truncated": truncated}


def fake_provider_responses(provider):
    owner, repo, base, _kind = pub.PROVIDERS[provider]
    prefix = f"https://api.github.com/repos/{owner}/{repo}"
    commit = {"object": {"type": "commit", "sha": SHA_A}}
    recorded = {
        prefix + "/git/ref/heads/main": commit,
        prefix + "/git/commits/" + SHA_A: {"sha": SHA_A, "tree": {"sha": SHA_B}},
    }
    if provider == "trickest":
        recorded[prefix + "/git/trees/" + SHA_B] = tree(
            SHA_B, [entry("2026", "tree", SHA_C)])
        recorded[prefix + "/git/trees/" + SHA_C] = tree(
            SHA_C, [entry(CVE + ".md", "blob", SHA_D),
                    entry("README.md", "blob", SHA_E)])
    else:
        recorded[prefix + "/git/trees/" + SHA_B] = tree(
            SHA_B, [entry("http", "tree", SHA_C)])
        recorded[prefix + "/git/trees/" + SHA_C] = tree(
            SHA_C, [entry("cves", "tree", SHA_D)])
        recorded[prefix + "/git/trees/" + SHA_D] = tree(
            SHA_D, [entry("2026", "tree", SHA_E)])
        recorded[prefix + "/git/trees/" + SHA_E] = tree(
            SHA_E, [entry(CVE + ".yaml", "blob", SHA_B),
                    entry(CVE + "-DAST.yaml", "blob", SHA_C)])
    return recorded


@pytest.fixture
def repo_db(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "public-artifacts.db"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    with factory() as db:
        src = Source(
            source_key="provider-fixture", kind="rss", adapter="rss_v1",
            item_kind="advisory", url="https://provider.example/rss",
            config_revision="test", config={"max_concurrency": 1},
            enabled=True, interval_minutes=360, max_requests_per_hour=2,
        )
        db.add(src)
        db.flush()
        item = Item(
            source_id=src.id, external_id=CVE, kind="advisory",
            canonical_url="https://provider.example/advisory",
            title=CVE, state="current", current_version=1,
            current_hash="a" * 64,
        )
        db.add(item)
        db.flush()
        db.add(CveItemLink(item_id=item.id, cve_id=CVE, relation="reference"))
        db.commit()
    try:
        yield factory
    finally:
        engine.dispose()


def test_metadata_parser_requires_complete_git_trees(monkeypatch):
    for provider in pub.PROVIDERS:
        fixtures = fake_provider_responses(provider)
        seen = []
        def fake(url):
            seen.append(url)
            return fixtures[url]
        monkeypatch.setattr(pub, "_get_json", fake)
        commit, contents = pub.fetch_repository_index(provider, 2026)
        assert commit == SHA_A
        assert CVE in contents
        assert all(ref["path"].startswith("2026/" if provider == "trickest"
                                         else "http/cves/2026/")
                   for ref in contents[CVE])
        assert all("/git/" in path for path in seen)
        assert len(contents[CVE]) == (1 if provider == "trickest" else 2)

    with pytest.raises(ValueError, match="year"):
        pub._indexed_files("trickest", 2026, [entry(OTHER.replace("2026", "2024") +
                                                      ".md", "blob", SHA_A)])
    with pytest.raises(ValueError, match="unsafe"):
        monkeypatch.setattr(pub, "_get_json", lambda url: tree(SHA_A, [
            entry("../escaped", "blob", SHA_B)]))
        pub._tree("trickest/cve", SHA_A)
    with pytest.raises(ValueError, match="incomplete"):
        monkeypatch.setattr(pub, "_get_json", lambda url: tree(
            SHA_A, [entry(CVE + ".md", "blob", SHA_B)], truncated=True))
        pub._tree("trickest/cve", SHA_A)


def test_source_scope_does_not_claim_po_c_without_verified_index(repo_db, monkeypatch):
    calls = []
    def fake_index(provider, year):
        assert year == 2026
        calls.append(provider)
        return SHA_A, {
            CVE: [{"path": "2026/" + CVE + ".md", "blob_sha": SHA_B}]
        } if provider == "trickest" else {
            CVE: [{"path": "http/cves/2026/" + CVE + ".yaml",
                   "blob_sha": SHA_C}]
        }
    monkeypatch.setattr(pub, "fetch_repository_index", fake_index)
    with repo_db() as db:
        before = pub.repository_artifacts_as_of(db, CVE, T0)
        assert all(x["status"] == "unknown" for x in before)

    assert pub.refresh_public_artifacts(repo_db, current=T0)
    assert pub.refresh_public_artifacts(repo_db, current=T0 + timedelta(minutes=1))
    assert set(calls) == set(pub.PROVIDERS)
    assert pub.refresh_public_artifacts(repo_db, current=T0 + timedelta(minutes=2)) is False

    with repo_db() as db:
        tracked = pub.repository_artifacts_as_of(db, CVE, T0 + timedelta(minutes=3))
        assert all(x["status"] == "indexed" for x in tracked)
        assert all(x["references"] for x in tracked)
        assert all("/blob/" + SHA_A + "/" in x["references"][0]["url"]
                   for x in tracked)
        unknown = pub.repository_artifacts_as_of(db, OTHER, T0 + timedelta(minutes=3))
        assert all(x["status"] == "not_indexed" for x in unknown)
        historical = pub.repository_artifacts_as_of(db, CVE, T0 - timedelta(seconds=1))
        assert all(x["status"] == "unknown" for x in historical)
        stale = pub.repository_artifacts_as_of(db, CVE, T0 + timedelta(days=4))
        assert all(x["status"] == "stale" for x in stale)
        assert all(x["references"] for x in stale)
        validated = CveResponse.model_validate(query_cve(
            db, CVE, observed_cutoff=T0 + timedelta(minutes=3)))
        assert validated.public_artifacts[0].status == "indexed"
        assert validated.kev.status == "unknown"


def test_complete_removal_is_versioned_without_rewriting_old_snapshots(repo_db, monkeypatch):
    monkeypatch.setattr(pub, "fetch_repository_index", lambda provider, year: (SHA_A, {
        CVE: [{"path": ("2026/" if provider == "trickest" else "http/cves/2026/") +
              CVE + (".md" if provider == "trickest" else ".yaml"),
              "blob_sha": SHA_B}]
    }))
    pub.refresh_public_artifacts(repo_db, current=T0)
    pub.refresh_public_artifacts(repo_db, current=T0 + timedelta(minutes=1))
    monkeypatch.setattr(pub, "fetch_repository_index", lambda provider, year: (SHA_C, {}))
    pub.refresh_public_artifacts(repo_db, current=T0 + timedelta(days=2))
    pub.refresh_public_artifacts(repo_db, current=T0 + timedelta(days=2, minutes=1))
    with repo_db() as db:
        earlier = pub.repository_artifacts_as_of(db, CVE, T0 + timedelta(hours=2))
        later = pub.repository_artifacts_as_of(db, CVE, T0 + timedelta(days=2, minutes=2))
        assert all(x["status"] == "indexed" for x in earlier)
        assert all(x["status"] == "not_indexed" for x in later)
        assert len(db.scalars(select(PublicArtifactObservation)).all()) == 4
        assert len(db.scalars(select(PublicArtifactContent)).all()) == 3


def test_incomplete_tree_does_not_overwrite_previous_observation(repo_db, monkeypatch):
    monkeypatch.setattr(pub, "fetch_repository_index", lambda provider, year:
                        (SHA_A, {CVE: [{"path": "2026/" + CVE + ".md",
                                        "blob_sha": SHA_B}]}))
    pub.refresh_public_artifacts(repo_db, current=T0)
    monkeypatch.setattr(pub, "fetch_repository_index", lambda provider, year:
                        (_ for _ in ()).throw(ValueError("truncated")))
    assert pub.refresh_public_artifacts(repo_db, current=T0 + timedelta(days=2))
    with repo_db() as db:
        assert len(db.scalars(select(PublicArtifactObservation)).all()) == 1
        failed = db.scalars(select(PublicArtifactPollState).where(
            PublicArtifactPollState.last_error.is_not(None))).all()
        assert len(failed) == 1
        assert failed[0].last_error == "ValueError"
