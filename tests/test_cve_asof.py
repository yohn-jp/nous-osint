"""Historical CVE references remain queryable after current links retire."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from nous.cve_index import version_cve_relations
from nous.cve_queries import query_cve
from nous.db import Base
from nous.models import CveItemLink, CveItemVersionLink, Item, ItemVersion, Source


def test_deleted_current_cve_link_does_not_erase_historical_reference(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "cve-asof.db"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    cve_id = "CVE-2026-67890"
    observed_at = datetime(2026, 1, 2, 12, tzinfo=timezone.utc)
    cutoff = observed_at + timedelta(minutes=1)

    with factory() as db:
        source = Source(
            source_key="fixture-vendor", kind="rss", adapter="rss_v1",
            item_kind="advisory", url="https://vendor.example/security/rss",
            config_revision="fixture", config={"max_concurrency": 1}, enabled=True,
            interval_minutes=60, max_requests_per_hour=4,
        )
        db.add(source)
        db.flush()
        item = Item(
            source_id=source.id, external_id="advisory-1",
            canonical_url="https://vendor.example/security/advisory-1",
            kind="advisory", title="Revised advisory without a CVE mention",
            state="current", first_seen_at=observed_at - timedelta(days=1),
            last_seen_at=observed_at + timedelta(days=1), current_version=2,
            current_hash="b" * 64,
        )
        db.add(item)
        db.flush()
        old_version = ItemVersion(
            item_id=item.id, version=1, observed_at=observed_at,
            sha256="a" * 64,
            attributes={
                "title": f"Security fix references {cve_id}",
                "url": item.canonical_url,
                "cve_relations": {cve_id: "title_mention"},
            },
            provenance={},
        )
        current_version = ItemVersion(
            item_id=item.id, version=2, observed_at=observed_at + timedelta(days=1),
            sha256="b" * 64,
            attributes={
                "title": item.title, "url": item.canonical_url,
                "cve_relations": {},
            },
            provenance={},
        )
        db.add_all([old_version, current_version])
        db.flush()
        db.add(CveItemVersionLink(
            item_version_id=old_version.id, cve_id=cve_id, relation="title_mention",
        ))
        # Current links have been retired after the title changed.
        assert db.scalar(select(CveItemLink).where(CveItemLink.cve_id == cve_id)) is None
        db.commit()

    with factory() as db:
        historical = query_cve(db, cve_id, observed_cutoff=cutoff)
        current = query_cve(db, cve_id)

    assert len(historical["references"]) == 1
    assert historical["references"][0]["title"] == f"Security fix references {cve_id}"
    assert historical["references"][0]["last_seen_at"] == observed_at.replace(tzinfo=None)
    assert current["references"] == []


def test_legacy_snapshot_without_frozen_map_keeps_current_and_historical_reference(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "legacy-cve-asof.db"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    cve_id = "CVE-2026-54321"
    observed_at = datetime(2026, 5, 1, 12, tzinfo=timezone.utc)
    attrs = {
        "title": f"Legacy snapshot references {cve_id}",
        "url": "https://vendor.example/security/legacy",
    }
    provenance = {"adapter": "rss_v1", "source_url": "https://vendor.example/rss"}
    relations = version_cve_relations(
        attributes=attrs, provenance=provenance, external_id="legacy-advisory",
        source_key="legacy-vendor", source_origin="official",
    )

    with factory() as db:
        source = Source(
            # The current adapter changed after this legacy observation; its
            # relation must still come from the recorded rss_v1 provenance.
            source_key="legacy-vendor", kind="json_api", adapter="json_v1",
            item_kind="advisory", url="https://vendor.example/rss",
            config_revision="fixture", config={}, enabled=True,
            interval_minutes=60, max_requests_per_hour=4,
        )
        db.add(source)
        db.flush()
        item = Item(
            source_id=source.id, external_id=cve_id,
            canonical_url=attrs["url"], kind="advisory", title=attrs["title"],
            state="current", first_seen_at=observed_at, last_seen_at=observed_at,
            current_version=1, current_hash="c" * 64,
        )
        db.add(item)
        db.flush()
        version = ItemVersion(
            item_id=item.id, version=1, observed_at=observed_at,
            sha256="c" * 64, attributes=attrs, provenance=provenance,
        )
        db.add(version)
        db.flush()
        for relation_id, relation in relations.items():
            db.add(CveItemVersionLink(
                item_version_id=version.id, cve_id=relation_id, relation=relation,
            ))
        # A conflicting current row must not rewrite the immutable snapshot grade.
        db.add(CveItemLink(item_id=item.id, cve_id=cve_id, relation="record"))
        db.commit()

    with factory() as db:
        historical = query_cve(
            db, cve_id, observed_cutoff=observed_at + timedelta(hours=1),
        )
        current = query_cve(db, cve_id)

    for result in (historical, current):
        assert len(result["references"]) == 1
        assert result["references"][0]["relation"] == "title_mention"


def test_complete_kev_catalog_timeline_handles_removal_and_relisting(tmp_path):
    import uuid
    from nous.models import KevCatalogContent, KevCatalogObservation

    engine = create_engine("sqlite:///" + str(tmp_path / "kev-timeline.db"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    cve_id = "CVE-2026-91234"
    t1 = datetime(2026, 11, 1, 10, tzinfo=timezone.utc)
    t2, t3, t4 = (t1 + timedelta(days=n) for n in (1, 2, 3))
    url = ("https://raw.githubusercontent.com/cisagov/kev-data/develop/"
           "known_exploited_vulnerabilities.json")

    with factory() as db:
        source = Source(
            source_key="cisa-kev", origin="official", kind="json_api",
            adapter="cisa_kev_v1", item_kind="vulnerability",
            url=url, config_revision="fixture", config={},
            enabled=True, interval_minutes=360, max_requests_per_hour=4,
            last_success_at=t4,
        )
        db.add(source)
        db.flush()
        item = Item(
            source_id=source.id, external_id=cve_id, kind="vulnerability",
            canonical_url=f"https://www.cve.org/CVERecord?id={cve_id}",
            title="CISA observation", state="unknown",
            first_seen_at=t1 - timedelta(minutes=1), last_seen_at=t3,
            current_version=1, current_hash="a" * 64,
        )
        db.add(item)
        db.flush()
        version = ItemVersion(
            item_id=item.id, version=1, observed_at=t1,
            sha256="a" * 64,
            attributes={
                "title": "CISA observation", "url": item.canonical_url,
                "vulnerability": {"cve_id": cve_id, "known_exploited": True},
                "cve_relations": {cve_id: "kev"},
            },
            provenance={"adapter": "cisa_kev_v1", "source_url": url},
        )
        db.add(version)
        db.flush()
        db.add(CveItemVersionLink(
            item_version_id=version.id, cve_id=cve_id, relation="kev",
        ))
        for instant, digest, members in (
            (t1, "1" * 64, [cve_id]),
            (t2, "2" * 64, ["CVE-2026-11111"]),
            (t3, "3" * 64, [cve_id]),
            (t4, "2" * 64, ["CVE-2026-11111"]),
        ):
            if digest != "2" * 64 or instant == t2:
                db.add(KevCatalogContent(digest=digest, cve_ids=members))
            db.add(KevCatalogObservation(
                id=str(uuid.uuid4()), source_id=source.id,
                observed_at=instant, digest=digest,
            ))
        db.commit()

    with factory() as db:
        older = query_cve(db, cve_id, observed_cutoff=t1 + timedelta(minutes=10))
        missing = query_cve(db, cve_id, observed_cutoff=t2 + timedelta(minutes=10))
        relisted = query_cve(db, cve_id, observed_cutoff=t3 + timedelta(minutes=10))
        removed = query_cve(db, cve_id, observed_cutoff=t4 + timedelta(minutes=10))
        unknown_prior = query_cve(db, cve_id, observed_cutoff=t1 - timedelta(days=1))

    assert older["kev"]["status"] == "listed"
    assert older["kev"]["catalog_as_of"] == t1
    assert older["references"][0]["state"] == "current"
    assert missing["kev"]["status"] == "not_listed"
    assert missing["kev"]["catalog_as_of"] == t2
    assert relisted["kev"]["status"] == "listed"
    assert relisted["kev"]["catalog_as_of"] == t3
    assert removed["kev"]["status"] == "not_listed"
    assert removed["kev"]["catalog_as_of"] == t4
    assert unknown_prior["kev"]["status"] == "unknown"
    assert unknown_prior["kev"]["catalog_as_of"] is None
