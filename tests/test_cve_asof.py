"""Historical CVE references remain queryable after current links retire."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

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
