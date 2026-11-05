"""DB-backed CVE↔KEV cross-source mapping and absence semantics."""
import os
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from nous import api, runtime
from nous.cve_index import sync_item_cves
from nous.cve_queries import query_cve
from nous.db import session_factory
from nous.models import CveItemLink, Item, ItemVersion, Source, now

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="PostgreSQL required")

CVE = "CVE-2026-67890"


def setup_sources():
    factory = session_factory()
    marker = uuid.uuid4().hex[:10]
    with factory() as db:
        kev = db.scalar(select(Source).where(Source.source_key == "cisa-kev"))
        if kev is None:
            kev = Source(
                source_key="cisa-kev", adapter="cisa_kev_v1",
                item_kind="vulnerability", kind="json_api",
                url="https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
                config_revision="test", config={"max_concurrency": 1},
                enabled=True, interval_minutes=360, max_requests_per_hour=4,
                last_success_at=now(),
            )
            db.add(kev)
        else:
            kev.last_success_at = now()
        vendor = Source(
            source_key="advisory-fixture-" + marker, adapter="rss_v1",
            item_kind="advisory", kind="rss",
            url="https://vendor.example/security/rss",
            config_revision="test", config={"max_concurrency": 1},
            enabled=True, interval_minutes=360, max_requests_per_hour=4,
        )
        db.add(vendor)
        db.flush()
        return_ids = (kev.id, vendor.id)
        db.commit()
    return factory, *return_ids


def kev_raw(cve_id=CVE):
    return {
        "id": cve_id, "title": "Example Product Vulnerability",
        "url": f"https://www.cve.org/CVERecord?id={cve_id}",
        "published": "2026-11-03T00:00:00Z",
        "vulnerability": {
            "cve_id": cve_id, "vendor": "Example Inc", "product": "Platform",
            "known_exploited": True, "date_added": "2026-11-03",
            "due_date": "2026-11-12", "ransomware_campaign_use": "Unknown",
            "catalog_version": "2026.11.04",
        },
    }


def test_cve_kev_query_preserves_two_independent_sources_and_provenance():
    factory, kev_id, vendor_id = setup_sources()
    test_cve = f"CVE-2026-{int(uuid.uuid4().hex[:8], 16)}"
    updated_cve = f"CVE-2026-{int(uuid.uuid4().hex[:8], 16)}"
    with factory() as db:
        kev = db.get(Source, kev_id)
        vendor = db.get(Source, vendor_id)
        runtime.store_item(db, kev, kev_raw(test_cve), kev.url)
        runtime.store_item(db, vendor, {
            "id": "vendor-issue", "title": f"Security fixes for {test_cve}",
            "url": "https://vendor.example/security/advisory-1",
        }, vendor.url)
        db.commit()
    with TestClient(api.app) as client:
        response = client.get("/v1/cves/" + test_cve)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["cve_id"] == test_cve
    assert payload["kev"]["status"] == "listed"
    assert payload["kev"]["catalog_fresh"] is True
    assert payload["kev"]["vendor"] == "Example Inc"
    assert payload["kev"]["date_added"] == "2026-11-03"
    assert payload["kev"]["source_url"].startswith("https://raw.githubusercontent.com/")
    assert {ref["relation"] for ref in payload["references"]} == {"kev", "title_mention"}
    assert len({ref["source"] for ref in payload["references"]}) == 2

    with factory() as db:
        vendor = db.get(Source, vendor_id)
        runtime.store_item(db, vendor, {
            "id": "vendor-issue",
            "title": f"Security fixes for {updated_cve}",
            "url": "https://vendor.example/security/advisory-1",
        }, vendor.url)
        db.commit()
    with factory() as db:
        vendor_item = db.scalar(select(Item).where(
            Item.source_id == vendor_id, Item.external_id == "vendor-issue"))
        assert vendor_item.current_version == 2
        assert len(db.scalars(select(ItemVersion).where(
            ItemVersion.item_id == vendor_item.id)).all()) == 2
        refs = db.scalars(select(CveItemLink).where(
            CveItemLink.item_id == vendor_item.id)).all()
        assert [(r.cve_id, r.relation) for r in refs] == [(updated_cve, "title_mention")]
    old = api.cve(test_cve)
    new = api.cve(updated_cve)
    assert len(old["references"]) == 1
    assert len(new["references"]) == 1
    assert new["kev"]["status"] == "not_listed"
    assert new["references"][0]["relation"] == "title_mention"


def test_cve_query_uses_immutable_version_at_cutoff_after_current_state_changes():
    factory, _, vendor_id = setup_sources()
    cutoff_cve = f"CVE-2026-{int(uuid.uuid4().hex[:8], 16)}"
    old_title = f"Security fixes for {cutoff_cve}"
    url = "https://vendor.example/security/cutoff-fixture"
    with factory() as db:
        vendor = db.get(Source, vendor_id)
        vendor_key = vendor.source_key
        runtime.store_item(db, vendor, {
            "id": "cutoff-fixture", "title": old_title, "url": url,
        }, vendor.url)
        db.commit()
        item = db.scalar(select(Item).where(Item.source_id == vendor_id,
                                            Item.external_id == "cutoff-fixture"))
        old_version = db.scalar(select(ItemVersion).where(ItemVersion.item_id == item.id))
        old_observed_at = old_version.observed_at
        cutoff = old_observed_at + timedelta(seconds=1)
        current_title = "Revised title after the selected cutoff"
        current_attributes = {**old_version.attributes, "title": current_title,
                              "cve_relations": {}}
        current_version = ItemVersion(
            item_id=item.id, version=2, observed_at=cutoff + timedelta(days=1),
            sha256="c" * 64, attributes=current_attributes,
            provenance=old_version.provenance,
        )
        item.current_version = 2
        item.state = "closed"
        item.title = current_title
        item.current_hash = "c" * 64
        item.last_seen_at = cutoff + timedelta(days=1)
        db.add(current_version)
        sync_item_cves(db, item, vendor, {
            "id": "cutoff-fixture", "title": current_title, "url": url,
        })
        db.commit()
        assert db.scalar(select(CveItemLink).where(
            CveItemLink.item_id == item.id, CveItemLink.cve_id == cutoff_cve)) is None

    with factory() as db:
        result = query_cve(db, cutoff_cve, observed_cutoff=cutoff)
    historical = next(ref for ref in result["references"]
                      if ref["source"] == vendor_key)
    assert historical["title"] == old_title
    assert historical["last_seen_at"] == old_observed_at
    with factory() as db:
        current = query_cve(db, cutoff_cve,
                            observed_cutoff=cutoff + timedelta(days=2))
    assert all(ref["source"] != vendor_key for ref in current["references"])


def test_kev_unknown_vs_not_listed_requires_recent_complete_source_snapshot():
    factory, kev_id, _ = setup_sources()
    unknown_cve = "CVE-2026-99999"
    with factory() as db:
        kev = db.get(Source, kev_id)
        kev.last_success_at = None
        db.commit()
    result = api.cve(unknown_cve)
    assert result["kev"]["status"] == "unknown"
    assert result["kev"]["catalog_as_of"] is None

    with factory() as db:
        kev = db.get(Source, kev_id)
        kev.last_success_at = now()
        db.commit()
    assert api.cve(unknown_cve)["kev"]["status"] == "not_listed"

    with factory() as db:
        kev = db.get(Source, kev_id)
        kev.last_success_at = now() - timedelta(hours=72)
        db.commit()
    result = api.cve(unknown_cve)
    assert result["kev"]["status"] == "unknown"
    assert result["kev"]["catalog_fresh"] is False


def test_non_cisa_source_cannot_assert_kev_via_title():
    unrelated_cve = "CVE-2026-67892"
    factory, _, vendor_id = setup_sources()
    with factory() as db:
        vendor = db.get(Source, vendor_id)
        runtime.store_item(db, vendor, {
            "id": unrelated_cve, "title": f"Known exploit discussed: {unrelated_cve}",
            "url": "https://vendor.example/security/advisory-2",
        }, vendor.url)
        db.commit()
    response = api.cve(unrelated_cve)
    assert response["kev"]["status"] == "not_listed"
    assert all(ref["relation"] != "kev" for ref in response["references"])


def test_removed_kev_item_does_not_remain_listed_after_fresh_complete_catalog():
    """Immutable historical KEV evidence is not proof of current membership."""
    factory, kev_id, _ = setup_sources()
    cve_id = f"CVE-2026-{int(uuid.uuid4().hex[:8], 16)}"
    with factory() as db:
        source = db.get(Source, kev_id)
        runtime.store_item(db, source, kev_raw(cve_id), source.url)
        db.commit()
    assert api.cve(cve_id)["kev"]["status"] == "listed"

    with factory() as db:
        source = db.get(Source, kev_id)
        item = db.scalar(select(Item).where(
            Item.source_id == kev_id, Item.external_id == cve_id))
        assert item is not None
        # A subsequent successfully validated complete CISA snapshot omitted
        # this CVE; runtime.process marks the item unknown, preserving versions.
        item.state = "unknown"
        source.last_success_at = now()
        db.commit()

    current = api.cve(cve_id)
    assert current["kev"]["status"] == "not_listed"
    assert all(ref["relation"] != "kev" for ref in current["references"])

    with factory() as db:
        source = db.get(Source, kev_id)
        source.last_success_at = now() - timedelta(hours=72)
        db.commit()
    assert api.cve(cve_id)["kev"]["status"] == "unknown"
