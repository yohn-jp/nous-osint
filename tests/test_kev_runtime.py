"""CISA KEV complete-snapshot semantics against Nous's existing PostgreSQL schema."""
import json
import os
import uuid

import pytest
from sqlalchemy import select

from nous import runtime
from nous.db import session_factory
from nous.models import FetchJob, Item, ItemVersion, Source

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="PostgreSQL required")


def setup_source():
    factory = session_factory()
    key = "kev-" + uuid.uuid4().hex[:12]
    with factory() as db:
        source = Source(
            source_key=key, kind="json_api", adapter="cisa_kev_v1",
            item_kind="vulnerability",
            url="https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
            config_revision="test", config={"max_concurrency": 1, "max_pages": 1},
            enabled=True, interval_minutes=360, max_requests_per_hour=2,
        )
        db.add(source)
        db.flush()
        job = FetchJob(source_id=source.id, dedupe_key=key, state="leased", attempts=1)
        db.add(job)
        db.commit()
        return factory, source.id, job.id


def record(cve):
    return {
        "cveID": cve,
        "vendorProject": "Vendor",
        "product": "Product",
        "vulnerabilityName": "Vendor Product Known Exploited Vulnerability",
        "dateAdded": "2026-11-04",
        "dueDate": "2026-11-07",
        "knownRansomwareCampaignUse": "Known",
        "requiredAction": "Do not copy the full publisher prose",
    }


def payload(entries, *, reported=None):
    return json.dumps({
        "catalogVersion": "2026.11.04",
        "count": len(entries) if reported is None else reported,
        "vulnerabilities": entries,
    }).encode()


def test_kev_ingestion_versions_with_cve_provenance(monkeypatch):
    factory, source_id, job_id = setup_source()
    data = payload([record("CVE-2026-45678")])
    monkeypatch.setattr(runtime, "fetch", lambda *args: (200, data, {}, args[0]))
    runtime.process(factory, job_id)

    with factory() as db:
        item = db.scalar(select(Item).where(Item.source_id == source_id))
        assert item.external_id == "CVE-2026-45678"
        assert item.kind == "vulnerability"
        assert item.published_at is not None
        version = db.scalar(select(ItemVersion).where(ItemVersion.item_id == item.id))
        assert version.attributes["vulnerability"]["cve_id"] == "CVE-2026-45678"
        assert version.attributes["vulnerability"]["known_exploited"] is True
        assert "requiredAction" not in str(version.attributes)
        assert version.provenance["source_url"].startswith("https://raw.githubusercontent.com/")


def test_malformed_kev_catalog_cannot_replace_existing_cve_records(monkeypatch):
    factory, source_id, job_id = setup_source()
    with factory() as db:
        source = db.get(Source, source_id)
        runtime.store_item(db, source, {
            "id": "CVE-2025-9999", "title": "Previously known exploited vulnerability",
            "url": "https://www.cve.org/CVERecord?id=CVE-2025-9999",
        }, source.url)
        db.commit()
    bad = payload([record("CVE-2026-45678")], reported=2)
    monkeypatch.setattr(runtime, "fetch", lambda *args: (200, bad, {}, args[0]))
    runtime.process(factory, job_id)
    with factory() as db:
        old = db.scalar(select(Item).where(Item.source_id == source_id))
        assert old.external_id == "CVE-2025-9999"
        assert old.state == "current"
        assert db.get(FetchJob, job_id).state == "failed"
