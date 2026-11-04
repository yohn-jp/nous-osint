"""Read-model for source-attributed CVE/KEV correlations.

Only the CISA-operated KEV catalog can assert confirmed exploitation; records
and title mentions from other sources remain distinct references. Absence in
an uncollected or stale KEV feed is never presented as a negative finding.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import case, select
from .cve_index import valid_cve_id
from .models import CveItemLink, Item, ItemVersion, Source


def query_cve(db, cve_id: str):
    if not valid_cve_id(cve_id):
        raise ValueError("invalid CVE identifier")

    kev_sources = db.scalars(
        select(Source).where(Source.adapter == "cisa_kev_v1",
                             Source.last_success_at.is_not(None))
        .order_by(Source.last_success_at.desc()).limit(1)
    ).all()
    catalog_as_of = kev_sources[0].last_success_at if kev_sources else None
    fresh = (catalog_as_of is not None and
             catalog_as_of >= datetime.now(timezone.utc) - timedelta(hours=48))

    priority = case(
        (CveItemLink.relation == "kev", 0),
        (CveItemLink.relation == "record", 1),
        (CveItemLink.relation == "reference", 2),
        else_=3,
    )
    rows = db.execute(
        select(CveItemLink, Item, Source, ItemVersion)
        .join(Item, CveItemLink.item_id == Item.id)
        .join(Source, Item.source_id == Source.id)
        .outerjoin(ItemVersion, (ItemVersion.item_id == Item.id) &
                   (ItemVersion.version == Item.current_version))
        .where(CveItemLink.cve_id == cve_id)
        .order_by(priority, Item.last_seen_at.desc(), Item.id)
        .limit(51)
    ).all()

    associated = []
    kev = None
    for link, item, source, version in rows:
        if (link.relation == "kev" and source.adapter == "cisa_kev_v1" and
                item.state == "current"):
            # Preserve only approved bounded CISA fields, not raw descriptions
            # or content from linked publishers.
            details = (version.attributes.get("vulnerability", {})
                       if version and isinstance(version.attributes, dict) else {})
            if not isinstance(details, dict):
                details = {}
            if kev is None:
                kev = {
                    "status": "listed",
                    "catalog_as_of": catalog_as_of,
                    "catalog_fresh": fresh,
                    "item_id": item.id,
                    "date_added": details.get("date_added"),
                    "due_date": details.get("due_date"),
                    "vendor": details.get("vendor"),
                    "product": details.get("product"),
                    "known_ransomware_campaign_use":
                        details.get("ransomware_campaign_use"),
                    "source_url": source.url,
                }
        if len(associated) < 50:
            associated.append({
                "item_id": item.id,
                "source": source.source_key,
                "relation": link.relation,
                "kind": item.kind,
                "state": item.state,
                "title": item.title,
                "url": item.canonical_url,
                "last_seen_at": item.last_seen_at,
                "source_url": source.url,
                "source_adapter": source.adapter,
            })
    if kev is None:
        kev = {
            "status": "not_listed" if fresh else "unknown",
            "catalog_as_of": catalog_as_of,
            "catalog_fresh": fresh,
            "item_id": None,
            "date_added": None,
            "due_date": None,
            "vendor": None,
            "product": None,
            "known_ransomware_campaign_use": None,
            "source_url": kev_sources[0].url if kev_sources else None,
        }
    return {
        "cve_id": cve_id,
        "canonical_url": f"https://www.cve.org/CVERecord?id={cve_id}",
        "kev": kev,
        "references": associated,
        "references_truncated": len(rows) > 50,
    }
