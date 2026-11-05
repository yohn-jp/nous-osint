"""Read-model for source-attributed CVE/KEV correlations.

Only the CISA-operated KEV catalog can assert confirmed exploitation; records
and title mentions from other sources remain distinct references. Absence in
an uncollected or stale KEV feed is never presented as a negative finding.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, select
from .cve_index import valid_cve_id, version_cve_relations
from .models import (CveItemVersionLink, Item, ItemVersion,
                     KevCatalogContent, KevCatalogObservation, Source)

_RELATIONS = {"kev", "record", "reference", "title_mention"}


def _version_at(db, item_id: int, cutoff: datetime):
    return db.scalar(select(ItemVersion).where(
        ItemVersion.item_id == item_id, ItemVersion.observed_at <= cutoff
    ).order_by(ItemVersion.observed_at.desc(), ItemVersion.id.desc()).limit(1))


def _relation_at(version: ItemVersion, item: Item, source: Source, cve_id: str):
    attrs = version.attributes if isinstance(version.attributes, dict) else {}
    relations = version_cve_relations(
        attributes=attrs, provenance=version.provenance,
        external_id=item.external_id, source_key=source.source_key,
        source_origin=source.origin,
    )
    relation = relations.get(cve_id)
    return relation if relation in _RELATIONS else None


def query_cve(db, cve_id: str, *, observed_cutoff: datetime | None = None):
    if not valid_cve_id(cve_id):
        raise ValueError("invalid CVE identifier")
    cutoff = observed_cutoff or datetime.now(timezone.utc)
    if cutoff.tzinfo is None:
        raise ValueError("CVE observation cutoff must be timezone-aware")
    cutoff = cutoff.astimezone(timezone.utc)

    cisa = db.scalar(select(Source).where(
        Source.source_key == "cisa-kev", Source.origin == "official"
    ))
    # The observation journal was introduced in 0010. A cutoff after its
    # first complete catalog is resolved against exactly the membership
    # observed at that time, including later removals and re-additions.
    observation = (db.scalar(select(KevCatalogObservation).where(
        KevCatalogObservation.source_id == cisa.id,
        KevCatalogObservation.observed_at <= cutoff,
    ).order_by(
        KevCatalogObservation.observed_at.desc(),
        KevCatalogObservation.id.desc(),
    ).limit(1)) if cisa is not None else None)
    if observation is not None:
        members = db.get(KevCatalogContent, observation.digest)
        # This is protected by the FK; fail closed for an inconsistent database.
        member_ids = set(members.cve_ids) if members is not None else set()
        catalog_as_of = observation.observed_at if members is not None else None
        membership_known = members is not None
        listed_in_catalog = cve_id in member_ids
    else:
        # Legacy databases have no historical membership journal. Their
        # current complete catalog remains readable, but a cutoff before the
        # latest successful fetch must not be inferred from old item versions.
        catalog_as_of = (cisa.last_success_at if cisa is not None and
                         cisa.last_success_at is not None and
                         cisa.last_success_at <= cutoff else None)
        membership_known = catalog_as_of is not None
        listed_in_catalog = None
    if catalog_as_of is not None and catalog_as_of.tzinfo is None:
        # SQLite fixtures store timezone-aware datetimes as naive UTC.
        catalog_as_of = catalog_as_of.replace(tzinfo=timezone.utc)
    fresh = (catalog_as_of is not None and
             catalog_as_of >= cutoff - timedelta(hours=48))

    def listed_at_cutoff(item: Item, source: Source) -> bool:
        if cisa is None or source.id != cisa.id or not membership_known:
            return False
        if listed_in_catalog is not None:
            return listed_in_catalog
        # Only the effective current catalog is safe to read without 0010
        # snapshots. No historical positive is invented for legacy intervals.
        return item.state == "current"

    candidate_item_ids = select(ItemVersion.item_id).join(
        CveItemVersionLink,
        CveItemVersionLink.item_version_id == ItemVersion.id,
    ).where(CveItemVersionLink.cve_id == cve_id).distinct()
    latest_versions = select(
        ItemVersion.id.label("item_version_id"),
        ItemVersion.item_id.label("item_id"),
        func.row_number().over(
            partition_by=ItemVersion.item_id,
            order_by=(ItemVersion.observed_at.desc(), ItemVersion.id.desc()),
        ).label("version_rank"),
    ).where(
        ItemVersion.observed_at <= cutoff,
        ItemVersion.item_id.in_(candidate_item_ids),
    ).subquery()
    priority = case(
        (CveItemVersionLink.relation == "kev", 0),
        (CveItemVersionLink.relation == "record", 1),
        (CveItemVersionLink.relation == "reference", 2),
        else_=3,
    )
    rows = db.execute(
        select(CveItemVersionLink, Item, Source, ItemVersion)
        .join(latest_versions,
              latest_versions.c.item_version_id == CveItemVersionLink.item_version_id)
        .join(ItemVersion, ItemVersion.id == latest_versions.c.item_version_id)
        .join(Item, ItemVersion.item_id == Item.id)
        .join(Source, Item.source_id == Source.id)
        .where(latest_versions.c.version_rank == 1,
               CveItemVersionLink.cve_id == cve_id,
               Item.first_seen_at <= cutoff)
        .order_by(priority, Item.id)
        .limit(51)
    ).all()

    associated = []
    kev = None
    seen_items = set()
    for link, item, source, version in rows:
        relation = _relation_at(version, item, source, cve_id)
        if relation is None or relation != link.relation:
            continue
        if relation == "kev" and not listed_at_cutoff(item, source):
            continue
        attrs = version.attributes if isinstance(version.attributes, dict) else {}
        details = attrs.get("vulnerability") if isinstance(attrs.get("vulnerability"), dict) else {}
        if relation == "kev" and source.source_key == "cisa-kev":
            if kev is None:
                kev = {
                    "status": "listed", "catalog_as_of": catalog_as_of,
                    "catalog_fresh": fresh, "item_id": item.id,
                    "date_added": details.get("date_added"),
                    "due_date": details.get("due_date"),
                    "vendor": details.get("vendor"), "product": details.get("product"),
                    "known_ransomware_campaign_use": details.get("ransomware_campaign_use"),
                    "source_url": source.url,
                }
        if len(associated) < 50:
            associated.append({
                "item_id": item.id, "source": source.source_key,
                "relation": relation, "kind": item.kind,
                "state": ("current" if relation == "kev" else item.state),
                "title": attrs.get("title", item.title),
                "url": attrs.get("url", item.canonical_url),
                "last_seen_at": version.observed_at, "source_url": source.url,
                "source_adapter": source.adapter,
            })
            seen_items.add(item.id)

    # The authoritative CISA row is also looked up by its normalized exact ID,
    # so a link retired after the cutoff cannot erase a historical listing.
    if cisa is not None and membership_known:
        kev_item = db.scalar(select(Item).where(
            Item.source_id == cisa.id, Item.external_id == cve_id,
            Item.first_seen_at <= cutoff))
        if kev_item is not None and listed_at_cutoff(kev_item, cisa):
            kev_version = _version_at(db, kev_item.id, cutoff)
            relation = (_relation_at(kev_version, kev_item, cisa, cve_id)
                        if kev_version else None)
            if relation == "kev":
                attrs = kev_version.attributes if isinstance(kev_version.attributes, dict) else {}
                details = attrs.get("vulnerability") if isinstance(attrs.get("vulnerability"), dict) else {}
                kev = {
                    "status": "listed", "catalog_as_of": catalog_as_of,
                    "catalog_fresh": fresh, "item_id": kev_item.id,
                    "date_added": details.get("date_added"),
                    "due_date": details.get("due_date"),
                    "vendor": details.get("vendor"), "product": details.get("product"),
                    "known_ransomware_campaign_use": details.get("ransomware_campaign_use"),
                    "source_url": cisa.url,
                }
                if kev_item.id not in seen_items and len(associated) < 50:
                    associated.insert(0, {
                        "item_id": kev_item.id, "source": cisa.source_key,
                        "relation": "kev", "kind": kev_item.kind,
                        "state": "current", "title": attrs.get("title", kev_item.title),
                        "url": attrs.get("url", kev_item.canonical_url),
                        "last_seen_at": kev_version.observed_at,
                        "source_url": cisa.url, "source_adapter": cisa.adapter,
                    })
    if kev is None:
        kev = {
            "status": "not_listed" if fresh and membership_known else "unknown",
            "catalog_as_of": catalog_as_of,
            "catalog_fresh": fresh,
            "item_id": None,
            "date_added": None,
            "due_date": None,
            "vendor": None,
            "product": None,
            "known_ransomware_campaign_use": None,
            "source_url": cisa.url if catalog_as_of is not None else None,
        }
    return {
        "cve_id": cve_id,
        "canonical_url": f"https://www.cve.org/CVERecord?id={cve_id}",
        "kev": kev,
        "references": associated,
        "references_truncated": len(rows) > 50,
    }
