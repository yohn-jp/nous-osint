"""Deterministic CVE identity links. Source observations remain authoritative.

A KEV assertion is only produced by CISA's native, fully validated KEV
adapter; mentions and other vulnerability records are not exploitation claims.
"""
from __future__ import annotations

import re
from types import SimpleNamespace
from sqlalchemy import delete, select
from .models import CveItemLink, CveItemVersionLink
from .registry import ADAPTERS

CVE_ID_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,}$"
_CVE_ID = re.compile(CVE_ID_PATTERN)
_TITLE_IDS = re.compile(r"(?<![A-Za-z0-9-])CVE-[0-9]{4}-[0-9]{4,}(?![A-Za-z0-9-])")
_MAX_IDS_PER_ITEM = 32
_MAX_ID_LENGTH = 64


def valid_cve_id(value: str) -> bool:
    return isinstance(value, str) and len(value) <= _MAX_ID_LENGTH and bool(_CVE_ID.fullmatch(value))


def authoritative_kev_version(*, source_key: str, source_origin: str, external_id: str,
                              attributes, provenance, cve_id: str) -> bool:
    """Trust KEV only from the official CISA source and its recorded parser."""
    attrs = attributes if isinstance(attributes, dict) else {}
    recorded = provenance if isinstance(provenance, dict) else {}
    vulnerability = attrs.get("vulnerability")
    return (
        source_key == "cisa-kev" and source_origin == "official" and
        recorded.get("adapter") == "cisa_kev_v1" and
        valid_cve_id(cve_id) and external_id == cve_id and
        isinstance(vulnerability, dict) and
        vulnerability.get("cve_id") == cve_id and
        vulnerability.get("known_exploited") is True
    )


def cve_relations(source, raw: dict) -> dict[str, str]:
    """Map source fields to CVE IDs with evidence grades; no fuzzy matching."""
    relations = {}
    identifier = raw.get("id")
    structured = raw.get("vulnerability")
    if source.adapter == "cisa_kev_v1":
        if (not isinstance(structured, dict) or
                not valid_cve_id(identifier) or
                structured.get("cve_id") != identifier or
                structured.get("known_exploited") is not True):
            raise ValueError("CISA KEV record has inconsistent CVE identity")
        return {identifier: "kev"}

    if isinstance(identifier, str) and valid_cve_id(identifier) and source.kind == "json_api":
        relations[identifier] = "record"

    if isinstance(structured, dict) and structured.get("cve_id") is not None:
        cve = structured["cve_id"]
        if not valid_cve_id(cve):
            raise ValueError("invalid structured CVE identifier")
        relations[cve] = "record"

    explicit = raw.get("cve_ids", [])
    if not isinstance(explicit, list):
        raise ValueError("CVE references must be an array")
    for cve in explicit:
        if not valid_cve_id(cve):
            raise ValueError("invalid CVE reference")
        relations.setdefault(cve, "reference")

    title = raw.get("title", "")
    if not isinstance(title, str):
        raise ValueError("item title must be text")
    for match in _TITLE_IDS.findall(title):
        if valid_cve_id(match):
            relations.setdefault(match, "title_mention")
    if len(relations) > _MAX_IDS_PER_ITEM:
        raise ValueError("too many CVE references in one item")
    return relations


def version_cve_relations(*, attributes, provenance, external_id: str,
                          source_key: str | None = None,
                          source_origin: str | None = None) -> dict[str, str]:
    """Read a frozen relation map or derive only from this version's snapshot.

    Legacy item versions predate ``cve_relations``. Their version-local title,
    structured vulnerability fields, immutable external ID, and recorded
    adapter can still support the canonical relation rules. Current link rows
    are deliberately not consulted because they cannot reconstruct as-of state.
    """
    attrs = attributes if isinstance(attributes, dict) else {}
    frozen = attrs.get("cve_relations")
    if isinstance(frozen, dict):
        relations = {}
        for cve_id, relation in frozen.items():
            if (not valid_cve_id(cve_id) or not isinstance(relation, str) or
                    relation not in {"kev", "record", "reference", "title_mention"}):
                continue
            if relation == "kev" and not authoritative_kev_version(
                    source_key=source_key or "", source_origin=source_origin or "",
                    external_id=external_id, attributes=attrs, provenance=provenance,
                    cve_id=cve_id):
                continue
            relations[cve_id] = relation
        return relations
    recorded_adapter = provenance.get("adapter") if isinstance(provenance, dict) else None
    if (not isinstance(recorded_adapter, str) or not recorded_adapter or
            not isinstance(external_id, str)):
        return {}
    # Source.kind can change when a custom feed is reconfigured. The adapter
    # recorded with this immutable observation determines its original kind.
    historical_kinds = [kind for kind, adapters in ADAPTERS.items()
                        if recorded_adapter in adapters]
    if len(historical_kinds) != 1:
        return {}
    raw = dict(attrs)
    raw["id"] = external_id
    raw.setdefault("title", "")
    try:
        relations = cve_relations(
            SimpleNamespace(adapter=recorded_adapter, kind=historical_kinds[0]), raw,
        )
    except (TypeError, ValueError):
        return {}
    relations = {
        cve_id: relation for cve_id, relation in relations.items()
        if relation != "kev" or authoritative_kev_version(
            source_key=source_key or "", source_origin=source_origin or "",
            external_id=external_id, attributes=attrs, provenance=provenance,
            cve_id=cve_id)
    }
    return relations


def sync_item_cves(db, item, source, raw: dict):
    """Replace only this item's current links in its normal observation TX."""
    target = cve_relations(source, raw)
    current = {
        row.cve_id: row
        for row in db.scalars(select(CveItemLink).where(CveItemLink.item_id == item.id))
    }
    obsolete = set(current) - set(target)
    if obsolete:
        db.execute(delete(CveItemLink).where(
            CveItemLink.item_id == item.id, CveItemLink.cve_id.in_(obsolete)
        ))
    for cve, relation in target.items():
        previous = current.get(cve)
        if previous is not None:
            previous.relation = relation
        else:
            db.add(CveItemLink(item_id=item.id, cve_id=cve, relation=relation))


def record_item_version_cves(db, item_version_id: int, relations: dict[str, str]):
    """Store exact relation grades alongside their immutable observation."""
    if not isinstance(relations, dict):
        raise ValueError("version CVE relations must be an object")
    rows = []
    for cve_id, relation in relations.items():
        if (not valid_cve_id(cve_id) or not isinstance(relation, str) or
                relation not in {"kev", "record", "reference", "title_mention"}):
            raise ValueError("invalid version CVE relation")
        rows.append(CveItemVersionLink(
            item_version_id=item_version_id, cve_id=cve_id, relation=relation,
        ))
    db.add_all(rows)
