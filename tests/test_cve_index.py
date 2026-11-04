"""CVE links are exact and provenance-graded; only CISA KEV asserts exploitation."""
from types import SimpleNamespace

import pytest

from nous.cve_index import cve_relations, valid_cve_id, version_cve_relations


def test_cve_identity_is_strict():
    for value in ("CVE-2026-1234", "CVE-2026-12345678"):
        assert valid_cve_id(value)
    for value in ("cve-2026-1234", "CVE-26-1234", "CVE-2026-12",
                  "CVE-2026-1234-url", "CVE-2026-1" + "9" * 100):
        assert not valid_cve_id(value)


def test_cisa_kev_is_authoritative_only_for_structurally_confirmed_cve():
    source = SimpleNamespace(adapter="cisa_kev_v1", kind="json_api")
    raw = {
        "id": "CVE-2026-1234",
        "title": "Some CVE-2026-1234 issue",
        "vulnerability": {"cve_id": "CVE-2026-1234", "known_exploited": True},
    }
    assert cve_relations(source, raw) == {"CVE-2026-1234": "kev"}
    with pytest.raises(ValueError, match="inconsistent"):
        cve_relations(source, {**raw, "vulnerability": {
            "cve_id": "CVE-2026-9999", "known_exploited": True}})
    with pytest.raises(ValueError, match="inconsistent"):
        cve_relations(source, {**raw, "vulnerability": {
            "cve_id": "CVE-2026-1234", "known_exploited": False}})


def test_vendor_title_mentions_cannot_claim_kev_or_false_substrings():
    source = SimpleNamespace(adapter="rss_v1", kind="rss")
    raw = {
        "id": "https://vendor.example/advisory/1",
        "title": "Fix CVE-2026-12345 and CVE-2025-9876 (not XCVE-2026-9999)",
        "url": "https://vendor.example/advisory/1",
        "description": "Do not include CVE-2024-5555 from the article body",
    }
    assert cve_relations(source, raw) == {
        "CVE-2026-12345": "title_mention",
        "CVE-2025-9876": "title_mention",
    }


def test_explicit_reference_or_native_record_outweighs_title_mentions():
    source = SimpleNamespace(adapter="json_v1", kind="json_api")
    raw = {"id": "CVE-2026-12345", "title": "CVE-2026-12345 and CVE-2024-5555",
           "cve_ids": ["CVE-2024-5555"], "vulnerability": {
               "cve_id": "CVE-2026-12345",
           }}
    assert cve_relations(source, raw) == {
        "CVE-2026-12345": "record",
        "CVE-2024-5555": "reference",
    }
    with pytest.raises(ValueError, match="invalid CVE reference"):
        cve_relations(source, {**raw, "cve_ids": ["arbitrary"]})


def test_too_many_title_ids_fail_without_partial_links():
    source = SimpleNamespace(adapter="rss_v1", kind="rss")
    raw = {"title": " ".join(f"CVE-2026-{n:04d}" for n in range(1000, 1034))}
    with pytest.raises(ValueError, match="too many"):
        cve_relations(source, raw)


def test_legacy_version_relations_use_immutable_fields_and_recorded_adapter():
    title_id = "CVE-2026-12345"
    title_relations = version_cve_relations(
        attributes={"title": f"Advisory references {title_id}"},
        provenance={"adapter": "rss_v1"}, external_id="advisory-1",
        source_adapter="rss_v1", source_kind="rss",
    )
    assert title_relations == {title_id: "title_mention"}

    record_id = "CVE-2026-67890"
    record_relations = version_cve_relations(
        attributes={"title": "Vendor vulnerability", "vulnerability": {"cve_id": record_id}},
        provenance={"adapter": "json_v1"}, external_id=record_id,
        source_adapter="json_v1", source_kind="json_api",
    )
    assert record_relations == {record_id: "record"}

    kev_relations = version_cve_relations(
        attributes={"title": "CISA record", "vulnerability": {
            "cve_id": record_id, "known_exploited": True,
        }},
        provenance={"adapter": "cisa_kev_v1"}, external_id=record_id,
        source_adapter="cisa_kev_v1", source_kind="json_api",
    )
    assert kev_relations == {record_id: "kev"}
    assert version_cve_relations(
        attributes={"title": f"Advisory references {title_id}"},
        provenance={"adapter": "json_v1"}, external_id="advisory-1",
        source_adapter="rss_v1", source_kind="rss",
    ) == {}
