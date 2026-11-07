
import pytest

from nous.report_editorial import (
    assemble_article,
    validate_article_v2,
    validate_claims,
    validate_review,
)
from nous.report_pipeline import ReportError, ReportSkipped
from nous.report_templates import template_snapshot


def bundle(template_id="security-daily"):
    result = {
        "template_id": template_id,
        "template_snapshot": template_snapshot(template_id),
        "parameters": {"target_date": "2026-11-03"},
        "evidence": [{
            "evidence_id": "E001", "source_key": "fixture-advisory", "relation": "record",
            "publisher_url": "https://publisher.example/advisory",
            "observed_at": "2026-11-03T01:00:00+00:00", "published_at": None,
            "title": "Official advisory metadata title",
            "content_policy": {"storage": "metadata_only", "license_id": "NOASSERTION"},
        }],
    }
    if template_id == "cve-kev-deep-dive":
        result["parameters"] = {"cve_id": "CVE-2026-12345"}
        result["evidence"][0]["relation"] = "reference"
        result["cve_context"] = {
            "cve_id": "CVE-2026-12345", "kev_status": "unknown", "catalog_as_of": None,
            "catalog_fresh": False,
            "canonical_url": "https://www.cve.org/CVERecord?id=CVE-2026-12345",
            "catalog_source_url": None,
        }
    return result


def proposal():
    return {
        "decision": "publish", "theme": "observed advisory update", "claims": [{
            "claim_id": "C001", "text": "公表元が更新情報を掲載したことを観測しました。",
            "classification": "observed", "evidence_ids": ["E001"],
            "section": "primary_observations", "importance": "normal",
        }],
    }


def review():
    return {"reviews": [{
        "claim_id": "C001", "decision": "accepted", "evidence_ids": ["E001"],
        "reason_code": "supported",
    }]}


def test_claims_assemble_deterministically_with_snapshot_sources():
    input_bundle = bundle()
    candidate = proposal()
    independent_review = review()
    article = assemble_article(candidate, independent_review, bundle=input_bundle,
                               template_id="security-daily")
    assert article["schema_version"] == 2
    assert article["title"] == "セキュリティ情報 2026-11-03"
    assert article["claims"][0]["text"] == candidate["claims"][0]["text"]
    assert article["sources"][0]["license_id"] == "NOASSERTION"
    assert validate_article_v2(article, bundle=input_bundle,
                               template_id="security-daily") == article


def test_claim_and_review_cannot_add_evidence_or_omit_candidates():
    input_bundle = bundle()
    candidate = proposal()
    validate_claims(candidate, input_bundle, "security-daily")
    bad_review = review()
    bad_review["reviews"][0]["evidence_ids"] = ["E999"]
    with pytest.raises(ReportError, match="claim_review_evidence_invalid"):
        validate_review(bad_review, candidate, input_bundle)
    with pytest.raises(ReportError, match="claim_review_incomplete"):
        validate_review({"reviews": []}, candidate, input_bundle)


def test_needs_revision_is_bounded_repair_signal_and_skip_stays_skipped():
    candidate = proposal()
    needs_revision = {"reviews": [{
        "claim_id": "C001", "decision": "needs_revision", "evidence_ids": ["E001"],
        "reason_code": "overclaim",
    }]}
    with pytest.raises(ReportError, match="claim_repair_required"):
        assemble_article(candidate, needs_revision, bundle=bundle(), template_id="security-daily")
    skipped = {"decision": "skip", "theme": "insufficient evidence", "claims": []}
    with pytest.raises(ReportSkipped, match="insufficient_evidence"):
        validate_claims(skipped, bundle(), "security-daily")


def test_article_rejects_fabricated_publication_metadata_and_cve_claims():
    input_bundle = bundle()
    article = assemble_article(proposal(), review(), bundle=input_bundle,
                               template_id="security-daily")
    article["sources"][0]["publisher_url"] = "https://attacker.example/fake"
    with pytest.raises(ReportError, match="article_sources_mismatch"):
        validate_article_v2(article, bundle=input_bundle, template_id="security-daily")
    cve_bundle = bundle("cve-kev-deep-dive")
    cve_proposal = proposal()
    cve_proposal["claims"][0]["text"] = "この脆弱性は悪用されています。"
    with pytest.raises(ReportError, match="unsupported_exploitation_claim"):
        validate_claims(cve_proposal, cve_bundle, "cve-kev-deep-dive")


def test_claims_reject_unsupported_numbers_and_mismatched_cve_identifiers():
    candidate = proposal()
    candidate["claims"][0]["text"] = "2028年に公表元が更新情報を掲載したと観測しました。"
    with pytest.raises(ReportError, match="unsupported_claim_number"):
        validate_claims(candidate, bundle(), "security-daily")

    cve_candidate = proposal()
    cve_candidate["claims"][0]["text"] = "CVE-2026-99999に関する記録を確認しました。"
    cve_candidate["claims"][0]["evidence_ids"] = ["E001"]
    with pytest.raises(ReportError, match="cve_claim_id_mismatch"):
        validate_claims(cve_candidate, bundle("cve-kev-deep-dive"), "cve-kev-deep-dive")


def test_exact_cve_claim_accepts_producer_keV_row_without_embedded_cve_id():
    cve_bundle = bundle("cve-kev-deep-dive")
    cve_bundle["cve_context"].update({"kev_status": "listed", "catalog_fresh": True})
    kev_row = cve_bundle["evidence"][0]
    kev_row.update({
        "relation": "kev", "source_key": "cisa-kev",
        "allowed_fields": ["title", "publisher_url", "observed_at", "published_at",
                            "vulnerability.date_added", "vulnerability.vendor"],
        "vulnerability": {"date_added": "2026-11-01", "vendor": "Example"},
        "content_policy": {"storage": "metadata_only", "license_id": "CC0-1.0",
                           "dataset_license": "CC0-1.0"},
    })
    candidate = proposal()
    candidate["claims"][0]["text"] = (
        "CVE-2026-12345についてCISAが悪用を確認した記録があります。"
    )
    assert validate_claims(candidate, cve_bundle, "cve-kev-deep-dive") == candidate
