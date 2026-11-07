"""Claim contracts and deterministic article-v2 assembly.

Codex supplies short, evidence-linked claims and an independent decision for
those claims. This module chooses every public heading, title, source citation,
summary, and CVE/KEV panel from the frozen evidence bundle.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import date
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

from .cve_index import valid_cve_id
from .report_templates import resolve_template

_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_DIR = Path(os.getenv("NOUS_REPORTS_DIR", str(_ROOT / "reports"))) / "schemas"
_UNSAFE_TEXT = re.compile(r"(?:<\/?[a-z!]|https?://|javascript:|data:|\bon\w+\s*=)", re.I)
_EXPLOIT_TEXT = re.compile(r"(?:悪用|エクスプロイト|exploit|ransomware|ランサムウェア)", re.I)
_KEV_TEXT = re.compile(r"\bKEV\b|既知の悪用脆弱性", re.I)
_CLAIM_ID = re.compile(r"^C[0-9]{3}$")
_EVIDENCE_ID = re.compile(r"^E[0-9]{3}$")
_CVE_ID = re.compile(r"(?<![A-Z0-9])CVE-[0-9]{4}-[0-9]{4,}(?![0-9])", re.I)
_NUMBER = re.compile(r"[0-9]+")
_HEADINGS = {
    "security-daily": {
        "primary_observations": "確認された事実",
        "analysis": "分析",
        "unknowns": "未確認事項",
    },
    "cve-kev-deep-dive": {
        "primary_observations": "CVEの確認情報",
        "analysis": "影響と未確認事項",
        "unknowns": "影響と未確認事項",
    },
}
_CLASS_SECTION = {"observed": "primary_observations", "inference": "analysis",
                  "unconfirmed": "unknowns"}
_REVIEW_REASON = {"accepted": {"supported"}, "rejected": {
    "unsupported_evidence", "contradiction", "overclaim", "unclear", "duplicate", "other",
}, "needs_revision": {"unsupported_evidence", "contradiction", "overclaim", "unclear", "other"}}


class EditorialError(ValueError):
    """Fallback contract error; public pipeline gates raise ReportError instead."""


def _raise(code: str, *, skipped: bool = False):
    # The orchestration imports this module lazily from report_pipeline, so a
    # function-local import safely preserves the worker's established handling.
    from .report_pipeline import ReportError, ReportSkipped
    if skipped:
        raise ReportSkipped(code)
    raise ReportError(code)


def _schema(name: str, value: object) -> None:
    try:
        schema = json.loads((_SCHEMA_DIR / name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value))
    except (OSError, ValueError) as exc:
        _raise("schema_unavailable")
        raise exc  # pragma: no cover
    if errors:
        _raise("schema_invalid")


def _safe_text(value: object) -> bool:
    return isinstance(value, str) and not _UNSAFE_TEXT.search(value) and len(value.splitlines()) <= 4


def _evidence_map(bundle: dict) -> dict[str, dict]:
    rows = bundle.get("evidence")
    if not isinstance(rows, list):
        _raise("invalid_evidence_bundle")
    result = {}
    for row in rows:
        if not isinstance(row, dict) or not _EVIDENCE_ID.fullmatch(str(row.get("evidence_id", ""))):
            _raise("invalid_evidence_bundle")
        if row["evidence_id"] in result:
            _raise("invalid_evidence_bundle")
        result[row["evidence_id"]] = row
    return result


def _numeric_tokens(value: object) -> set[str]:
    if isinstance(value, bool) or value is None:
        return set()
    if isinstance(value, (str, int, float)):
        return {str(int(token)) for token in _NUMBER.findall(str(value))}
    if isinstance(value, list):
        return set().union(*(_numeric_tokens(item) for item in value)) if value else set()
    if isinstance(value, dict):
        return set().union(*(_numeric_tokens(item) for item in value.values())) if value else set()
    return set()


def _validate_claim_rows(claims: list, evidence: dict[str, dict], *, template_id: str,
                         bundle: dict | None = None) -> None:
    seen = set()
    for claim in claims:
        claim_id = claim["claim_id"]
        if not _CLAIM_ID.fullmatch(claim_id) or claim_id in seen:
            _raise("claim_id_invalid")
        seen.add(claim_id)
        if not _safe_text(claim["text"]):
            _raise("unsafe_claim_text")
        if any(eid not in evidence for eid in claim["evidence_ids"]):
            _raise("invalid_evidence_reference")
        if template_id == "cve-kev-deep-dive" and _KEV_TEXT.search(claim["text"]):
            _raise("kev_text_must_use_deterministic_panel")
        cited_rows = [evidence[eid] for eid in claim["evidence_ids"]]
        cve_ids = {item.upper() for item in _CVE_ID.findall(claim["text"])}
        if cve_ids:
            bundle_value = bundle or {}
            expected_cve_id = (bundle_value.get("cve_context") or {}).get("cve_id")
            parameter_cve_id = (bundle_value.get("parameters") or {}).get("cve_id")
            if expected_cve_id != parameter_cve_id:
                _raise("invalid_cve_context")
            if expected_cve_id and cve_ids != {expected_cve_id.upper()}:
                _raise("cve_claim_id_mismatch")
            if not all(any(
                cve_id in {value.upper() for value in _CVE_ID.findall(str(row.get("title", "")))}
                or cve_id == str((row.get("vulnerability") or {}).get("cve_id", "")).upper()
                or (
                    template_id == "cve-kev-deep-dive"
                    and expected_cve_id
                    and row.get("relation") == "kev"
                    and row.get("source_key") == "cisa-kev"
                    and row.get("content_policy", {}).get("dataset_license") == "CC0-1.0"
                    and isinstance(row.get("vulnerability"), dict)
                )
                for row in cited_rows) for cve_id in cve_ids
            ):
                _raise("cve_claim_evidence_mismatch")
        # The exact CVE identifier is checked above against the run snapshot
        # and cited relation. Its year/sequence digits are part of the ID,
        # not independent numerical claims requiring duplicate metadata.
        claim_numbers = _numeric_tokens(_CVE_ID.sub("", claim["text"]))
        if claim_numbers:
            permitted_numbers: set[str] = set()
            for row in cited_rows:
                permitted_numbers.update(_numeric_tokens(row.get("title", "")))
                permitted_numbers.update(_numeric_tokens(row.get("observed_at")))
                permitted_numbers.update(_numeric_tokens(row.get("published_at")))
                allowed_fields = row.get("allowed_fields", [])
                for field in allowed_fields:
                    if field == "title":
                        continue
                    if field.startswith("vulnerability."):
                        permitted_numbers.update(_numeric_tokens(
                            (row.get("vulnerability") or {}).get(field.partition(".")[2])))
                    elif field in {"observed_at", "published_at"}:
                        permitted_numbers.update(_numeric_tokens(row.get(field)))
            if not claim_numbers <= permitted_numbers:
                _raise("unsupported_claim_number")


def validate_claims(proposal: object, bundle: dict, template_id: str) -> dict:
    """Validate candidate atomic claims and ensure each cites this snapshot."""
    if not isinstance(proposal, dict):
        _raise("claims_invalid")
    _schema("claims.schema.json", proposal)
    if bundle.get("template_id") != template_id:
        _raise("article_template_mismatch")
    evidence = _evidence_map(bundle)
    try:
        template = resolve_template(template_id, bundle.get("template_snapshot"))
    except (KeyError, TypeError, ValueError):
        _raise("invalid_template_snapshot")
    if len(evidence) < template["publish_policy"]["minimum_evidence"]:
        _raise("insufficient_evidence", skipped=True)
    claims = proposal["claims"]
    _validate_claim_rows(claims, evidence, template_id=template_id, bundle=bundle)
    if proposal["decision"] == "skip":
        if claims:
            _raise("skip_with_claims")
        _raise("insufficient_evidence", skipped=True)
    if not claims:
        _raise("no_claims_proposed", skipped=True)
    context = bundle.get("cve_context") or {}
    for claim in claims:
        if _EXPLOIT_TEXT.search(claim["text"]):
            if (template_id != "cve-kev-deep-dive" or context.get("kev_status") != "listed" or
                    context.get("catalog_fresh") is not True):
                _raise("unsupported_exploitation_claim")
            if not any(evidence[eid].get("relation") == "kev" and
                       evidence[eid].get("source_key") == "cisa-kev" and
                       evidence[eid].get("content_policy", {}).get("dataset_license") == "CC0-1.0"
                       for eid in claim["evidence_ids"]):
                _raise("exploitation_claim_missing_kev_evidence")
    return deepcopy(proposal)


def validate_review(review: object, proposal: dict, bundle: dict) -> dict:
    """Require one independent decision per candidate and forbid new evidence."""
    if not isinstance(review, dict):
        _raise("claim_review_invalid")
    _schema("claim-review.schema.json", review)
    evidence = _evidence_map(bundle)
    claims = {claim["claim_id"]: claim for claim in proposal.get("claims", [])}
    decisions = {}
    for row in review["reviews"]:
        claim_id = row["claim_id"]
        if claim_id not in claims or claim_id in decisions:
            _raise("claim_review_reference_invalid")
        original_ids = set(claims[claim_id]["evidence_ids"])
        reviewed_ids = set(row["evidence_ids"])
        if (not reviewed_ids or not reviewed_ids <= original_ids or
                any(evidence_id not in evidence for evidence_id in reviewed_ids)):
            _raise("claim_review_evidence_invalid")
        if row["reason_code"] not in _REVIEW_REASON[row["decision"]]:
            _raise("claim_review_reason_invalid")
        if row["decision"] == "accepted" and reviewed_ids != original_ids:
            _raise("claim_review_evidence_changed")
        decisions[claim_id] = row
    if set(decisions) != set(claims):
        _raise("claim_review_incomplete")
    return deepcopy(review)


def _safe_url(value: object) -> bool:
    if not isinstance(value, str) or len(value) > 2048:
        return False
    try:
        parts = urlsplit(value)
        return (parts.scheme == "https" and bool(parts.hostname) and not parts.username and
                not parts.password and parts.port in (None, 443) and
                not any(ord(char) < 32 for char in value))
    except ValueError:
        return False


def _sources(evidence: dict[str, dict], ids: set[str]) -> list[dict]:
    result = []
    for evidence_id in sorted(ids):
        row = evidence[evidence_id]
        policy = row.get("content_policy") or {}
        if not _safe_url(row.get("publisher_url")):
            _raise("invalid_publisher_url")
        if policy.get("storage") != "metadata_only":
            _raise("source_policy_not_approved")
        result.append({
            "evidence_id": evidence_id,
            "source_key": row["source_key"],
            "relation": row["relation"],
            "title": str(row["title"])[:300],
            "publisher_url": row["publisher_url"].partition("#")[0],
            "observed_at": row["observed_at"],
            "published_at": row.get("published_at"),
            "license_id": policy.get("license_id", "NOASSERTION"),
        })
    return result


def _title(template_id: str, bundle: dict) -> str:
    parameters = bundle.get("parameters") or {}
    if template_id == "security-daily":
        raw_date = parameters.get("target_date")
        try:
            target = date.fromisoformat(raw_date)
        except (TypeError, ValueError):
            _raise("invalid_report_parameters")
        return f"セキュリティ情報 {target.isoformat()}"
    context = bundle.get("cve_context") or {}
    cve_id = context.get("cve_id") or parameters.get("cve_id")
    if not valid_cve_id(cve_id):
        _raise("invalid_cve_context")
    return f"{cve_id} の確認情報"


def _cve_panel(bundle: dict, evidence: dict[str, dict]) -> dict:
    context = bundle.get("cve_context") or {}
    cve_id = context.get("cve_id")
    if cve_id != (bundle.get("parameters") or {}).get("cve_id"):
        _raise("invalid_cve_context")
    if not valid_cve_id(cve_id):
        _raise("invalid_cve_context")
    if context.get("kev_status") not in {"listed", "not_listed", "unknown"}:
        _raise("invalid_cve_context")
    if context.get("kev_status") == "not_listed" and context.get("catalog_fresh") is not True:
        _raise("invalid_cve_context")
    if context.get("kev_status") == "unknown" and context.get("catalog_fresh") is True:
        _raise("invalid_cve_context")
    if not _safe_url(context.get("canonical_url")):
        _raise("invalid_cve_context")
    source_url = context.get("catalog_source_url")
    if source_url is not None and not _safe_url(source_url):
        _raise("invalid_cve_context")
    ids = sorted(row["evidence_id"] for row in evidence.values()
                 if row.get("relation") in {"kev", "record", "reference", "title_mention"})
    if not ids:
        _raise("cve_evidence_required")
    return {
        "id": cve_id,
        "kev_status": context["kev_status"],
        "catalog_as_of": context.get("catalog_as_of"),
        "catalog_fresh": context["catalog_fresh"],
        "canonical_url": context["canonical_url"],
        "catalog_source_url": source_url,
        "evidence_ids": ids,
    }


def assemble_article(proposal: dict, review: dict, *, bundle: dict, template_id: str) -> dict:
    """Build article-v2 only from accepted immutable claim text and snapshot metadata."""
    proposal = validate_claims(proposal, bundle, template_id)
    review = validate_review(review, proposal, bundle)
    decisions = {row["claim_id"]: row for row in review["reviews"]}
    if any(row["decision"] == "needs_revision" for row in decisions.values()):
        _raise("claim_repair_required")
    accepted = [claim for claim in proposal["claims"]
                if decisions[claim["claim_id"]]["decision"] == "accepted"]
    rejected = [claim for claim in proposal["claims"]
                if decisions[claim["claim_id"]]["decision"] == "rejected"]
    del rejected  # Rejected claims are never assembled or persisted as article content.
    try:
        template = resolve_template(template_id, bundle.get("template_snapshot"))
    except (KeyError, TypeError, ValueError):
        _raise("invalid_template_snapshot")
    min_claims = template["publish_policy"]["minimum_supported_claims"]
    if sum(claim["classification"] == "observed" for claim in accepted) < min_claims:
        _raise("insufficient_verified_claims", skipped=True)
    if not accepted:
        _raise("no_claims_accepted", skipped=True)
    evidence = _evidence_map(bundle)
    used_ids = {eid for claim in accepted for eid in claim["evidence_ids"]}
    if template_id == "cve-kev-deep-dive":
        cve = _cve_panel(bundle, evidence)
        used_ids.update(cve["evidence_ids"])
    else:
        cve = None
    sources = _sources(evidence, used_ids)
    if len(sources) > template["evidence_limits"]["max_sources_in_article"]:
        _raise("too_many_sources")

    headings = _HEADINGS[template_id]
    sections = []
    for section_key in ("primary_observations", "analysis", "unknowns"):
        members = [claim for claim in accepted if claim["section"] == section_key]
        if members:
            sections.append({
                "heading": headings[section_key],
                "claim_ids": [claim["claim_id"] for claim in members],
                "evidence_ids": sorted({eid for claim in members for eid in claim["evidence_ids"]}),
            })
    # CVE metadata is a deterministic panel in the existing renderer; keeping
    # the evidence in a fixed section also lets legacy DB evidence collectors
    # retain every immutable relation.
    if cve:
        sections.append({"heading": "出典", "claim_ids": [],
                         "evidence_ids": cve["evidence_ids"]})
    claims = [{key: deepcopy(claim[key]) for key in (
        "claim_id", "text", "classification", "evidence_ids", "section", "importance")}
        for claim in accepted]
    primary = [claim for claim in accepted if claim["classification"] == "observed"]
    if not primary:
        _raise("insufficient_verified_claims", skipped=True)
    article = {
        "schema_version": 2,
        "template_id": template_id,
        "language": "ja",
        "title": _title(template_id, bundle),
        "dek": primary[0]["text"],
        "summary": [claim["text"] for claim in accepted[:3]],
        "sections": sections,
        "claims": claims,
        "sources": sources,
    }
    if cve:
        article["cve"] = cve
    _validate_article_shape(article, evidence, bundle, template_id)
    return article


def validate_article_v2(article: object, *, bundle: dict, template_id: str) -> dict:
    """Re-check the complete publication contract before it reaches the renderer."""
    if not isinstance(article, dict):
        _raise("article_invalid")
    _validate_article_shape(article, _evidence_map(bundle), bundle, template_id)
    return deepcopy(article)


def _validate_article_shape(article: dict, evidence: dict[str, dict], bundle: dict,
                            template_id: str) -> None:
    _schema("article-v2.schema.json", article)
    if (article.get("schema_version") != 2 or article.get("template_id") != template_id or
            bundle.get("template_id") != template_id or article.get("language") != "ja"):
        _raise("article_template_mismatch")
    try:
        template = resolve_template(template_id, bundle.get("template_snapshot"))
    except (KeyError, ValueError, TypeError):
        _raise("invalid_template_snapshot")
    claims = article["claims"]
    _validate_claim_rows(claims, evidence, template_id=template_id, bundle=bundle)
    claim_map = {claim["claim_id"]: claim for claim in claims}
    if len(claim_map) != len(claims):
        _raise("claim_id_invalid")
    if sum(claim["classification"] == "observed" for claim in claims) < template["publish_policy"]["minimum_supported_claims"]:
        _raise("insufficient_verified_claims")
    expected_title = _title(template_id, bundle)
    if article["title"] != expected_title:
        _raise("title_not_deterministic")
    if article["dek"] not in {claim["text"] for claim in claims if claim["classification"] == "observed"}:
        _raise("dek_not_supported_by_verified_claim")
    if any(summary not in {claim["text"] for claim in claims} for summary in article["summary"]):
        _raise("summary_not_supported_by_verified_claim")
    displayed = []
    referenced: set[str] = set()
    for section in article["sections"]:
        if section["heading"] not in set(_HEADINGS[template_id].values()) | {"出典"}:
            _raise("unreviewed_section_heading")
        if not _safe_text(section["heading"]):
            _raise("unsafe_article_text")
        if any(eid not in evidence for eid in section["evidence_ids"]):
            _raise("invalid_evidence_reference")
        referenced.update(section["evidence_ids"])
        for claim_id in section["claim_ids"]:
            if claim_id not in claim_map:
                _raise("displayed_text_claim_unverified")
            claim = claim_map[claim_id]
            if section["heading"] != _HEADINGS[template_id][claim["section"]]:
                _raise("claim_section_mismatch")
            if not set(claim["evidence_ids"]) <= set(section["evidence_ids"]):
                _raise("displayed_evidence_does_not_match_claims")
            displayed.append(claim_id)
    if len(displayed) != len(set(displayed)) or set(displayed) != set(claim_map):
        _raise("unrendered_verified_claim")
    expected_referenced = {eid for claim in claims for eid in claim["evidence_ids"]}
    if template_id == "cve-kev-deep-dive":
        expected_cve = _cve_panel(bundle, evidence)
        if article.get("cve") != expected_cve:
            _raise("cve_fact_context_mismatch")
        expected_referenced.update(expected_cve["evidence_ids"])
    elif article.get("cve") is not None:
        _raise("model_supplied_private_metadata")
    if referenced != expected_referenced:
        _raise("article_evidence_mismatch")
    expected_sources = _sources(evidence, expected_referenced)
    if article["sources"] != expected_sources:
        _raise("article_sources_mismatch")
