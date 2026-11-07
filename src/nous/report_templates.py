"""Strict, reviewed report templates and their bounded parameter processors."""
from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from .cve_index import valid_cve_id
from .source_taxonomy import SOURCE_CATEGORIES

_TEMPLATE_FIELDS = {
    "id", "revision", "title", "category", "parameters_schema", "source_selector",
    "window_policy", "evidence_limits", "outline", "quality_rules", "publish_policy",
}
_SLUG = re.compile(r"^[a-z][a-z0-9-]{1,79}$")
_DEFAULT_DIR = Path(os.getenv("NOUS_REPORTS_DIR", str(Path(__file__).resolve().parents[2] / "reports"))) / "templates"


def _templates_dir() -> Path:
    return Path(os.getenv("NOUS_REPORT_TEMPLATES_DIR", str(_DEFAULT_DIR)))


def _validated_template(raw: object) -> dict:
    if not isinstance(raw, dict) or set(raw) != _TEMPLATE_FIELDS:
        raise ValueError("invalid report template fields")
    template_id = raw.get("id")
    if not isinstance(template_id, str) or not _SLUG.fullmatch(template_id):
        raise ValueError("invalid report template ID")
    if type(raw.get("revision")) is not int or raw["revision"] < 1:
        raise ValueError("template revision must be a positive integer")
    if not isinstance(raw.get("title"), str) or not 1 <= len(raw["title"]) <= 120:
        raise ValueError("invalid report template title")
    if raw.get("category") not in {"security", "cve"}:
        raise ValueError("invalid report template category")

    params = raw.get("parameters_schema")
    if template_id == "security-daily":
        if (not isinstance(params, dict) or set(params) != {"required", "optional", "category_values"} or
                params["required"] != ["target_date"] or
                set(params["optional"]) != {"timezone", "category"} or
                params["category_values"] != ["security", "advisory", "vulnerability"]):
            raise ValueError("invalid security-daily parameter schema")
        selector = raw.get("source_selector")
        if (not isinstance(selector, dict) or set(selector) != {"kinds", "allow_title_metadata"} or
                selector["kinds"] != ["news", "advisory", "vulnerability"] or
                selector["allow_title_metadata"] is not True):
            raise ValueError("invalid security-daily selector")
        window = raw.get("window_policy")
        if (not isinstance(window, dict) or set(window) != {"type", "timezone_default"} or
                window != {"type": "local_day", "timezone_default": "Asia/Tokyo"}):
            raise ValueError("invalid security-daily window policy")
    elif template_id == "cve-kev-deep-dive":
        if (not isinstance(params, dict) or set(params) != {"required", "optional"} or
                params["required"] != ["cve_id"] or params["optional"] != ["period_days"]):
            raise ValueError("invalid cve-kev parameter schema")
        selector = raw.get("source_selector")
        if (not isinstance(selector, dict) or set(selector) != {"cve_linked", "allow_title_metadata"} or
                selector != {"cve_linked": True, "allow_title_metadata": True}):
            raise ValueError("invalid CVE selector")
        window = raw.get("window_policy")
        if (not isinstance(window, dict) or set(window) != {"type", "default_days", "max_days"} or
                window != {"type": "rolling_days", "default_days": 30, "max_days": 90}):
            raise ValueError("invalid CVE window policy")
    else:
        raise ValueError("unknown MVP template")

    limits = raw.get("evidence_limits")
    expected_limits = {"max_records", "max_per_source", "max_sources", "max_bundle_bytes",
                       "max_sources_in_article"}
    if (not isinstance(limits, dict) or set(limits) != expected_limits or
            any(type(v) is not int or v < 1 for v in limits.values()) or
            not 1 <= limits["max_records"] <= 200 or
            not 1 <= limits["max_per_source"] <= 50 or
            not 1 <= limits["max_sources"] <= 50 or
            not 1024 <= limits["max_bundle_bytes"] <= 2_097_152 or
            not 1 <= limits["max_sources_in_article"] <= 50):
        raise ValueError("invalid report evidence limits")
    outline = raw.get("outline")
    rules = raw.get("quality_rules")
    if (not isinstance(outline, list) or not 2 <= len(outline) <= 8 or
            any(not isinstance(v, str) or not v.strip() or len(v) > 80 for v in outline) or
            not isinstance(rules, list) or not 1 <= len(rules) <= 20 or
            any(not isinstance(v, str) or not v.strip() or len(v) > 500 for v in rules)):
        raise ValueError("invalid report editorial policy")
    publish = raw.get("publish_policy")
    blocks = {"paragraph", "bullet_list", "fact_table", "source_list", "cve_fact", "quote"}
    if (not isinstance(publish, dict) or set(publish) != {
            "minimum_evidence", "minimum_supported_claims", "allowed_blocks"} or
            type(publish["minimum_evidence"]) is not int or
            not 1 <= publish["minimum_evidence"] <= limits["max_records"] or
            type(publish["minimum_supported_claims"]) is not int or
            not 1 <= publish["minimum_supported_claims"] <= 10 or
            not isinstance(publish["allowed_blocks"], list) or not publish["allowed_blocks"] or
            len(publish["allowed_blocks"]) != len(set(publish["allowed_blocks"])) or
            any(name not in blocks for name in publish["allowed_blocks"])):
        raise ValueError("invalid report publication policy")
    if not isinstance(raw.get("outline"), list):
        raise ValueError("invalid report outline")
    canonical = json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {**raw, "revision_key": hashlib.sha256(canonical.encode()).hexdigest()}


def load_templates() -> dict[str, dict]:
    result = {}
    for path in sorted(_templates_dir().glob("*.yaml")):
        template = _validated_template(yaml.safe_load(path.read_text(encoding="utf-8")))
        template_id = template["id"]
        if path.stem != template_id or template_id in result:
            raise ValueError("report template filename/ID mismatch or duplicate")
        result[template_id] = template
    if set(result) != {"security-daily", "cve-kev-deep-dive"}:
        raise ValueError("the reviewed MVP template catalog is incomplete")
    return result


def template_snapshot(template_id: str) -> dict:
    return dict(load_templates()[template_id])


def resolve_template(template_id: str, snapshot: object | None = None) -> dict:
    if snapshot is None:
        return load_templates()[template_id]
    if not isinstance(snapshot, dict) or set(snapshot) != _TEMPLATE_FIELDS | {"revision_key"}:
        raise ValueError("invalid stored template snapshot")
    raw = {key: value for key, value in snapshot.items() if key != "revision_key"}
    result = _validated_template(raw)
    if result["id"] != template_id or result["revision_key"] != snapshot["revision_key"]:
        raise ValueError("stored template revision hash mismatch")
    return result


def template_revision(template_id: str) -> str:
    return load_templates()[template_id]["revision_key"]


def _normalize_source_scope(raw: dict, result: dict) -> dict:
    """An omitted scope means all sources; an explicitly empty list is rejected."""
    for field, allowed in (
        ("source_categories", SOURCE_CATEGORIES),
        ("source_ids", None),
    ):
        if field not in raw:
            continue
        selected = raw[field]
        if (not isinstance(selected, list) or not 1 <= len(selected) <= 50 or
                len(set(str(value) for value in selected)) != len(selected) or
                any(not isinstance(value, str) or (value not in allowed if allowed else
                    not re.fullmatch(r"[a-z][a-z0-9-]{2,99}", value)) for value in selected)):
            raise ValueError("invalid report " + field)
        result[field] = sorted(selected)
    return result


def normalize_parameters(template_id: str, raw: object, *, now: datetime | None = None) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("parameters must be an object")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if template_id == "security-daily":
        allowed = {"target_date", "timezone", "category", "source_categories", "source_ids"}
        if set(raw) - allowed:
            raise ValueError("unsupported security-daily parameter")
        zone_name = raw.get("timezone", "Asia/Tokyo")
        if not isinstance(zone_name, str) or len(zone_name) > 64:
            raise ValueError("invalid IANA timezone")
        try:
            zone = ZoneInfo(zone_name)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError("invalid IANA timezone") from exc
        target_value = raw.get("target_date")
        if target_value is None:
            target = now.astimezone(zone).date()
        elif isinstance(target_value, str):
            try:
                target = date.fromisoformat(target_value)
            except ValueError as exc:
                raise ValueError("target_date must be YYYY-MM-DD") from exc
            if target.isoformat() != target_value:
                raise ValueError("target_date must be YYYY-MM-DD")
        else:
            raise ValueError("target_date must be YYYY-MM-DD")
        if target > now.astimezone(zone).date() or target < now.astimezone(zone).date() - timedelta(days=90):
            raise ValueError("target_date must be within the previous 90 days")
        category = raw.get("category")
        if category not in (None, "security", "advisory", "vulnerability"):
            raise ValueError("unsupported report category")
        start = datetime.combine(target, time.min, tzinfo=zone).astimezone(timezone.utc)
        end = datetime.combine(target + timedelta(days=1), time.min, tzinfo=zone).astimezone(timezone.utc)
        result = {"target_date": target.isoformat(), "timezone": zone_name, "category": category,
                  "window_start": start.isoformat(), "window_end": end.isoformat()}
        return _normalize_source_scope(raw, result)
    if template_id == "cve-kev-deep-dive":
        if set(raw) - {"cve_id", "period_days", "source_categories", "source_ids"}:
            raise ValueError("unsupported cve-kev-deep-dive parameter")
        cve_id = raw.get("cve_id")
        if not isinstance(cve_id, str) or not valid_cve_id(cve_id):
            raise ValueError("a normalized CVE identifier is required")
        period = raw.get("period_days", 30)
        if type(period) is not int or not 1 <= period <= 90:
            raise ValueError("period_days must be between 1 and 90")
        cutoff = now.astimezone(timezone.utc)
        result = {"cve_id": cve_id, "period_days": period,
                  "window_start": (cutoff - timedelta(days=period)).isoformat(),
                  "window_end": cutoff.isoformat()}
        return _normalize_source_scope(raw, result)
    raise ValueError("unknown report template")


def public_template_list() -> list[dict]:
    fields = ("id", "revision", "revision_key", "title", "category", "parameters_schema",
              "evidence_limits", "outline")
    return [{key: value for key, value in template.items() if key in fields}
            for template in load_templates().values()]
