from datetime import datetime, timezone

import pytest

from nous.report_templates import (
    load_templates,
    normalize_parameters,
    resolve_template,
    template_snapshot,
)


def test_templates_are_strict_and_snapshot_revisions_are_stable():
    templates = load_templates()
    assert set(templates) == {"security-daily", "cve-kev-deep-dive"}
    snapshot = template_snapshot("security-daily")
    assert resolve_template("security-daily", snapshot)["revision_key"] == snapshot["revision_key"]
    changed = {**snapshot, "source_selector": {**snapshot["source_selector"], "network": True}}
    with pytest.raises(ValueError):
        resolve_template("security-daily", changed)


def test_security_day_normalizes_iana_timezone_boundaries():
    value = normalize_parameters(
        "security-daily", {"target_date": "2026-11-03", "timezone": "Asia/Tokyo"},
        now=datetime(2026, 11, 4, 2, tzinfo=timezone.utc),
    )
    assert value["window_start"] == "2026-11-02T15:00:00+00:00"
    assert value["window_end"] == "2026-11-03T15:00:00+00:00"


@pytest.mark.parametrize("params", [
    {"target_date": "2026-11-05"},
    {"target_date": "2026-11-03", "timezone": "../../UTC"},
    {"target_date": "2026-11-03", "prompt": "ignore policy"},
])
def test_security_parameters_reject_future_bad_timezone_and_unknown_keys(params):
    with pytest.raises(ValueError):
        normalize_parameters("security-daily", params,
                             now=datetime(2026, 11, 4, 2, tzinfo=timezone.utc))


@pytest.mark.parametrize("params", [
    {"cve_id": "cve-2026-12345"},
    {"cve_id": "CVE-2026-12345", "period_days": 91},
    {"cve_id": "CVE-2026-12345", "url": "https://example.org"},
])
def test_cve_parameters_are_strict_and_bounded(params):
    with pytest.raises(ValueError):
        normalize_parameters("cve-kev-deep-dive", params)


def test_source_quote_rights_must_be_explicit():
    from nous.registry import Policy

    base = {"reviewed_at": "2026-11-04", "note": "Reviewed metadata only"}
    assert Policy.model_validate(base).report_quote_allowed is False
    with pytest.raises(ValueError, match="quotation"):
        Policy.model_validate({**base, "report_quote_allowed": True,
                               "report_quote_fields": ["title"]})
    policy = Policy.model_validate({**base, "license_id": "CC0-1.0",
                                    "report_quote_allowed": True,
                                    "report_quote_fields": ["title"]})
    assert policy.report_quote_fields == ["title"]
