from datetime import datetime, timezone

import pytest

from nous.report_pipeline import (
    ReportError,
    ReportSkipped,
    run_editorial_pipeline,
    validate_article,
)
from nous.report_templates import template_snapshot


def evidence_bundle(template_id="security-daily"):
    return {
        "schema_version": 1,
        "template_id": template_id,
        "template_revision": template_snapshot(template_id)["revision_key"],
        "template_snapshot": template_snapshot(template_id),
        "parameters": {"target_date": "2026-11-03", "timezone": "Asia/Tokyo",
                        "category": None, "window_start": "2026-11-02T15:00:00+00:00",
                        "window_end": "2026-11-03T15:00:00+00:00"},
        "observed_cutoff": "2026-11-04T00:00:00+00:00",
        "window_start": "2026-11-02T15:00:00+00:00",
        "window_end": "2026-11-03T15:00:00+00:00",
        "evidence": [{
            "evidence_id": "E001", "source_key": "fixture-advisory", "item_id": 7,
            "item_version_id": 11, "item_version_sha256": "a" * 64,
            "relation": "record", "publisher_url": "https://publisher.example/security/7",
            "observed_at": "2026-11-03T01:00:00+00:00",
            "published_at": "2026-11-03T00:00:00+00:00", "retrieved_at": "2026-11-03T01:00:00+00:00",
            "title": "公式アドバイザリは影響対象の更新を説明するための試験用タイトルです。",
            "kind": "advisory", "allowed_fields": ["title", "publisher_url", "observed_at", "published_at"],
            "content_policy": {"storage": "metadata_only", "license_id": "NOASSERTION",
                               "quote_allowed": False, "quote_values": []},
        }],
        "truncated": False,
        "sha256": "b" * 64,
    }


def article_for(bundle, *, text="公式アドバイザリには影響対象の更新が記載されています。"):
    return {
        "schema_version": 1, "template_id": bundle["template_id"], "language": "ja",
        "title": "確認された更新情報と対応上の論点",
        "dek": "観測できた情報と、その範囲での分析を区別して整理します。",
        "summary": ["本稿は取得済みの公開メタデータを根拠IDと結び付けて紹介します。"],
        "sections": [
            {"heading": "確認された事実", "blocks": [{
                "type": "paragraph", "text": text, "evidence_ids": ["E001"],
                "claim_ids": ["C001"],
            }]},
            {"heading": "出典", "blocks": [{"type": "source_list", "evidence_ids": ["E001"]}]},
        ],
        "claims": [{"claim_id": "C001", "text": text, "classification": "observed",
                    "evidence_ids": ["E001"]}],
    }


def fact_check_for(text="公式アドバイザリには影響対象の更新が記載されています。"):
    return {"claims": [{"claim_id": "C001", "text": text, "classification": "observed",
                        "evidence_ids": ["E001"], "assessment": "supported"}],
            "revision_request": [], "summary": "一次情報メタデータと対応しています。"}


class FixtureRunner:
    model = "fixture-only"

    def __init__(self, outputs=None):
        self.outputs = outputs or {}
        self.calls = []

    def run(self, stage, payload, *, run_id, timeout=240):
        self.calls.append(stage)
        if stage in self.outputs:
            return self.outputs[stage]
        if stage == "plan":
            return {"decision": "publish", "thesis": "確認された更新を整理します。",
                    "audience": "運用担当者", "outline": ["事実", "出典"],
                    "evidence_ids": ["E001"], "reason": "公開日に観測されています。"}
        if stage == "fact_check":
            return fact_check_for()
        return article_for(payload["bundle"] if "bundle" in payload else evidence_bundle())


def test_fixture_editorial_pipeline_records_four_distinct_stages():
    bundle = evidence_bundle()
    runner = FixtureRunner()
    persisted = {}
    final, model = run_editorial_pipeline(bundle, template_id="security-daily", run_id="run-1",
                                           runner=runner,
                                           persist_stage=lambda name, value: persisted.update({name: value}))
    assert runner.calls == ["plan", "fact_check", "draft", "edit"]
    assert set(persisted) == {"plan", "fact_check", "draft", "article"}
    assert final["sources"][0]["evidence_id"] == "E001"
    assert model == "fixture-only"


def test_fixture_pipeline_skips_without_evidence_before_model_call():
    runner = FixtureRunner()
    with pytest.raises(ReportSkipped):
        run_editorial_pipeline({**evidence_bundle(), "evidence": []}, template_id="security-daily",
                               run_id="run-2", runner=runner, persist_stage=lambda *_: None)
    assert runner.calls == []


@pytest.mark.parametrize("bad_text,code", [
    ("<script>alert(1)</script>", "unsafe_article_text"),
    ("https://attacker.example/path", "unsafe_article_text"),
    ("別の文に置き換えられた根拠なしの文章です。", "displayed_text_not_exact_verified_claim"),
])
def test_deterministic_gate_rejects_unsafe_or_unmapped_display_text(bad_text, code):
    bundle = evidence_bundle()
    text = "公式アドバイザリには影響対象の更新が記載されています。"
    article = article_for(bundle)
    if bad_text.startswith("<") or bad_text.startswith("https://"):
        article["claims"][0]["text"] = bad_text
        article["sections"][0]["blocks"][0]["text"] = bad_text
    else:
        article["sections"][0]["blocks"][0]["text"] = bad_text
    with pytest.raises(ReportError, match=code):
        validate_article(article, template_id="security-daily", bundle=bundle,
                         fact_check=fact_check_for(text))


def test_quote_requires_explicit_source_policy_permission():
    bundle = evidence_bundle()
    text = bundle["evidence"][0]["title"]
    article = article_for(bundle, text=text)
    article["sections"][0]["blocks"][0] = {
        "type": "quote", "text": text, "evidence_ids": ["E001"], "claim_ids": ["C001"],
    }
    with pytest.raises(ReportError, match="quote_rights_not_granted"):
        validate_article(article, template_id="security-daily", bundle=bundle,
                         fact_check=fact_check_for(text))


def test_claims_must_keep_fact_check_identity_and_evidence():
    bundle = evidence_bundle()
    article = article_for(bundle)
    article["claims"][0]["evidence_ids"] = ["E999"]
    article["sections"][0]["blocks"][0]["evidence_ids"] = ["E999"]
    with pytest.raises(ReportError, match="invalid_evidence_reference"):
        validate_article(article, template_id="security-daily", bundle=bundle,
                         fact_check=fact_check_for())


def test_fact_claim_must_be_displayed_verbatim_and_linked_to_same_evidence():
    bundle = evidence_bundle()
    article = article_for(bundle)
    article["sections"][0]["blocks"][0]["claim_ids"] = ["C002"]
    with pytest.raises(ReportError, match="displayed_text_claim_unverified"):
        validate_article(article, template_id="security-daily", bundle=bundle,
                         fact_check=fact_check_for())
