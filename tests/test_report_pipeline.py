from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

from nous.report_pipeline import (
    CodexRunner,
    ReportError,
    ReportSkipped,
    run_editorial_pipeline,
    validate_article,
    _evidence_record,
    _safe_publisher_url,
    _check_site,
    _codex_article_schema,
    _codex_failure_code,
)
from nous.report_templates import template_snapshot


def test_report_release_allows_only_canonical_library_return_link(tmp_path):
    (tmp_path / "index.html").write_text('<a href="/explore">ライブラリへ戻る</a>', encoding="utf-8")
    assets, digest = _check_site(tmp_path)
    assert assets == [] and len(digest) == 64

    (tmp_path / "index.html").write_text('<a href="/admin/sources">管理</a>', encoding="utf-8")
    with pytest.raises(ReportError, match="renderer_relative_link_rejected"):
        _check_site(tmp_path)


def test_safe_publisher_url_drops_only_fragment_and_rejects_other_unsafe_parts():
    original = "https://publisher.example/advisory?id=7#impact"
    assert _safe_publisher_url(original) == "https://publisher.example/advisory?id=7"
    assert _safe_publisher_url("https://publisher.example/advisory#") == (
        "https://publisher.example/advisory")

    for unsafe in (
        "http://publisher.example/advisory#impact",
        "https://user@publisher.example/advisory#impact",
        "https://publisher.example:8443/advisory#impact",
        "https://publisher.example/advisory\n#impact",
    ):
        with pytest.raises(ReportError, match="invalid_publisher_url"):
            _safe_publisher_url(unsafe)


def test_evidence_record_defrags_public_url_without_mutating_immutable_item_data():
    original = "https://publisher.example/advisory?id=7#impact"
    version = SimpleNamespace(
        attributes={"title": "Security advisory with a tested title", "url": original},
        provenance={"item_url": original},
        sha256="a" * 64,
        id=11,
        observed_at=datetime(2026, 11, 3, tzinfo=timezone.utc),
    )
    item = SimpleNamespace(id=7, canonical_url=original, kind="advisory")
    source = SimpleNamespace(
        source_key="fixture-advisories",
        config={"policy": {"content_storage": "metadata_only", "license_id": "CC-BY-4.0"}},
    )

    record = _evidence_record(version, item, source, "record", "E001")

    assert record["publisher_url"] == "https://publisher.example/advisory?id=7"
    assert version.attributes["url"] == original
    assert version.provenance["item_url"] == original
    assert version.sha256 == "a" * 64


def _codex_runner_for_home(home, monkeypatch):
    runner = object.__new__(CodexRunner)
    runner.codex_home = home
    runner.gid = 10002
    monkeypatch.setattr("nous.report_pipeline.os.geteuid", lambda: 0)
    monkeypatch.setattr("nous.report_pipeline.os.chown", lambda *_args: None)
    return runner


def test_codex_home_clears_only_official_arg0_runtime_and_preserves_credentials(tmp_path, monkeypatch):
    home = tmp_path / "codex-home"
    runtime = home / "tmp" / "arg0-linux" / "codex-arg0fixture"
    runtime.mkdir(parents=True)
    target = tmp_path / "installed-codex"
    target.write_text("installed binary", encoding="utf-8")
    (runtime / ".lock").touch()
    for name in ("codex-linux-sandbox", "apply_patch", "applypatch"):
        (runtime / name).symlink_to(target)
    credentials = home / "auth.json"
    credentials.write_text('{"credential":"preserve-this"}', encoding="utf-8")

    _codex_runner_for_home(home, monkeypatch)._prepare_codex_home()

    assert not (home / "tmp" / "arg0-linux").exists()
    assert credentials.read_text(encoding="utf-8") == '{"credential":"preserve-this"}'
    assert target.read_text(encoding="utf-8") == "installed binary"


def test_codex_home_still_rejects_symlinks_outside_arg0_runtime(tmp_path, monkeypatch):
    home = tmp_path / "codex-home"
    home.mkdir()
    external = tmp_path / "external-secret"
    external.write_text("untouched", encoding="utf-8")
    (home / "unexpected-link").symlink_to(external)

    with pytest.raises(ReportError, match="codex_home_unsafe"):
        _codex_runner_for_home(home, monkeypatch)._prepare_codex_home()

    assert external.read_text(encoding="utf-8") == "untouched"


def test_codex_home_rejects_symlinked_tmp_parent_without_traversing_it(tmp_path, monkeypatch):
    home = tmp_path / "codex-home"
    home.mkdir()
    external_tmp = tmp_path / "external-tmp"
    runtime = external_tmp / "arg0-linux" / "codex-arg0fixture"
    runtime.mkdir(parents=True)
    target = tmp_path / "external-target"
    target.write_text("untouched", encoding="utf-8")
    launcher = runtime / "apply_patch"
    launcher.symlink_to(target)
    (home / "tmp").symlink_to(external_tmp, target_is_directory=True)

    with pytest.raises(ReportError, match="codex_home_unsafe"):
        _codex_runner_for_home(home, monkeypatch)._prepare_codex_home()

    assert launcher.is_symlink()
    assert target.read_text(encoding="utf-8") == "untouched"


def test_codex_article_schema_is_strict_and_keeps_publication_contract():
    generation_schema = _codex_article_schema()
    assert "cve" not in generation_schema["properties"]
    assert "sources" not in generation_schema["properties"]
    assert "cve" not in generation_schema["$defs"]
    assert "source" not in generation_schema["$defs"]

    def check(node):
        if isinstance(node, dict):
            assert "oneOf" not in node
            if node.get("type") == "object" and "properties" in node:
                assert set(node["required"]) == set(node["properties"])
                assert node["additionalProperties"] is False
            for child in node.values():
                check(child)
        elif isinstance(node, list):
            for child in node:
                check(child)

    check(generation_schema)
    Draft202012Validator.check_schema(generation_schema)
    Draft202012Validator(generation_schema).validate(article_for(evidence_bundle()))
    _, cve_article, _ = cve_fact_fixture()
    Draft202012Validator(generation_schema).validate(cve_article)


def test_codex_exec_is_non_git_and_both_commands_use_same_uid():
    runner = object.__new__(CodexRunner)
    runner.binary, runner.model = "codex", None
    runner.uid, runner.gid = 10002, 10002
    runner.setpriv, runner.prlimit = "setpriv", "prlimit"
    identity = runner._identity_args()
    assert identity[:5] == ["setpriv", "--reuid", "10002", "--regid", "10002"]
    assert "--no-new-privs" in identity
    args = runner._codex_args(Path("/tmp/job/plan"), Path("/tmp/plan.json"),
                              Path("/tmp/job/plan/output.json"))
    assert args[:2] == ["codex", "exec"]
    assert "--skip-git-repo-check" in args
    assert "--output-schema" in args and "--output-last-message" in args


@pytest.mark.parametrize("message,code", [
    ("Not a git repository", "codex_git_repo_rejected"),
    ("Invalid JSON schema for response_format", "codex_schema_rejected"),
    ("Permission denied (os error 13)", "codex_permission_denied"),
    ("Not logged in", "codex_auth"),
    ("Usage limit reached", "codex_usage_limit"),
    ("unrelated temporary failure", "codex_execution_failed"),
])
def test_codex_error_codes_never_include_stderr(message, code):
    assert _codex_failure_code(message) == code
    assert message.lower() not in code


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
        "title": text,
        "dek": text,
        "summary": [text],
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


def cve_fact_fixture(*, cve_id="CVE-2026-12345"):
    bundle = evidence_bundle("cve-kev-deep-dive")
    bundle["parameters"] = {
        "cve_id": cve_id, "period_days": 30,
        "window_start": "2026-10-01T00:00:00+00:00",
        "window_end": "2026-11-04T00:00:00+00:00",
    }
    bundle["evidence"][0]["relation"] = "reference"
    bundle["cve_context"] = {
        "cve_id": cve_id, "kev_status": "unknown", "catalog_as_of": None,
        "catalog_fresh": False, "canonical_url": f"https://www.cve.org/CVERecord?id={cve_id}",
        "catalog_source_url": None,
    }
    text = "公式記録には対象CVEの参照情報が掲載されています。"
    article = {
        "schema_version": 1, "template_id": "cve-kev-deep-dive", "language": "ja",
        "title": text, "dek": text, "summary": [text],
        "sections": [
            {"heading": "CVEの確認情報", "blocks": [{
                "type": "cve_fact", "cve_id": cve_id,
                "evidence_ids": ["E001"], "claim_ids": ["C001"],
            }]},
            {"heading": "出典", "blocks": [{
                "type": "source_list", "evidence_ids": ["E001"],
            }]},
        ],
        "claims": [{"claim_id": "C001", "text": text, "classification": "observed",
                    "evidence_ids": ["E001"]}],
    }
    fact_check = {"claims": [{
        "claim_id": "C001", "text": text, "classification": "observed",
        "evidence_ids": ["E001"], "assessment": "supported",
    }], "revision_request": [], "summary": "根拠IDに対応しています。"}
    return bundle, article, fact_check


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


@pytest.mark.parametrize("field,code", [
    ("title", "title_not_supported_by_verified_claim"),
    ("dek", "dek_not_supported_by_verified_claim"),
    ("summary", "summary_not_supported_by_verified_claim"),
])
def test_fabricated_editorial_header_is_rejected(field, code):
    bundle = evidence_bundle()
    article = article_for(bundle)
    article[field] = (["未確認の侵害が複数組織で発生したことを示すまとめです。"]
                      if field == "summary"
                      else "未確認の侵害が複数組織で発生したことを示す見出しです。")
    with pytest.raises(ReportError, match=code):
        validate_article(article, template_id="security-daily", bundle=bundle,
                         fact_check=fact_check_for())


def test_exploitation_claim_requires_a_fresh_cisa_catalog():
    bundle = evidence_bundle("cve-kev-deep-dive")
    bundle["parameters"] = {"cve_id": "CVE-2026-12345", "period_days": 30,
                            "window_start": "2026-10-01T00:00:00+00:00",
                            "window_end": "2026-11-04T00:00:00+00:00"}
    bundle["evidence"][0].update({
        "source_key": "cisa-kev", "relation": "kev",
        "content_policy": {"storage": "metadata_only", "license_id": "CC0-1.0",
                            "quote_allowed": False, "quote_values": [],
                            "dataset_license": "CC0-1.0"},
    })
    text = "この脆弱性は攻撃者によって広く悪用されています。"
    bundle["cve_context"] = {
        "cve_id": "CVE-2026-12345", "kev_status": "listed",
        "catalog_as_of": "2026-11-04T00:00:00+00:00", "catalog_fresh": False,
        "canonical_url": "https://www.cve.org/CVERecord?id=CVE-2026-12345",
        "catalog_source_url": "https://catalog.example/kev.json",
    }
    article = {
        "schema_version": 1, "template_id": "cve-kev-deep-dive", "language": "ja",
        "title": text, "dek": text, "summary": [text],
        "sections": [
            {"heading": "確認された事実", "blocks": [{
                "type": "paragraph", "text": text,
                "evidence_ids": ["E001"], "claim_ids": ["C001"],
            }]},
            {"heading": "出典", "blocks": [{
                "type": "source_list", "evidence_ids": ["E001"],
            }]},
        ],
        "claims": [{"claim_id": "C001", "text": text, "classification": "observed",
                    "evidence_ids": ["E001"]}],
    }
    fact_check = {"claims": [{"claim_id": "C001", "text": text,
                               "classification": "observed", "evidence_ids": ["E001"],
                               "assessment": "supported"}]}
    with pytest.raises(ReportError, match="unsupported_exploitation_claim"):
        validate_article(article, template_id="cve-kev-deep-dive", bundle=bundle,
                         fact_check=fact_check)


def test_cve_fact_passes_full_fixture_editorial_pipeline():
    bundle, article, fact_check = cve_fact_fixture()
    plan = {
        "decision": "publish", "thesis": "公式記録の参照情報を整理します。",
        "audience": "脆弱性対応担当者", "outline": ["CVEの確認情報", "出典"],
        "evidence_ids": ["E001"], "reason": "対象CVEに紐づく一次情報があります。",
    }
    runner = FixtureRunner({
        "plan": plan, "fact_check": fact_check, "draft": article, "edit": article,
    })

    final, model = run_editorial_pipeline(
        bundle, template_id="cve-kev-deep-dive", run_id="cve-fact-fixture",
        runner=runner, persist_stage=lambda *_args: None,
    )

    assert runner.calls == ["plan", "fact_check", "draft", "edit"]
    assert model == "fixture-only"
    assert final["sections"][0]["blocks"][0] == article["sections"][0]["blocks"][0]
    assert final["cve"]["id"] == "CVE-2026-12345"


def test_cve_fact_requires_matching_bundle_id_and_visible_claim_evidence():
    bundle, article, fact_check = cve_fact_fixture()
    article["sections"][0]["blocks"][0]["cve_id"] = "CVE-2026-54321"
    with pytest.raises(ReportError, match="cve_fact_context_mismatch"):
        validate_article(article, template_id="cve-kev-deep-dive", bundle=bundle,
                         fact_check=fact_check)

    bundle, article, fact_check = cve_fact_fixture()
    article["sections"][0]["blocks"][0]["evidence_ids"] = ["E002"]
    with pytest.raises(ReportError, match="invalid_evidence_reference"):
        validate_article(article, template_id="cve-kev-deep-dive", bundle=bundle,
                         fact_check=fact_check)


def test_approved_kev_vulnerability_field_is_available_for_quote_rights():
    from datetime import datetime, timezone
    from types import SimpleNamespace

    cve_id = "CVE-2026-12345"
    source_url = ("https://raw.githubusercontent.com/cisagov/kev-data/develop/"
                  "known_exploited_vulnerabilities.json")
    source = SimpleNamespace(
        source_key="cisa-kev", origin="official", url=source_url,
        config={"policy": {
            "license_id": "CC0-1.0", "content_storage": "metadata_only",
            "report_quote_allowed": True,
            "report_quote_fields": ["vulnerability.vendor"],
        }},
    )
    item = SimpleNamespace(
        id=1, external_id=cve_id, canonical_url=f"https://www.cve.org/CVERecord?id={cve_id}",
        kind="vulnerability",
    )
    version = SimpleNamespace(
        id=2, sha256="a" * 64,
        observed_at=datetime(2026, 11, 3, tzinfo=timezone.utc),
        provenance={"adapter": "cisa_kev_v1", "source_url": source_url},
        attributes={
            "title": "Known Exploited Vulnerability",
            "url": item.canonical_url,
            "vulnerability": {
                "cve_id": cve_id, "known_exploited": True,
                "vendor": "Example Vendor",
            },
        },
    )

    evidence = _evidence_record(version, item, source, "kev", "E001")
    assert evidence["content_policy"]["quote_allowed"] is True
    assert evidence["content_policy"]["quote_values"] == ["Example Vendor"]
    assert "vulnerability.vendor" in evidence["allowed_fields"]


def test_unreviewed_article_section_heading_cannot_publish_an_unchecked_claim():
    bundle = evidence_bundle()
    article = article_for(bundle)
    article["sections"][0]["heading"] = "ランサムウェアでの悪用が確認された"
    with pytest.raises(ReportError, match="unreviewed_section_heading"):
        validate_article(article, template_id="security-daily", bundle=bundle,
                         fact_check=fact_check_for())


def test_fact_table_columns_must_use_neutral_reviewed_labels():
    bundle = evidence_bundle()
    text = "セキュリティ更新の内容 | 公式アドバイザリの情報"
    article = article_for(bundle, text=text)
    article["sections"][0]["blocks"] = [{
        "type": "fact_table", "headers": ["項目", "内容"],
        "rows": [{"cells": text.split(" | "), "claim_ids": ["C001"],
                  "evidence_ids": ["E001"]}],
    }]
    validated = validate_article(
        article, template_id="security-daily", bundle=bundle,
        fact_check=fact_check_for(text),
    )
    assert validated["sections"][0]["blocks"][0]["headers"] == ["項目", "内容"]

    article["sections"][0]["blocks"][0]["headers"][1] = "深刻な侵害が確定"
    with pytest.raises(ReportError, match="unreviewed_table_header"):
        validate_article(
            article, template_id="security-daily", bundle=bundle,
            fact_check=fact_check_for(text),
        )
