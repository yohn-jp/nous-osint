from pathlib import Path

import pytest
import yaml

from nous import onboard_source
from nous.onboard_source import main, probe
from nous.registry import SourceConfig


def _args(root: Path):
    return [
        "--sources-dir", str(root),
        "--id", "example-advisories",
        "--url", "https://example.org/feed.xml",
        "--kind", "rss",
        "--item-kind", "advisory",
        "--reviewed-at", "2026-11-03",
        "--policy-note", "Reviewed metadata-only feed",
    ]


def test_preview_does_not_write(tmp_path, capsys):
    main(_args(tmp_path))
    data = yaml.safe_load(capsys.readouterr().out)
    assert data["enabled"] is False
    assert data["adapter"] == "rss_v1"
    assert not list(tmp_path.glob("*.yaml"))


def test_write_stages_disabled_candidate_and_rejects_duplicate(tmp_path):
    main(_args(tmp_path) + ["--write"])
    path = tmp_path / "example-advisories.yaml"
    assert yaml.safe_load(path.read_text())["enabled"] is False
    with pytest.raises(SystemExit):
        main(_args(tmp_path) + ["--write"])


def test_html_requires_site_specific_review(tmp_path):
    args = _args(tmp_path)
    args[args.index("rss")] = "html"
    with pytest.raises(SystemExit):
        main(args + ["--write"])
    assert not list(tmp_path.glob("*.yaml"))


def test_json_mapping_candidate(tmp_path, capsys):
    args = _args(tmp_path)
    args[args.index("rss")] = "json_api"
    main(args + ["--json-path", "results", "--map", "title=summary",
                 "--map", "url=link", "--map", "id=uid"])
    data = yaml.safe_load(capsys.readouterr().out)
    assert data["adapter"] == "json_v1"
    assert data["json_path"] == "results"
    assert data["field_map"] == {"title": "summary", "url": "link", "id": "uid"}
    assert data["enabled"] is False


def test_html_selectors_candidate(tmp_path, capsys):
    args = _args(tmp_path)
    args[args.index("rss")] = "html"
    main(args + ["--selector", "item=article", "--selector", "title=h2",
                 "--selector", "url=a"])
    data = yaml.safe_load(capsys.readouterr().out)
    assert data["adapter"] == "html_v1"
    assert data["selectors"] == {"item": "article", "title": "h2", "url": "a"}


def test_invalid_or_duplicate_mapping_rejected(tmp_path):
    with pytest.raises(SystemExit):
        main(_args(tmp_path) + ["--map", "unknown=x"])
    with pytest.raises(SystemExit):
        main(_args(tmp_path) + ["--map", "title=a", "--map", "title=b"])


def test_registry_check_is_offline(tmp_path, capsys):
    main(["--check-registry", "--sources-dir", str(tmp_path)])
    assert capsys.readouterr().out.strip() == '{"valid_sources": 0}'


def test_probe_does_not_write_and_verifies_extraction(tmp_path, capsys, monkeypatch):
    content = b'<rss><channel><item><title>Official Alert</title><link>https://example.org/a</link><guid>foo</guid></item></channel></rss>'
    calls = []

    def mock_fetch(url):
        calls.append(url)
        return 200, content, {}, url

    monkeypatch.setattr(onboard_source, "fetch", mock_fetch)
    main(_args(tmp_path) + ["--probe"])
    output = capsys.readouterr()
    assert "Official Alert" in output.err
    assert yaml.safe_load(output.out)["enabled"] is False
    assert calls == ["https://example.org/feed.xml"]
    assert not list(tmp_path.glob("*.yaml"))


def test_probe_rejects_untrusted_item_urls(monkeypatch):
    config = SourceConfig.model_validate({
        "id": "example-advisories", "url": "https://example.org/feed.xml",
        "kind": "rss", "adapter": "rss_v1", "item_kind": "advisory",
        "enabled": False, "interval_minutes": 360,
        "max_requests_per_hour": 4, "max_concurrency": 1,
        "policy": {"reviewed_at": "2026-11-03", "note": "reviewed"},
    })
    monkeypatch.setattr(onboard_source, "fetch", lambda u: (200, b"ok", {}, u))
    monkeypatch.setattr(onboard_source, "extract",
                        lambda *a: [{"id": "1", "title": "bad", "url": "file:///etc/passwd"}])
    with pytest.raises(ValueError, match="HTTPS"):
        probe(config)
