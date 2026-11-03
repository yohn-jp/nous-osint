from pathlib import Path

import pytest
import yaml

from nous.onboard_source import main


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
    with pytest.raises((SystemExit, ValueError)):
        main(args + ["--write"])
    assert not list(tmp_path.glob("*.yaml"))
