"""Prepare a reviewed source registry entry without mutating the live database.

Example:
  python -m nous.onboard_source --id vendor-advisories --url https://example.org/feed.xml \
    --kind rss --item-kind advisory --organization Vendor \
    --terms-url https://example.org/terms --policy-note "Reviewed official feed"
"""
import argparse
import sys
from pathlib import Path

import yaml

from .registry import SourceConfig, load_registry


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate and stage a source definition for Git review")
    parser.add_argument("--id", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--kind", choices=("rss", "json_api", "html"), required=True)
    parser.add_argument("--adapter", help="Explicit adapter; default rss_v1 or json_v1")
    parser.add_argument("--item-kind", required=True)
    parser.add_argument("--organization")
    parser.add_argument("--interval-minutes", type=int, default=360)
    parser.add_argument("--max-requests-per-hour", type=int, default=4)
    parser.add_argument("--max-concurrency", type=int, default=1)
    parser.add_argument("--reviewed-at", required=True, help="YYYY-MM-DD, reviewed by operator")
    parser.add_argument("--terms-url")
    parser.add_argument("--robots-url")
    parser.add_argument("--policy-note", required=True)
    parser.add_argument("--sources-dir", type=Path, default=Path("sources"))
    parser.add_argument("--write", action="store_true", help="Write a disabled YAML candidate")
    args = parser.parse_args(argv)

    adapter = args.adapter or {"rss": "rss_v1", "json_api": "json_v1", "html": "html_v1"}[args.kind]
    config = SourceConfig.model_validate({
        "id": args.id, "url": args.url, "kind": args.kind,
        "adapter": adapter, "item_kind": args.item_kind,
        "organization": args.organization, "interval_minutes": args.interval_minutes,
        "max_requests_per_hour": args.max_requests_per_hour,
        "max_concurrency": args.max_concurrency, "enabled": False,
        "policy": {"reviewed_at": args.reviewed_at, "terms_url": args.terms_url,
                   "robots_url": args.robots_url, "content_storage": "metadata_only",
                   "note": args.policy_note},
    })
    if config.kind == "html":
        parser.error("HTML requires site-specific selectors; author and validate YAML manually")
    if config.kind == "json_api":
        parser.error("JSON API requires json_path/field_map review; author and validate YAML manually")
    existing = {entry.id for entry in load_registry(args.sources_dir)}
    if config.id in existing:
        parser.error(f"source ID already registered: {config.id}")
    target = args.sources_dir / f"{config.id}.yaml"
    if target.exists():
        parser.error(f"source file already exists: {target}")
    output = yaml.safe_dump(config.model_dump(exclude_none=True), sort_keys=False, allow_unicode=True)
    if not args.write:
        sys.stdout.write(output)
        return
    args.sources_dir.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as handle:
        handle.write(output)
    print(f"Staged disabled candidate: {target}")


if __name__ == "__main__":
    main()
