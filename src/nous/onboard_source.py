"""Review, validate, and optionally probe declarative OSINT source candidates.

All registration changes remain Git-reviewed YAML. No database or server writes.
Probes reuse the production SSRF-protected fetcher and extraction adapters.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import yaml

from .adapters import extract
from .fetch import fetch
from .job_postings import fetch_lever_board
from .registry import KINDS, SourceConfig, load_registry

_FIELD_NAMES = {"id", "url", "title", "published", "updated"}
_SELECTORS = {"item", "title", "url"}


def _pairs(values: list[str], *, allowed: set[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for expression in values:
        key, separator, value = expression.partition("=")
        if not separator or key not in allowed or not value or key in result:
            raise ValueError(f"invalid {label}: {expression!r}")
        result[key] = value
    return result


def probe(config: SourceConfig) -> dict:
    """Bounded GET + parse + source record sanity; never expose source bodies."""
    if config.adapter == "lever_jobs_v1":
        runtime_source = SimpleNamespace(
            url=config.url, config=config.model_dump(), adapter=config.adapter
        )
        status, rows, _, _ = fetch_lever_board(runtime_source, fetch)
    else:
        status, body, _, final_url = fetch(config.url)
        if status == 200:
            rows = extract(SimpleNamespace(kind=config.kind, adapter=config.adapter,
                                           config=config.model_dump()), body, final_url)
    if status != 200:
        raise ValueError(f"upstream HTTP status {status}; probe needs 200")
    if not isinstance(rows, list) or not rows:
        raise ValueError("extractor returned no entries")
    valid = 0
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("extractor emitted a non-object")
        if (not isinstance(row.get("id"), str) or not row["id"] or
                not isinstance(row.get("title"), str) or not row["title"].strip() or
                len(row["title"]) > 1000 or not isinstance(row.get("url"), str)):
            raise ValueError("entry has missing/invalid id, title or URL")
        url = urlsplit(row["url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise ValueError("entry URL must be an absolute safe HTTPS URL")
        valid += 1
    return {"source": config.id, "status": status, "entries": valid,
            "sample": [{"title": row["title"][:120], "url": row["url"]}
                       for row in rows[:3]]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Stage or probe a reviewed registry entry")
    parser.add_argument("--check-registry", action="store_true",
                        help="Validate all tracked source YAML entries; no network requests")
    parser.add_argument("--probe-id", help="Probe an already tracked source by its ID")
    parser.add_argument("--id")
    parser.add_argument("--url")
    parser.add_argument("--kind", choices=("rss", "json_api", "html"))
    parser.add_argument("--adapter")
    parser.add_argument("--item-kind", choices=sorted(KINDS))
    parser.add_argument("--organization")
    parser.add_argument("--interval-minutes", type=int, default=360)
    parser.add_argument("--max-requests-per-hour", type=int, default=4)
    parser.add_argument("--max-concurrency", type=int, default=1)
    parser.add_argument("--max-pages", type=int, default=1)
    parser.add_argument("--reviewed-at", help="YYYY-MM-DD, reviewed by operator")
    parser.add_argument("--terms-url")
    parser.add_argument("--robots-url")
    parser.add_argument("--policy-note")
    parser.add_argument("--json-path")
    parser.add_argument("--map", dest="field_map", action="append", default=[],
                        metavar="FIELD=SOURCE_FIELD")
    parser.add_argument("--selector", action="append", default=[],
                        metavar="FIELD=CSS_SELECTOR")
    parser.add_argument("--sources-dir", type=Path, default=Path("sources"))
    parser.add_argument("--probe", action="store_true", help="Fetch and parse once without mutation")
    parser.add_argument("--write", action="store_true", help="Write a disabled YAML candidate")
    args = parser.parse_args(argv)
    try:
        known = load_registry(args.sources_dir)
        if args.check_registry:
            if args.probe_id or args.write or args.probe or args.id:
                parser.error("--check-registry cannot be combined with other operations")
            print(json.dumps({"valid_sources": len(known)}))
            return
        if args.probe_id:
            if args.write or args.id or args.probe:
                parser.error("--probe-id cannot be combined with candidate options")
            config = next((s for s in known if s.id == args.probe_id), None)
            if config is None:
                parser.error(f"unknown source ID: {args.probe_id}")
            print(json.dumps(probe(config), ensure_ascii=False))
            return
        required = ("id", "url", "kind", "item_kind", "reviewed_at", "policy_note")
        missing = [name.replace("_", "-") for name in required if not getattr(args, name)]
        if missing:
            parser.error("missing required options: " + ", ".join("--" + n for n in missing))
        adapter = args.adapter or {
            "rss": "rss_v1", "json_api": "json_v1", "html": "html_v1"
        }[args.kind]
        selectors = _pairs(args.selector, allowed=_SELECTORS, label="selector")
        field_map = _pairs(args.field_map, allowed=_FIELD_NAMES, label="map")
        config = SourceConfig.model_validate({
            "id": args.id, "url": args.url, "kind": args.kind,
            "adapter": adapter, "item_kind": args.item_kind,
            "organization": args.organization, "interval_minutes": args.interval_minutes,
            "max_requests_per_hour": args.max_requests_per_hour,
            "max_concurrency": args.max_concurrency, "max_pages": args.max_pages,
            "enabled": False,
            "policy": {"reviewed_at": args.reviewed_at, "terms_url": args.terms_url,
                       "robots_url": args.robots_url, "content_storage": "metadata_only",
                       "note": args.policy_note},
            "selectors": selectors, "json_path": args.json_path, "field_map": field_map,
        })
        if config.id in {entry.id for entry in known}:
            parser.error(f"source ID already registered: {config.id}")
        target = args.sources_dir / f"{config.id}.yaml"
        if target.exists():
            parser.error(f"source file already exists: {target}")
        if args.probe:
            print(json.dumps(probe(config), ensure_ascii=False), file=sys.stderr)
        output = yaml.safe_dump(config.model_dump(exclude_none=True),
                                sort_keys=False, allow_unicode=True)
        if args.write:
            args.sources_dir.mkdir(parents=True, exist_ok=True)
            with target.open("x", encoding="utf-8") as handle:
                handle.write(output)
            print(f"Staged disabled candidate: {target}")
        else:
            sys.stdout.write(output)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
