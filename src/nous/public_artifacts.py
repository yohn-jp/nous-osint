"""Passive GitHub repository-index snapshots for public CVE references.

No exploit payloads or template content are fetched or executed. The only
network requests use pinned, fixed GitHub API repository paths. A complete
(non-truncated) directory tree is required before recording presence/absence.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from .cve_index import valid_cve_id
from .fetch import fetch
from .models import (CveItemLink, PublicArtifactContent,
                     PublicArtifactObservation, PublicArtifactPollState)

log = logging.getLogger(__name__)

# The Nuclei scope is specifically HTTP CVE templates. Network/DNS templates
# are not evaluated and absence must never be read as "no Nuclei template".
PROVIDERS = {
    "trickest": ("trickest", "cve", (), "md"),
    "nuclei_http": ("projectdiscovery", "nuclei-templates", ("http", "cves"), "yaml"),
}
_API_ROOT = "https://api.github.com/repos"
_MAX_TREE_BYTES = 7_000_000
_MAX_TREE_ENTRIES = 50000
_MAX_FILES_PER_CVE = 64
_MAX_INDEXED_CVES = 40000
_MAX_TRACKED_YEARS = 16
_FRESH = timedelta(hours=72)
_SHA = re.compile(r"^[a-f0-9]{40}$")
_TRICKEST_NAME = re.compile(r"^(CVE-[0-9]{4}-[0-9]{4,})[.]md$")
_NUCLEI_NAME = re.compile(r"^(CVE-[0-9]{4}-[0-9]{4,})(?:-[a-zA-Z0-9_-]{1,60})?[.]ya?ml$")


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _get_json(url: str) -> dict:
    # All URLs originate from fixed repository identifiers and SHA-only refs.
    if not url.startswith(_API_ROOT + "/"):
        raise ValueError("unapproved GitHub API host")
    status, content, _headers, _final_url = fetch(url)
    if status != 200 or len(content) > _MAX_TREE_BYTES:
        raise ValueError("GitHub tree unavailable or oversized")
    try:
        payload = json.loads(content)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("GitHub tree response not JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("GitHub tree response has invalid shape")
    return payload


def _tree(repo: str, sha: str) -> list[dict]:
    if not _SHA.fullmatch(sha):
        raise ValueError("invalid Git tree hash")
    payload = _get_json(f"{_API_ROOT}/{repo}/git/trees/{sha}")
    if (payload.get("sha") != sha or payload.get("truncated") is not False
            or not isinstance(payload.get("tree"), list)
            or len(payload["tree"]) > _MAX_TREE_ENTRIES):
        raise ValueError("Git tree incomplete or inconsistent")
    seen = set()
    for entry in payload["tree"]:
        if not isinstance(entry, dict):
            raise ValueError("invalid Git tree entry")
        name, child_sha = entry.get("path"), entry.get("sha")
        if (not isinstance(name, str) or not 1 <= len(name) <= 160
                or "/" in name or name in {".", ".."} or name in seen
                or not isinstance(child_sha, str) or not _SHA.fullmatch(child_sha)
                or entry.get("type") not in {"tree", "blob"}):
            raise ValueError("unsafe or ambiguous Git tree entry")
        seen.add(name)
    return payload["tree"]


def _child(entries: list[dict], name: str) -> str | None:
    for entry in entries:
        if entry["path"] == name:
            if entry["type"] != "tree":
                raise ValueError("expected Git repository directory")
            return entry["sha"]
    return None


def _indexed_files(provider: str, year: int, entries: list[dict]) -> dict:
    prefix = (f"{year}/" if provider == "trickest" else f"http/cves/{year}/")
    pattern = _TRICKEST_NAME if provider == "trickest" else _NUCLEI_NAME
    indexed: dict[str, list[dict]] = {}
    for entry in entries:
        if entry["type"] != "blob" or entry.get("mode") != "100644":
            continue
        matched = pattern.fullmatch(entry["path"])
        if matched is None:
            continue
        cve_id = matched.group(1)
        if not valid_cve_id(cve_id) or int(cve_id[4:8]) != year:
            raise ValueError("file name has conflicting CVE year")
        references = indexed.setdefault(cve_id, [])
        if len(references) >= _MAX_FILES_PER_CVE:
            raise ValueError("too many Git references for one CVE")
        references.append({"path": prefix + entry["path"], "blob_sha": entry["sha"]})
        if len(indexed) > _MAX_INDEXED_CVES:
            raise ValueError("Git catalog exceeds reviewed storage bound")
    return {key: sorted(value, key=lambda item: item["path"])
            for key, value in sorted(indexed.items())}


def fetch_repository_index(provider: str, year: int) -> tuple[str, dict]:
    """Return a complete verified year directory index and immutable commit SHA."""
    if provider not in PROVIDERS or not 1999 <= year <= datetime.now(timezone.utc).year + 1:
        raise ValueError("unsupported index provider/year")
    owner, repo_name, base, _extension = PROVIDERS[provider]
    repo = f"{owner}/{repo_name}"
    ref = _get_json(f"{_API_ROOT}/{repo}/git/ref/heads/main").get("object")
    if (not isinstance(ref, dict) or ref.get("type") != "commit"
            or not isinstance(ref.get("sha"), str) or not _SHA.fullmatch(ref["sha"])):
        raise ValueError("GitHub branch did not resolve to a commit")
    commit_sha = ref["sha"]
    # Git trees accepts commit SHAs, then nested subtrees are pinned by hash.
    commit = _get_json(f"{_API_ROOT}/{repo}/git/commits/{commit_sha}")
    if commit.get("sha") != commit_sha or not isinstance(commit.get("tree"), dict):
        raise ValueError("GitHub commit mismatch")
    root_sha = commit["tree"].get("sha")
    if not isinstance(root_sha, str) or not _SHA.fullmatch(root_sha):
        raise ValueError("invalid Git root tree")
    entries = _tree(repo, root_sha)
    for directory in base:
        child = _child(entries, directory)
        if child is None:
            raise ValueError("reviewed repository directory no longer exists")
        entries = _tree(repo, child)
    selected = _child(entries, str(year))
    if selected is None:
        return commit_sha, {}
    return commit_sha, _indexed_files(provider, year, _tree(repo, selected))


def _tracked_years(db) -> list[int]:
    # Restrict the number of current CVE links read per scheduling tick.
    year_column = func.substr(CveItemLink.cve_id, 5, 4)
    rows = db.scalars(select(year_column).distinct().order_by(year_column.desc())
                      .limit(_MAX_TRACKED_YEARS + 1)).all()
    current_year = datetime.now(timezone.utc).year
    years = [int(value) for value in rows
             if isinstance(value, str) and len(value) == 4
             and value.isdigit() and 1999 <= int(value) <= current_year + 1]
    return years[:_MAX_TRACKED_YEARS]


def refresh_public_artifacts(factory, *, current: datetime | None = None) -> bool:
    """Poll at most one provider/year per scheduler tick, with durable backoff."""
    started = _utc(current or datetime.now(timezone.utc))
    with factory() as db:
        years = _tracked_years(db)
        # The regular service has a single scheduler process. Per-row leases
        # protect a restarted/duplicated worker after the first initialization.
        for provider in PROVIDERS:
            for year in years:
                if db.get(PublicArtifactPollState, (provider, year)) is None:
                    db.add(PublicArtifactPollState(
                        provider=provider, year=year,
                        next_due_at=started - timedelta(seconds=1),
                    ))
        db.commit()
    with factory() as db:
        selected = db.scalar(select(PublicArtifactPollState).where(
            PublicArtifactPollState.next_due_at <= started,
        ).order_by(
            PublicArtifactPollState.next_due_at,
            PublicArtifactPollState.year.desc(),
            PublicArtifactPollState.provider,
        ).with_for_update(skip_locked=True).limit(1))
        if selected is None:
            return False
        provider, year = selected.provider, selected.year
        selected.next_due_at = started + timedelta(minutes=40)
        db.commit()

    try:
        commit_sha, index = fetch_repository_index(provider, year)
        observed = _utc(current or datetime.now(timezone.utc))
        canonical = json.dumps(index, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        with factory() as db:
            if db.get(PublicArtifactContent, digest) is None:
                db.add(PublicArtifactContent(digest=digest, entries=index))
                db.flush()
            db.add(PublicArtifactObservation(
                id=str(uuid.uuid4()), provider=provider, year=year,
                observed_at=observed, digest=digest, commit_sha=commit_sha,
            ))
            state = db.get(PublicArtifactPollState, (provider, year))
            state.last_success_at = observed
            state.last_error = None
            state.next_due_at = observed + timedelta(hours=24)
            db.commit()
        log.info("Public CVE index %s/%d: %d CVEs", provider, year, len(index))
    except Exception as exc:
        with factory() as db:
            state = db.get(PublicArtifactPollState, (provider, year))
            if state is not None:
                state.last_error = type(exc).__name__[:60]
                state.next_due_at = started + timedelta(hours=2)
                db.commit()
        log.warning("Public CVE index refresh rejected: %s/%s %s",
                    provider, year, type(exc).__name__)
    return True


def repository_artifacts_as_of(db, cve_id: str, cutoff: datetime) -> list[dict]:
    """Source-attributed, as-of metadata; unknown is not proof of no PoC."""
    if not valid_cve_id(cve_id):
        raise ValueError("invalid CVE identity")
    cutoff = _utc(cutoff)
    year = int(cve_id[4:8])
    results = []
    for provider, (owner, name, _base, _ext) in PROVIDERS.items():
        row = db.scalar(select(PublicArtifactObservation).where(
            PublicArtifactObservation.provider == provider,
            PublicArtifactObservation.year == year,
            PublicArtifactObservation.observed_at <= cutoff,
        ).order_by(PublicArtifactObservation.observed_at.desc(),
                   PublicArtifactObservation.id.desc()).limit(1))
        observed = _utc(row.observed_at) if row else None
        content = db.get(PublicArtifactContent, row.digest) if row else None
        catalog = content.entries if content is not None else None
        files = catalog.get(cve_id, []) if isinstance(catalog, dict) else []
        pattern = _TRICKEST_NAME if provider == "trickest" else _NUCLEI_NAME
        expected_prefix = f"{year}/" if provider == "trickest" else f"http/cves/{year}/"
        valid_files = (
            isinstance(catalog, dict) and isinstance(files, list)
            and len(files) <= _MAX_FILES_PER_CVE and all(
                isinstance(entry, dict)
                and isinstance(entry.get("path"), str)
                and entry["path"].startswith(expected_prefix)
                and pattern.fullmatch(entry["path"][len(expected_prefix):]) is not None
                and pattern.fullmatch(entry["path"][len(expected_prefix):]).group(1) == cve_id
                and isinstance(entry.get("blob_sha"), str)
                and _SHA.fullmatch(entry["blob_sha"])
                for entry in files
            )
        )
        refs = [{
            "url": f"https://github.com/{owner}/{name}/blob/{row.commit_sha}/{entry['path']}",
            "path": entry["path"], "blob_sha": entry["blob_sha"],
        } for entry in files] if row and valid_files else []
        if not row or not valid_files:
            status = "unknown"
        elif cutoff - observed > _FRESH:
            status = "stale"
        else:
            status = "indexed" if refs else "not_indexed"
        results.append({
            "provider": provider, "scope": ("Public PoC reference index"
                                           if provider == "trickest" else "Nuclei HTTP CVE templates"),
            "status": status,
            "observed_at": row.observed_at if row else None,
            "commit_sha": row.commit_sha if row else None,
            "repository_url": f"https://github.com/{owner}/{name}",
            "references": refs,
            "references_truncated": False,
        })
    return results
