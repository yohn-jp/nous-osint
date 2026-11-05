"""Singleton durable report queue, lease fencing and recoverable Astro release publisher."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import ctypes
import errno
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import threading
import time
import uuid

from sqlalchemy import and_, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from .cve_index import authoritative_kev_version
from .db import session_factory
from .models import (
    CveItemVersionLink,
    Item,
    ItemVersion,
    Report,
    ReportEvidence,
    ReportRun,
    ReportSchedule,
    ReportSiteState,
    Source,
    now,
)
from .report_pipeline import (
    CodexRunner,
    ReportError,
    ReportSkipped,
    _all_article_evidence,
    _json_bytes,
    build_evidence_bundle,
    build_static_release,
    release_manifest,
    run_editorial_pipeline,
)
from .report_templates import normalize_parameters, resolve_template

log = logging.getLogger("nous.report_worker")
_MAX_ATTEMPTS = 2
_LEASE_SECONDS = 300
_HEARTBEAT_SECONDS = 30
_MAX_ARCHIVE_REPORTS = 1000
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_AT_FDCWD = -100
_RENAME_EXCHANGE = 2


class LeaseLost(RuntimeError):
    pass


def _path_env(name: str, default: str) -> Path:
    path = Path(os.getenv(name, default))
    if path.is_symlink():
        raise ReportError("report_path_symlink_rejected")
    return path.resolve(strict=False)


def private_root() -> Path:
    root = _path_env("NOUS_REPORT_PRIVATE_DIR", "/var/lib/nous-reports/private")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or not root.is_dir():
        raise ReportError("private_artifact_root_invalid")
    try:
        root.chmod(0o700)
    except PermissionError:
        pass
    return root


def public_root() -> Path:
    root = _path_env("NOUS_REPORT_SITE_DIR", "/var/lib/nous-reports/site")
    root.mkdir(parents=True, exist_ok=True, mode=0o755)
    if root.is_symlink() or not root.is_dir():
        raise ReportError("report_site_root_invalid")
    (root / "releases").mkdir(exist_ok=True, mode=0o755)
    (root / "_astro").mkdir(exist_ok=True, mode=0o755)
    (root / ".manifests").mkdir(exist_ok=True, mode=0o700)
    return root


@contextmanager
def _publication_lock(site_root: Path):
    lock_path = site_root / ".publish.lock"
    if lock_path.is_symlink():
        raise ReportError("publication_lock_unsafe")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _uuid(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ReportError("invalid_run_id") from exc


def _fsync_write(path: Path, content: bytes, mode: int = 0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        dirfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        temp.unlink(missing_ok=True)


def _safe_private_path(root: Path, relative: str) -> Path:
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or any(part in {"..", "."} for part in candidate.parts):
        raise ReportError("private_artifact_path_invalid")
    path = root.joinpath(*candidate.parts)
    resolved = path.resolve(strict=False)
    if root not in resolved.parents or path.is_symlink():
        raise ReportError("private_artifact_path_invalid")
    return path


def _bundle_digest(bundle: dict) -> str:
    content = dict(bundle)
    given = content.pop("sha256", None)
    digest = hashlib.sha256(_json_bytes(content)).hexdigest()
    if given != digest:
        raise ReportError("bundle_digest_mismatch")
    return digest


def _read_or_build_bundle(factory, claim: dict) -> dict:
    root = private_root()
    run_id = _uuid(claim["id"])
    if claim.get("bundle_path"):
        path = _safe_private_path(root, claim["bundle_path"])
        try:
            if path.stat().st_size > 2_097_152:
                raise ReportError("stored_bundle_too_large")
            bundle = json.loads(path.read_text(encoding="utf-8"))
        except ReportError:
            raise
        except (OSError, ValueError) as exc:
            raise ReportError("stored_bundle_corrupt") from exc
        if _bundle_digest(bundle) != claim.get("bundle_sha256"):
            raise ReportError("stored_bundle_corrupt")
        return bundle

    cutoff = claim.get("observed_cutoff") or now()
    bundle = build_evidence_bundle(factory, claim["template_id"], claim["parameters"],
                                   cutoff, claim["template_snapshot"])
    bundle_path = root / "runs" / run_id / "bundle.json"
    content = _json_bytes(bundle)
    _fsync_write(bundle_path, content)
    with factory() as db:
        row = db.scalar(select(ReportRun).where(
            ReportRun.id == run_id, ReportRun.lease_token == claim["lease_token"]
        ).with_for_update())
        lease_until = row.lease_until if row is not None else None
        if lease_until is not None and lease_until.tzinfo is None:
            lease_until = lease_until.replace(tzinfo=timezone.utc)
        if row is None or lease_until is None or lease_until <= now():
            raise LeaseLost()
        row.observed_cutoff = cutoff
        row.bundle_sha256 = bundle["sha256"]
        row.bundle_path = str(bundle_path.relative_to(root))
        row.stage = "evidence"
        row.lease_until = now() + timedelta(seconds=_LEASE_SECONDS)
        db.commit()
    return bundle


def _claim_run(factory) -> dict | None:
    for _ in range(3):
        with factory() as db:
            current = now()
            expired = and_(ReportRun.state.in_(
                ("leased", "running", "validating", "publishing")),
                ReportRun.lease_until.is_not(None), ReportRun.lease_until < current)
            row = db.scalar(select(ReportRun).where(
                ReportRun.available_at <= current,
                (ReportRun.state == "queued") | expired,
            ).order_by(ReportRun.available_at, ReportRun.created_at, ReportRun.id)
              .with_for_update(skip_locked=True).limit(1))
            if row is None:
                return None
            if row.attempts >= _MAX_ATTEMPTS:
                row.state = "failed"
                row.stage = "retry_exhausted"
                row.error_code = row.error_code or "attempt_limit"
                row.finished_at = current
                row.lease_until = None
                row.lease_token = None
                db.commit()
                continue
            token = str(uuid.uuid4())
            row.state = "leased"
            row.stage = "claimed"
            row.attempts += 1
            row.lease_until = current + timedelta(seconds=_LEASE_SECONDS)
            row.lease_token = token
            row.started_at = row.started_at or current
            db.commit()
            return {
                "id": row.id,
                "lease_token": token,
                "template_id": row.template_id,
                "template_revision": row.template_revision,
                "template_snapshot": row.template_snapshot,
                "parameters": row.parameters,
                "attempts": row.attempts,
                "observed_cutoff": row.observed_cutoff,
                "bundle_sha256": row.bundle_sha256,
                "bundle_path": row.bundle_path,
                "stage_artifacts": row.stage_artifacts or {},
            }
    return None


class _LeaseHeartbeat:
    def __init__(self, factory, run_id: str, token: str):
        self.factory, self.run_id, self.token = factory, run_id, token
        self.stop_event = threading.Event()
        self.lost = threading.Event()
        self.thread = threading.Thread(target=self._run, name="report-lease-heartbeat", daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=2)

    def _run(self):
        while not self.stop_event.wait(_HEARTBEAT_SECONDS):
            try:
                with self.factory() as db:
                    result = db.execute(update(ReportRun).where(
                        ReportRun.id == self.run_id,
                        ReportRun.lease_token == self.token,
                        ReportRun.state.in_(("leased", "running", "validating", "publishing")),
                    ).values(lease_until=now() + timedelta(seconds=_LEASE_SECONDS)))
                    db.commit()
                if result.rowcount != 1:
                    self.lost.set()
                    return
            except SQLAlchemyError:
                self.lost.set()
                return

    def assert_owned(self):
        if self.lost.is_set():
            raise LeaseLost()


def _assert_lease(db, run_id: str, token: str) -> ReportRun:
    row = db.scalar(select(ReportRun).where(
        ReportRun.id == run_id, ReportRun.lease_token == token
    ).with_for_update())
    lease_until = row.lease_until if row is not None else None
    if lease_until is not None and lease_until.tzinfo is None:
        lease_until = lease_until.replace(tzinfo=timezone.utc)
    if row is None or lease_until is None or lease_until <= now():
        raise LeaseLost()
    return row


def _persist_stage(factory, run_id: str, token: str, name: str, value: dict):
    with factory() as db:
        row = _assert_lease(db, run_id, token)
        artifacts = dict(row.stage_artifacts or {})
        artifacts[name] = value
        row.stage_artifacts = artifacts
        row.stage = name
        row.state = "running"
        row.lease_until = now() + timedelta(seconds=_LEASE_SECONDS)
        db.commit()
    root = private_root()
    path = root / "runs" / _uuid(run_id) / "stages" / f"{name}.json"
    _fsync_write(path, _json_bytes(value))


def _set_failure(factory, claim: dict, *, state: str, code: str, retryable: bool):
    with factory() as db:
        row = db.scalar(select(ReportRun).where(
            ReportRun.id == claim["id"], ReportRun.lease_token == claim["lease_token"]
        ).with_for_update())
        if row is None:
            return
        row.error_code = code[:64]
        row.lease_token = None
        row.lease_until = None
        if retryable and row.attempts < _MAX_ATTEMPTS:
            row.state = "queued"
            row.stage = "retry_wait"
            row.available_at = now() + timedelta(seconds=min(300, 30 * (2 ** row.attempts)))
            row.finished_at = None
        else:
            row.state = state
            row.stage = state
            row.finished_at = now()
        db.commit()


def _site_article(report: Report) -> dict:
    category = report.category
    return {
        **report.article,
        "slug": report.slug,
        "category": category,
        "published_at": report.published_at.astimezone(timezone.utc).isoformat(),
        "url": f"/reports/{category}/{report.slug}/",
    }


def _site_articles(db, candidate: dict | None = None) -> list[dict]:
    reports = db.scalars(select(Report).order_by(Report.published_at.desc()).limit(
        _MAX_ARCHIVE_REPORTS + 1
    )).all()
    if len(reports) > _MAX_ARCHIVE_REPORTS or (
        candidate is not None and len(reports) >= _MAX_ARCHIVE_REPORTS
    ):
        # Reject before writing the candidate or its pending release intent.
        # Otherwise publication #1001 succeeds and blocks every subsequent
        # reconciliation tick, including the initial recovery path.
        raise ReportError("report_archive_limit_exceeded")
    values = [_site_article(report) for report in reports]
    if candidate is not None:
        values.append(candidate)
    return values


def _exchange_directories(left: Path, right: Path):
    """Atomically replace an existing release directory without a broken pointer."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise ReportError("release_atomic_repair_unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p,
                          ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        _AT_FDCWD, os.fsencode(left), _AT_FDCWD, os.fsencode(right), _RENAME_EXCHANGE,
    )
    if result != 0:
        code = ctypes.get_errno()
        if code in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
            raise ReportError("release_atomic_repair_unavailable")
        raise OSError(code, os.strerror(code), str(right))


def _remove_release_tree(path: Path):
    """Make a swapped-out immutable release removable, then delete it safely."""
    if path.is_symlink():
        path.unlink()
        return
    if not path.exists():
        return
    for child in path.rglob("*"):
        if child.is_symlink():
            continue
        try:
            child.chmod(0o700 if child.is_dir() else 0o600)
        except OSError:
            pass
    try:
        path.chmod(0o700)
    except OSError:
        pass
    shutil.rmtree(path)


def _write_release(site_root: Path, dist: Path, assets: list[Path], digest: str) -> dict:
    if not _DIGEST.fullmatch(digest):
        raise ReportError("release_digest_invalid")
    release_dir = site_root / "releases" / digest
    temp_release = site_root / "releases" / (".stage-" + uuid.uuid4().hex)
    if release_dir.exists() and (release_dir.is_symlink() or not release_dir.is_dir()):
        raise ReportError("release_path_unsafe")
    if not release_dir.exists() or not _verify_release(site_root, digest):
        temp_release.mkdir(mode=0o700)
        try:
            for source in sorted(dist.rglob("*.html")):
                relative = source.relative_to(dist)
                destination = temp_release / relative
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                shutil.copyfile(source, destination)
                destination.chmod(0o444)
            for directory in sorted((p for p in temp_release.rglob("*") if p.is_dir()),
                                    key=lambda p: len(p.parts), reverse=True):
                directory.chmod(0o555)
            temp_release.chmod(0o555)
            if release_dir.exists():
                _exchange_directories(temp_release, release_dir)
                _remove_release_tree(temp_release)
            else:
                os.replace(temp_release, release_dir)
        except Exception:
            if temp_release.exists():
                try:
                    _remove_release_tree(temp_release)
                except OSError:
                    pass
            raise

    for source in assets:
        if source.is_symlink() or not re.fullmatch(r"[A-Za-z0-9._-]{1,255}", source.name):
            raise ReportError("release_asset_name_unsafe")
        target = site_root / "_astro" / source.name
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ReportError("release_asset_collision")
        if target.exists():
            matches = hashlib.sha256(target.read_bytes()).digest() == hashlib.sha256(source.read_bytes()).digest()
        else:
            matches = False
        if not matches:
            temp_asset = target.with_name(target.name + ".tmp-" + uuid.uuid4().hex)
            shutil.copyfile(source, temp_asset)
            temp_asset.chmod(0o444)
            os.replace(temp_asset, target)

    manifest = release_manifest(dist, assets, digest)
    _fsync_write(site_root / ".manifests" / f"{digest}.json", _json_bytes(manifest), 0o600)
    if not _verify_release(site_root, digest):
        raise ReportError("release_verification_failed")
    return manifest


def _manifest_file_path(site_root: Path, digest: str, relative: str) -> Path:
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ReportError("release_manifest_invalid")
    if path.parts and path.parts[0] == "_astro":
        if len(path.parts) != 2:
            raise ReportError("release_manifest_invalid")
        return site_root / "_astro" / path.parts[1]
    return site_root / "releases" / digest / Path(*path.parts)


def _verify_release(site_root: Path, digest: str) -> bool:
    manifest_path = site_root / ".manifests" / f"{digest}.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("digest") != digest or not isinstance(manifest.get("files"), dict):
            return False
        hash_state = hashlib.sha256()
        for relative, expected in sorted(manifest["files"].items()):
            if not isinstance(relative, str) or not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
                return False
            path = _manifest_file_path(site_root, digest, relative)
            if path.is_symlink() or not path.is_file():
                return False
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != expected:
                return False
            hash_state.update(relative.encode())
            hash_state.update(b"\0")
            hash_state.update(data)
            hash_state.update(b"\0")
        return hash_state.hexdigest() == digest
    except (OSError, ValueError, KeyError, TypeError, ReportError):
        return False


def _release_has_404_page(site_root: Path, digest: str) -> bool:
    """Require the renderer's not-found page in the immutable release contract."""
    try:
        manifest = json.loads(
            (site_root / ".manifests" / f"{digest}.json").read_text(encoding="utf-8")
        )
        files = manifest.get("files")
        html_files = manifest.get("html_files")
        return (
            isinstance(files, dict)
            and "404.html" in files
            and isinstance(html_files, list)
            and "404.html" in html_files
        )
    except (OSError, ValueError, TypeError):
        return False


def _is_current_contract_release(site_root: Path, digest: str) -> bool:
    return _verify_release(site_root, digest) and _release_has_404_page(site_root, digest)


def _current_digest(site_root: Path) -> str | None:
    current = site_root / "current"
    if not current.exists() and not current.is_symlink():
        return None
    if not current.is_symlink():
        raise ReportError("report_current_not_symlink")
    target = os.readlink(current)
    match = re.fullmatch(r"releases/([a-f0-9]{64})", target)
    if not match:
        raise ReportError("report_current_target_invalid")
    return match.group(1)


def _promote(site_root: Path, digest: str):
    if not _verify_release(site_root, digest):
        raise ReportError("release_verification_failed")
    temp = site_root / (".current-" + uuid.uuid4().hex)
    os.symlink(f"releases/{digest}", temp)
    os.replace(temp, site_root / "current")


def _persist_site_state(factory, digest: str):
    with factory() as db:
        row = db.scalar(select(ReportSiteState).where(ReportSiteState.id == 1).with_for_update())
        if row is None:
            row = ReportSiteState(id=1, active_digest=digest, pending_digest=None,
                                  pending_run_id=None, updated_at=now())
            db.add(row)
        else:
            row.active_digest = digest
            row.pending_digest = None
            row.pending_run_id = None
            row.updated_at = now()
        db.commit()


def _ensure_current_release_locked(factory, site_root: Path) -> str:
    """Recover durable intents and file/DB pointer mismatches under publication lock."""
    with factory() as db:
        state = db.get(ReportSiteState, 1)
        expected = state.active_digest if state else None
        pending_run_id = state.pending_run_id if state else None
        pending_digest = state.pending_digest if state else None
        reports = _site_articles(db)
    if pending_digest:
        # An intent is committed before promotion. If it remains at recovery
        # time, the worker did not commit the report transaction; restore the
        # last committed digest before accepting another publication.
        if expected and _is_current_contract_release(site_root, expected):
            _promote(site_root, expected)
        elif expected:
            private = private_root()
            build_root = private / "build-recovery"
            dist = assets = None
            try:
                dist, assets, digest = build_static_release(reports, build_root)
                _write_release(site_root, dist, assets, digest)
                _promote(site_root, digest)
                expected = digest
            finally:
                if dist is not None:
                    shutil.rmtree(dist, ignore_errors=True)
                shutil.rmtree(build_root, ignore_errors=True)
        else:
            current = site_root / "current"
            if current.is_symlink():
                current.unlink()
        with factory() as db:
            state = db.scalar(select(ReportSiteState).where(
                ReportSiteState.id == 1).with_for_update())
            if (state is not None and state.pending_run_id == pending_run_id and
                    state.pending_digest == pending_digest):
                state.active_digest = expected or state.active_digest
                state.pending_digest = None
                state.pending_run_id = None
                state.updated_at = now()
                db.commit()
        if expected is None:
            # A first publication should only happen after an initial empty
            # release has been persisted, but repair if old state is missing.
            return _ensure_current_release_locked(factory, site_root)
    actual = _current_digest(site_root)
    if expected and actual == expected and _is_current_contract_release(site_root, expected):
        return expected
    if expected and _is_current_contract_release(site_root, expected):
        _promote(site_root, expected)
        return expected
    # The selected release is absent or corrupt. Rebuild the complete archive
    # from immutable DB article JSON before changing the public pointer.
    private = private_root()
    build_root = private / "build-recovery"
    dist = assets = None
    try:
        dist, assets, digest = build_static_release(reports, build_root)
        _write_release(site_root, dist, assets, digest)
        _promote(site_root, digest)
        _persist_site_state(factory, digest)
        return digest
    finally:
        if dist is not None:
            shutil.rmtree(dist, ignore_errors=True)
        shutil.rmtree(build_root, ignore_errors=True)


def ensure_current_release(factory) -> str:
    """Recover stale-contract releases from DB articles and create an initial index."""
    site_root = public_root()
    with _publication_lock(site_root):
        return _ensure_current_release_locked(factory, site_root)


def _slug_for(template: dict, parameters: dict, run_id: str, published_at: datetime) -> str:
    suffix = uuid.UUID(run_id).hex[:12]
    if template["id"] == "security-daily":
        slug = f"{parameters['target_date']}-security-daily-{suffix}"
    else:
        slug = f"{parameters['cve_id'].lower()}-deep-dive-{published_at:%Y%m%d}-{suffix}"
    if len(slug) > 128 or not _SLUG.fullmatch(slug):
        raise ReportError("report_slug_invalid")
    return slug


def _used_evidence(article: dict) -> set[str]:
    result = set(_all_article_evidence(article))
    if isinstance(article.get("cve"), dict):
        result.update(article["cve"].get("evidence_ids", []))
    return result


def _evidence_db_rows(db, report_id: str, article: dict, bundle: dict) -> list[ReportEvidence]:
    evidence = {row["evidence_id"]: row for row in bundle["evidence"]}
    used = _used_evidence(article)
    if not used or any(evidence_id not in evidence for evidence_id in used):
        raise ReportError("publication_evidence_invalid")
    result = []
    for evidence_id in sorted(used):
        item_data = evidence[evidence_id]
        item = db.get(Item, item_data["item_id"])
        version = db.get(ItemVersion, item_data["item_version_id"])
        if (item is None or version is None or version.item_id != item.id or
                version.sha256 != item_data["item_version_sha256"]):
            raise ReportError("immutable_evidence_version_mismatch")
        source = db.get(Source, item.source_id)
        attrs = version.attributes if isinstance(version.attributes, dict) else {}
        if (source is None or source.source_key != item_data["source_key"] or
                attrs.get("url") != item_data["publisher_url"]):
            raise ReportError("evidence_source_identity_mismatch")
        observed_at = version.observed_at
        if observed_at.tzinfo is None:
            observed_at = observed_at.replace(tzinfo=timezone.utc)
        if observed_at.astimezone(timezone.utc).isoformat() != item_data["observed_at"]:
            raise ReportError("evidence_observation_time_mismatch")
        relation = item_data["relation"]
        if relation in {"kev", "record", "reference", "title_mention"}:
            cve_id = bundle.get("parameters", {}).get("cve_id")
            if cve_id:
                link = db.get(CveItemVersionLink, (version.id, cve_id))
                if link is None or link.relation != relation:
                    raise ReportError("evidence_cve_relation_mismatch")
            elif relation != "record":
                raise ReportError("evidence_relation_not_supported")
        if relation == "kev" and not authoritative_kev_version(
                source_key=source.source_key, source_origin=source.origin,
                external_id=item.external_id, attributes=attrs,
                provenance=version.provenance, cve_id=bundle.get("parameters", {}).get("cve_id", "")):
            raise ReportError("kev_source_not_authoritative")
        result.append(ReportEvidence(
            report_id=report_id, evidence_id=evidence_id, item_id=item.id,
            item_version_id=version.id, item_version_sha256=version.sha256,
            source_key=source.source_key, publisher_url=item_data["publisher_url"],
            observed_at=observed_at,
            published_at=(datetime.fromisoformat(item_data["published_at"])
                          if item_data.get("published_at") else None),
            relation=relation,
        ))
    return result


def _publish_candidate(factory, claim: dict, token: str, bundle: dict, article: dict,
                       model: str | None, harness_version: str) -> tuple[str, str]:
    template = resolve_template(claim["template_id"], claim["template_snapshot"])
    published_at = now()
    slug = _slug_for(template, claim["parameters"], claim["id"], published_at)
    report_id = str(uuid.uuid4())
    category = template["category"]
    site_candidate = {
        **article,
        "slug": slug,
        "category": category,
        "published_at": published_at.isoformat(),
        "url": f"/reports/{category}/{slug}/",
    }
    site_root = public_root()
    private = private_root()
    build_root = private / "runs" / _uuid(claim["id"]) / "build"
    dist = None
    promoted = False
    previous_digest = None
    try:
        # Serialize the complete site snapshot and publication. A second
        # worker cannot build from an archive that omits a concurrently
        # published report.
        with _publication_lock(site_root):
            previous_digest = _ensure_current_release_locked(factory, site_root)
            with factory() as db:
                site_articles = _site_articles(db, site_candidate)
            dist, assets, digest = build_static_release(
                site_articles, build_root)
            _write_release(site_root, dist, assets, digest)

            if _current_digest(site_root) != previous_digest:
                raise ReportError("publication_pointer_changed", retryable=True)
            input_digest = hashlib.sha256(_json_bytes({
                "bundle_sha256": bundle["sha256"], "parameters": claim["parameters"],
                "template_revision": claim["template_revision"],
            })).hexdigest()

            # Validate the lease and every immutable evidence reference before
            # recording a durable intent. The intent lets startup distinguish
            # an interrupted promotion from a committed publication.
            with factory() as db:
                run = _assert_lease(db, claim["id"], token)
                state = db.scalar(select(ReportSiteState).where(
                    ReportSiteState.id == 1).with_for_update())
                if (state is None or state.pending_digest is not None or
                        state.active_digest != previous_digest):
                    raise ReportError("publication_state_busy", retryable=True)
                _evidence_db_rows(db, report_id, article, bundle)
                run.state = "publishing"
                run.stage = "publishing"
                run.lease_until = now() + timedelta(seconds=_LEASE_SECONDS)
                state.pending_digest = digest
                state.pending_run_id = run.id
                state.updated_at = now()
                db.commit()

            try:
                with factory() as db:
                    run = _assert_lease(db, claim["id"], token)
                    state = db.scalar(select(ReportSiteState).where(
                        ReportSiteState.id == 1).with_for_update())
                    if (state is None or state.pending_digest != digest or
                            state.pending_run_id != run.id or
                            state.active_digest != previous_digest):
                        raise ReportError("publication_intent_lost", retryable=True)
                    evidence_rows = _evidence_db_rows(db, report_id, article, bundle)
                    report = Report(
                        id=report_id, run_id=run.id, slug=slug, category=category,
                        template_id=template["id"], article_schema_version=1,
                        article=article, headline=article["title"], summary=article["summary"],
                        published_at=published_at, artifact_digest=digest,
                        artifact_path=f"releases/{digest}", supersedes_id=None,
                        model=model, harness_version=harness_version,
                        input_digest=input_digest,
                    )
                    db.add(report)
                    db.flush()
                    for row in evidence_rows:
                        db.add(row)

                    # The lease is fenced, the state singleton is locked, the
                    # intent is durable, and evidence has been revalidated.
                    # Commit advances the DB pointer in the same transaction;
                    # if it fails, the exception path restores the old link.
                    promoted = True
                    _promote(site_root, digest)
                    run.report_id = report_id
                    run.state = "published"
                    run.stage = "published"
                    run.error_code = None
                    run.finished_at = now()
                    run.lease_until = None
                    run.lease_token = None
                    run.bundle_sha256 = bundle["sha256"]
                    state.active_digest = digest
                    state.pending_digest = None
                    state.pending_run_id = None
                    state.updated_at = now()
                    db.commit()
            except Exception:
                committed = False
                try:
                    with factory() as db:
                        state = db.get(ReportSiteState, 1)
                        committed = bool(
                            state and state.active_digest == digest and
                            state.pending_digest is None and db.get(Report, report_id))
                except SQLAlchemyError:
                    pass
                if promoted and not committed and previous_digest:
                    try:
                        _promote(site_root, previous_digest)
                    except Exception:
                        log.exception(json.dumps({
                            "event": "report_pointer_rollback_failed",
                            "run_id": claim["id"],
                        }))
                try:
                    with factory() as db:
                        state = db.scalar(select(ReportSiteState).where(
                            ReportSiteState.id == 1).with_for_update())
                        if (state is not None and state.pending_digest == digest and
                                state.pending_run_id == claim["id"]):
                            state.pending_digest = None
                            state.pending_run_id = None
                            state.updated_at = now()
                            db.commit()
                except SQLAlchemyError:
                    # The persisted intent is recovered by ensure_current_release.
                    log.exception(json.dumps({
                        "event": "report_intent_cleanup_failed",
                        "run_id": claim["id"],
                    }))
                raise
        return report_id, digest
    finally:
        if dist is not None:
            shutil.rmtree(dist, ignore_errors=True)
        shutil.rmtree(build_root, ignore_errors=True)


def process_claim(factory, claim: dict):
    run_id, token = claim["id"], claim["lease_token"]
    heartbeat = _LeaseHeartbeat(factory, run_id, token)
    runner = None
    workdir = None
    heartbeat.start()
    try:
        with factory() as db:
            run = _assert_lease(db, run_id, token)
            run.state = "running"
            run.stage = "evidence"
            run.lease_until = now() + timedelta(seconds=_LEASE_SECONDS)
            db.commit()
        bundle = _read_or_build_bundle(factory, claim)
        if len(bundle["evidence"]) < claim["template_snapshot"]["publish_policy"]["minimum_evidence"]:
            raise ReportSkipped("insufficient evidence for this template")
        work_root = Path(os.getenv("NOUS_CODEX_WORK_ROOT", "/tmp/nous-codex-work"))
        if work_root.is_symlink():
            raise ReportError("codex_work_root_invalid")
        work_root.mkdir(parents=True, exist_ok=True, mode=0o711)
        work_root.chmod(0o711)
        # Every run gets a private directory; the unprivileged Codex process
        # can traverse its own stage directory but cannot enumerate siblings.
        workdir = work_root / ("job-" + uuid.uuid4().hex)
        workdir.mkdir(mode=0o710)
        runner = CodexRunner(workdir=workdir)
        final, model = run_editorial_pipeline(
            bundle, template_id=claim["template_id"], run_id=run_id, runner=runner,
            persist_stage=lambda name, value: _persist_stage(factory, run_id, token, name, value),
        )
        heartbeat.assert_owned()
        with factory() as db:
            run = _assert_lease(db, run_id, token)
            run.state = "validating"
            run.stage = "article_validated"
            run.lease_until = now() + timedelta(seconds=_LEASE_SECONDS)
            db.commit()
        report_id, digest = _publish_candidate(factory, claim, token, bundle, final,
                                                model, runner.version)
        log.info(json.dumps({"event": "report_published", "run_id": run_id,
                             "report_id": report_id, "artifact_digest": digest}))
    except ReportSkipped:
        _set_failure(factory, claim, state="skipped", code="no_publishable_content", retryable=False)
        log.info(json.dumps({"event": "report_skipped", "run_id": run_id}))
    except LeaseLost:
        log.warning(json.dumps({"event": "report_lease_lost", "run_id": run_id}))
    except ReportError as exc:
        _set_failure(factory, claim, state="failed", code=exc.code,
                     retryable=exc.retryable)
        log.warning(json.dumps({"event": "report_failed", "run_id": run_id,
                                "error_code": exc.code}))
    except Exception as exc:
        _set_failure(factory, claim, state="failed", code="worker_internal_error", retryable=True)
        log.warning(json.dumps({"event": "report_failed", "run_id": run_id,
                               "error_code": "worker_internal_error",
                               "error_type": type(exc).__name__}))
    finally:
        heartbeat.stop()
        if workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)


def _future_slot(slot: datetime, cadence: str, timezone_name: str, current: datetime,
                 *, wall_time: str | None = None) -> datetime:
    from zoneinfo import ZoneInfo
    zone = ZoneInfo(timezone_name)
    local_current = current.astimezone(zone)
    local_slot = slot.astimezone(zone)
    # Read the durable configured clock time, not the local time of a UTC slot
    # shifted by a DST gap. Otherwise a spring-forward 02:30 becomes 03:30
    # permanently on following days.
    selected_time = (datetime.strptime(wall_time, "%H:%M").time() if wall_time
                     else local_slot.timetz().replace(tzinfo=None))
    step = timedelta(days=1 if cadence == "daily" else 7)
    days = ((local_slot.weekday() - local_current.weekday()) % 7
            if cadence == "weekly" else 0)
    candidate_date = local_current.date() + timedelta(days=days)
    while True:
        candidate = datetime.combine(candidate_date, selected_time, tzinfo=zone)
        instant = candidate.astimezone(timezone.utc)
        # ZoneInfo accepts nonexistent wall times by assigning a pre-transition
        # offset. Skip that calendar slot instead of silently shifting it.
        exists = (instant.astimezone(zone).replace(tzinfo=None) ==
                  candidate.replace(tzinfo=None))
        if exists and instant > current:
            return instant
        candidate_date += step


def schedule_due(factory):
    current = now()
    with factory() as db:
        due = db.scalars(select(ReportSchedule).where(
            ReportSchedule.enabled.is_(True), ReportSchedule.next_slot_at <= current
        ).order_by(ReportSchedule.next_slot_at, ReportSchedule.id)
          .with_for_update(skip_locked=True).limit(100)).all()
        count = 0
        for schedule in due:
            slot = schedule.next_slot_at
            if slot.tzinfo is None:
                slot = slot.replace(tzinfo=timezone.utc)
            next_slot = _future_slot(
                slot, schedule.cadence, schedule.timezone, current,
                wall_time=schedule.local_time,
            )
            # Emit at most one recent missed slot. Older slots are advanced
            # without generating a retrospective catch-up storm.
            grace = timedelta(days=1 if schedule.cadence == "daily" else 7)
            if slot >= current - grace:
                raw = dict(schedule.parameters or {})
                slot_local = slot.astimezone(__import__("zoneinfo").ZoneInfo(schedule.timezone))
                if schedule.template_id == "security-daily":
                    raw["target_date"] = slot_local.date().isoformat()
                    raw["timezone"] = schedule.timezone
                params = normalize_parameters(schedule.template_id, raw, now=slot)
                key = "schedule:" + hashlib.sha256(
                    f"{schedule.id}\0{slot.isoformat()}".encode()
                ).hexdigest()
                db.add(ReportRun(
                    id=str(uuid.uuid4()), schedule_id=schedule.id, schedule_slot=slot,
                    trigger="scheduled", created_by=schedule.created_by,
                    template_id=schedule.template_id,
                    template_revision=schedule.template_revision,
                    template_snapshot=schedule.template_snapshot, parameters=params,
                    idempotency_key=key, state="queued", stage="queued", attempts=0,
                    available_at=current, stage_artifacts={}, created_at=current,
                ))
                count += 1
            schedule.next_slot_at = next_slot
        try:
            db.commit()
        except IntegrityError:
            # A duplicate tick is expected to collide with the unique schedule
            # slot/idempotency keys; rollback leaves schedule state retryable.
            db.rollback()
        if count:
            log.info(json.dumps({"event": "report_schedules_enqueued", "count": count}))


def run_once(factory=None) -> bool:
    factory = factory or session_factory()
    schedule_due(factory)
    ensure_current_release(factory)
    claim = _claim_run(factory)
    if claim is None:
        return False
    process_claim(factory, claim)
    # Reconcile filesystem and database after any failed publication phase.
    ensure_current_release(factory)
    return True


def main():
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    factory = session_factory()
    while True:
        try:
            processed = run_once(factory)
        except (SQLAlchemyError, ReportError, OSError, ValueError) as exc:
            log.warning(json.dumps({"event": "report_worker_tick_failed",
                                    "error_code": getattr(exc, "code", type(exc).__name__)[:64]}))
            processed = False
        if not processed:
            time.sleep(5)


if __name__ == "__main__":
    main()
