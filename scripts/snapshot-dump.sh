#!/usr/bin/env bash
# Run as the rootless `nous` account on the VM. Emits a tar stream containing a
# PostgreSQL custom dump and the report-site volume; the caller must encrypt it.
set -Eeuo pipefail
umask 077

fail() { printf 'nous-snapshot: %s\n' "$*" >&2; exit 1; }

if [[ ${NOUS_SNAPSHOT_DATABASE_ONLY:-0} == 1 ]]; then
  # This branch runs inside the PostgreSQL container and produces one dump from
  # the same exported snapshot as all SQL metadata.
  coproc SNAPSHOT_SQL { psql -X -qAt -F '|' -v ON_ERROR_STOP=1 -U nous -d nous; }
  sql_in=${SNAPSHOT_SQL[1]}
  sql_out=${SNAPSHOT_SQL[0]}
  sql_pid=$SNAPSHOT_SQL_PID
  printf '%s\n' \
    'BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;' \
    'SELECT pg_export_snapshot();' \
    "SELECT (SELECT version_num FROM alembic_version), (SELECT count(*) FROM sources), (SELECT count(*) FROM items), (SELECT count(*) FROM item_versions), (SELECT count(*) FROM report_runs), (SELECT count(*) FROM report_schedules), (SELECT count(*) FROM reports), (SELECT count(*) FROM report_evidence), COALESCE((SELECT active_digest FROM report_site_state WHERE id = 1), 'none');" \
    >&"$sql_in"
  IFS= read -r snapshot <&"$sql_out" || exit 1
  IFS= read -r metadata <&"$sql_out" || exit 1
  [[ "$snapshot" =~ ^[0-9A-Fa-f-]+$ ]] || fail "invalid exported snapshot"
  [[ "$metadata" =~ ^[A-Za-z0-9._-]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|(none|[a-f0-9]{64})$ ]] \
    || fail "invalid database snapshot metadata"
  pg_dump --snapshot="$snapshot" -U nous -d nous -Fc
  printf 'COMMIT;\n\\q\n' >&"$sql_in"
  wait "$sql_pid"
  printf 'NOUS_SNAPSHOT_METADATA=%s\n' "$metadata" >&2
  exit 0
fi

for command_name in podman systemctl findmnt mktemp tar sha256sum cut python3 sed wc; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done

[[ $(findmnt -n -o FSTYPE /dev/shm 2>/dev/null || true) == tmpfs ]] \
  || fail "/dev/shm must be a tmpfs; refusing plaintext staging on persistent storage"
[[ -n ${XDG_RUNTIME_DIR:-} && -d $XDG_RUNTIME_DIR ]] \
  || fail "rootless systemd runtime directory is unavailable"

volume=${NOUS_REPORT_SITE_VOLUME:-nous-report-site}
postgres_image=${NOUS_BACKUP_POSTGRES_IMAGE:-docker.io/library/postgres@sha256:f4b419e350fd98d4a8429603295208976dea4c8fb8326d818d346d3e29f1db6f}
[[ "$volume" =~ ^[a-zA-Z0-9_.-]+$ && "$volume" != -* ]] || fail "invalid report volume name"
[[ "$postgres_image" =~ ^[a-zA-Z0-9./:@_-]+$ ]] || fail "invalid PostgreSQL image reference"
podman volume inspect "$volume" >/dev/null 2>&1 || fail "report-site volume does not exist"

worker_was_active=0
tmpdir=
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if (( worker_was_active )); then
    if ! systemctl --user start nous-report-worker.service; then
      printf 'nous-snapshot: failed to restart previously active report Worker\n' >&2
      status=1
    fi
  fi
  [[ -z $tmpdir ]] || rm -rf -- "$tmpdir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

worker_state=$(systemctl --user show --property=ActiveState --value \
  nous-report-worker.service) || fail "cannot inspect report Worker state"
case "$worker_state" in
  active|activating|deactivating|reloading)
  worker_was_active=1
  systemctl --user stop nous-report-worker.service
  ;;
  inactive|failed) ;;
  *) fail "unknown report Worker state: ${worker_state}" ;;
esac
worker_state=$(systemctl --user show --property=ActiveState --value \
  nous-report-worker.service) || fail "cannot inspect stopped report Worker state"
if [[ "$worker_state" != inactive && "$worker_state" != failed ]]; then
  fail "report Worker remained active after stop"
fi

tmpdir=$(mktemp -d /dev/shm/nous-report-backup.XXXXXX) || fail "cannot allocate tmpfs workspace"
chmod 700 "$tmpdir"
mkdir -m 700 "$tmpdir/site"

# PostgreSQL dump and row counts share one exported repeatable-read snapshot.
podman exec -i nous-db env NOUS_SNAPSHOT_DATABASE_ONLY=1 bash -s \
  < "${BASH_SOURCE[0]}" > "$tmpdir/database.dump" 2> "$tmpdir/database.meta"
[[ -s "$tmpdir/database.dump" ]] || fail "database dump is empty"
db_metadata=$(sed -n 's/^NOUS_SNAPSHOT_METADATA=//p' "$tmpdir/database.meta")
[[ $(wc -l < "$tmpdir/database.meta") -eq 1 ]] || fail "database snapshot metadata is missing or ambiguous"
[[ "$db_metadata" =~ ^[A-Za-z0-9._-]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|(none|[a-f0-9]{64})$ ]] \
  || fail "database snapshot metadata is malformed"
IFS='|' read -r schema_version source_count item_count version_count run_count schedule_count report_count evidence_count db_digest <<< "$db_metadata"

# The Worker is stopped before either capture. A named volume tar preserves the
# current symlink, release HTML, private manifests and append-only assets.
podman run --rm --network none --volume="$volume:/site:ro" \
  --entrypoint tar "$postgres_image" --numeric-owner -C /site -cpf - . \
  > "$tmpdir/report-site.tar"
[[ -s "$tmpdir/report-site.tar" ]] || fail "report-site volume archive is empty"
site_metadata=$(python3 - "$tmpdir/report-site.tar" "$tmpdir/site" "$db_digest" <<'PY'
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

archive, destination, expected_digest = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
root = destination.resolve()
try:
    with tarfile.open(archive, "r:") as stream:
        stream.extractall(root, filter="data")
except (OSError, tarfile.TarError, ValueError) as exc:
    raise SystemExit("report-site archive extraction rejected") from exc
current = root / "current"
if not current.exists() and not current.is_symlink():
    if expected_digest != "none":
        raise SystemExit("database/site active digest mismatch")
    print("none|0|0|none")
    raise SystemExit(0)
if not current.is_symlink():
    raise SystemExit("report-site current pointer is not a symlink")
match = re.fullmatch(r"releases/([a-f0-9]{64})", current.readlink().as_posix())
if not match or match.group(1) != expected_digest:
    raise SystemExit("database/site active digest mismatch")
digest = match.group(1)
manifest_path = root / ".manifests" / f"{digest}.json"
if manifest_path.is_symlink() or not manifest_path.is_file():
    raise SystemExit("active report-site manifest is missing or unsafe")
manifest_bytes = manifest_path.read_bytes()
try:
    manifest = json.loads(manifest_bytes)
except (ValueError, UnicodeDecodeError) as exc:
    raise SystemExit("active report-site manifest is invalid") from exc
files = manifest.get("files")
if manifest.get("digest") != digest or not isinstance(files, dict) or not files:
    raise SystemExit("active report-site manifest has no file map")
if not isinstance(manifest.get("html_files"), list) or not isinstance(manifest.get("assets"), list):
    raise SystemExit("active report-site manifest is incomplete")
if any(path.is_symlink() for path in root.rglob("*")):
    if current.is_symlink() is False:
        raise SystemExit("report-site symlink is unexpected")
    if any(path.is_symlink() and path != current for path in root.rglob("*")):
        raise SystemExit("report-site contains an unexpected symlink")
html = set(manifest["html_files"])
assets = set(manifest["assets"])
if len(html) != len(manifest["html_files"]) or len(assets) != len(manifest["assets"]):
    raise SystemExit("active report-site manifest has duplicate paths")
if (html != {name for name in files if not name.startswith("_astro/")} or
        assets != {name.removeprefix("_astro/") for name in files if name.startswith("_astro/")}):
    raise SystemExit("active report-site manifest file lists disagree")
hash_state = hashlib.sha256()
for relative, expected in sorted(files.items()):
    if not isinstance(relative, str):
        raise SystemExit("active report-site manifest path is invalid")
    rel = PurePosixPath(relative)
    if (rel.is_absolute() or not rel.parts or
            any(part in {".", ".."} for part in rel.parts) or "\\" in relative or
            not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected)):
        raise SystemExit("active report-site manifest path or hash is invalid")
    if rel.parts[0] == "_astro":
        if len(rel.parts) != 2:
            raise SystemExit("active asset path is invalid")
        path = root / "_astro" / rel.parts[1]
    else:
        path = root / "releases" / digest / Path(*rel.parts)
    if path.is_symlink() or not path.is_file():
        raise SystemExit("active report-site file is missing or unsafe")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit("active report-site file hash mismatch")
    hash_state.update(relative.encode())
    hash_state.update(b"\0")
    hash_state.update(data)
    hash_state.update(b"\0")
release = root / "releases" / digest
actual_html = {path.relative_to(release).as_posix() for path in release.rglob("*")
               if path.is_file() and not path.is_symlink()}
if actual_html != html or hash_state.hexdigest() != digest:
    raise SystemExit("active report-site digest or release contents mismatch")
print(f"{digest}|{len(files)}|{len(assets)}|{hashlib.sha256(manifest_bytes).hexdigest()}")
PY
)
[[ "$site_metadata" =~ ^(none|[a-f0-9]{64})\|[0-9]+\|[0-9]+\|(none|[a-f0-9]{64})$ ]] \
  || fail "report-site metadata is malformed"
IFS='|' read -r site_digest site_file_count site_asset_count site_manifest_hash <<< "$site_metadata"
[[ "$site_digest" == "$db_digest" ]] || fail "database and report-site active digests differ"

db_sha=$(sha256sum -- "$tmpdir/database.dump" | cut -d ' ' -f 1)
site_sha=$(sha256sum -- "$tmpdir/report-site.tar" | cut -d ' ' -f 1)
python3 - "$tmpdir/manifest.json" "${NOUS_BACKUP_CREATED_AT:-$(date -u +%Y%m%dT%H%M%SZ)}" \
  "$schema_version" "$source_count" "$item_count" "$version_count" "$run_count" \
  "$schedule_count" "$report_count" "$evidence_count" "$db_digest" "$site_file_count" \
  "$site_asset_count" "$site_manifest_hash" "$db_sha" "$site_sha" <<'PY'
import json
from pathlib import Path
import re
import sys

(_, path, created, schema, sources, items, versions, runs, schedules, reports,
 evidence, active, site_files, site_assets, site_manifest, db_sha, site_sha) = sys.argv
digest_re = re.compile(r"[a-f0-9]{64}")
for value in (sources, items, versions, runs, schedules, reports, evidence, site_files, site_assets):
    if not value.isdigit():
        raise SystemExit("invalid count while writing backup manifest")
if active != "none" and not digest_re.fullmatch(active):
    raise SystemExit("invalid active digest while writing backup manifest")
for value in (site_manifest, db_sha, site_sha):
    if value != "none" and not digest_re.fullmatch(value):
        raise SystemExit("invalid checksum while writing backup manifest")
manifest = {
    "format": "nous-report-site-backup-v1",
    "created_at": created,
    "schema_version": schema,
    "counts": {
        "sources": int(sources), "items": int(items), "item_versions": int(versions),
        "report_runs": int(runs), "report_schedules": int(schedules),
        "reports": int(reports), "report_evidence": int(evidence),
    },
    "report_site": {
        "active_digest": active, "file_count": int(site_files),
        "asset_count": int(site_assets), "manifest_sha256": site_manifest,
    },
    "checksums": {"database_dump_sha256": db_sha, "report_site_archive_sha256": site_sha},
}
Path(path).write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8")
Path(path).chmod(0o600)
PY

tar --numeric-owner -C "$tmpdir" -cf - manifest.json database.dump report-site.tar
printf 'NOUS_SNAPSHOT_METADATA=%s\n' "$db_metadata" >&2
printf 'NOUS_SITE_METADATA=%s|%s|%s|%s|%s|%s\n' \
  "$site_digest" "$site_file_count" "$site_asset_count" "$site_manifest_hash" "$db_sha" "$site_sha" >&2
