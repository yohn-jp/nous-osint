#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

fail() { printf 'nous-restore-test: %s\n' "$*" >&2; exit 1; }
for command_name in gpg sha256sum cut python3 podman seq sleep findmnt mktemp; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done

archive=${1:-}
[[ -n "$archive" && -f "$archive" ]] || fail "usage: restore-test.sh BACKUP.tar.gpg [MANIFEST.json.gpg]"
manifest=${2:-${archive%.tar.gpg}.manifest.json.gpg}
[[ -f "$manifest" ]] || fail "encrypted backup manifest not found: $manifest"
[[ $(findmnt -n -o FSTYPE /dev/shm 2>/dev/null || true) == tmpfs ]] \
  || fail "/dev/shm must be a tmpfs; refusing plaintext secret staging on persistent storage"
tmpdir=$(mktemp -d /dev/shm/nous-restore.XXXXXX)
chmod 700 "$tmpdir"
trap 'rm -rf -- "$tmpdir"' EXIT
manifest_plain="$tmpdir/manifest.json"
gpg --batch --quiet --decrypt -- "$manifest" > "$manifest_plain" \
  || fail "encrypted backup manifest could not be decrypted"

manifest_fields=$(python3 - "$manifest_plain" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
if value.get("format") != "nous-report-site-backup-v1":
    raise SystemExit("unsupported or legacy database-only backup format")
counts = value.get("counts")
site = value.get("report_site")
checksums = value.get("checksums")
if not isinstance(counts, dict) or not isinstance(site, dict) or not isinstance(checksums, dict):
    raise SystemExit("backup manifest is incomplete")
schema = value.get("schema_version")
if not isinstance(schema, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", schema):
    raise SystemExit("backup schema version is invalid")
names = ("sources", "items", "item_versions", "report_runs", "report_schedules", "reports", "report_evidence")
rows = [counts.get(name) for name in names]
if any(type(row) is not int or row < 0 for row in rows):
    raise SystemExit("backup row counts are invalid")
active = site.get("active_digest")
if active != "none" and (not isinstance(active, str) or not re.fullmatch(r"[a-f0-9]{64}", active)):
    raise SystemExit("backup active digest is invalid")
site_files, site_assets = site.get("file_count"), site.get("asset_count")
if type(site_files) is not int or site_files < 0 or type(site_assets) is not int or site_assets < 0:
    raise SystemExit("backup site counts are invalid")
site_manifest = site.get("manifest_sha256")
if site_manifest != "none" and (not isinstance(site_manifest, str) or not re.fullmatch(r"[a-f0-9]{64}", site_manifest)):
    raise SystemExit("backup site manifest checksum is invalid")
database_sha = checksums.get("database_dump_sha256")
site_sha = checksums.get("report_site_archive_sha256")
archive_sha = value.get("sha256")
for digest in (database_sha, site_sha, archive_sha):
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise SystemExit("backup checksum is invalid")
artifact = value.get("artifact")
if not isinstance(artifact, str) or "/" in artifact or "\\" in artifact or not artifact.endswith(".tar.gpg"):
    raise SystemExit("backup artifact name is invalid")
print("\t".join([schema, *(str(row) for row in rows), active, str(site_files),
                  str(site_assets), site_manifest, database_sha, site_sha,
                  archive_sha, artifact]))
PY
) || fail "backup manifest validation failed"
IFS=$'\t' read -r schema_version expected_sources expected_items expected_versions \
  expected_runs expected_schedules expected_reports expected_evidence expected_digest \
  expected_site_files expected_site_assets expected_site_manifest expected_db_sha \
  expected_site_sha expected_archive_sha expected_artifact <<< "$manifest_fields"
[[ $(basename -- "$archive") == "$expected_artifact" ]] || fail "manifest artifact name mismatch"
actual_hash=$(sha256sum -- "$archive" | cut -d ' ' -f 1)
[[ "$actual_hash" == "$expected_archive_sha" ]] || fail "encrypted artifact checksum mismatch"

image=${NOUS_RESTORE_POSTGRES_IMAGE:-docker.io/library/postgres@sha256:f4b419e350fd98d4a8429603295208976dea4c8fb8326d818d346d3e29f1db6f}
[[ "$image" =~ ^[a-zA-Z0-9./:@_-]+$ ]] || fail "invalid PostgreSQL image reference"
suffix=$(python3 -c 'import secrets; print(secrets.token_hex(6))')
container="nous-restore-${suffix}"
volume="nous-restore-db-${suffix}"
site_volume="nous-restore-site-${suffix}"
secret="nous-restore-${suffix}"
password_file="$tmpdir/db_password"
python3 -c 'import secrets; print(secrets.token_hex(32), end="")' > "$password_file"
chmod 600 "$password_file"
cleanup() {
  podman rm -f "$container" >/dev/null 2>&1 || true
  podman volume rm "$volume" "$site_volume" >/dev/null 2>&1 || true
  podman secret rm "$secret" >/dev/null 2>&1 || true
  rm -rf -- "$tmpdir"
}
trap cleanup EXIT
podman secret create "$secret" "$password_file" >/dev/null
podman volume create "$volume" >/dev/null
podman volume create "$site_volume" >/dev/null
podman run -d --name "$container" --volume "$volume:/var/lib/postgresql" \
  --network none --secret "$secret,type=mount,target=/run/secrets/db_password" \
  --env POSTGRES_DB=nous --env POSTGRES_USER=nous \
  --env POSTGRES_PASSWORD_FILE=/run/secrets/db_password "$image" >/dev/null
rm -f "$password_file"

ready=0
for _ in $(seq 1 60); do
  if podman exec "$container" pg_isready -U nous -d nous >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
(( ready == 1 )) || fail "isolated PostgreSQL did not become ready"

# Parse the encrypted tar as a stream. The custom dump is piped into pg_restore
# and the site tar into an isolated container running only GNU tar; no plaintext
# archive or dump is written to a host file. The site tar is extracted only into
# a disposable rootless Podman volume, then verified in Podman's user namespace.
archive_parser=$(cat <<'PY'
import hashlib
import json
import subprocess
import sys
import tarfile

manifest_path, container, site_volume, postgres_image = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as stream:
    outer = json.load(stream)



members = set()
inner = None
for_archive = tarfile.open(fileobj=sys.stdin.buffer, mode="r|")
for member in for_archive:
    if member.name not in {"manifest.json", "database.dump", "report-site.tar"} or member.name in members:
        raise SystemExit("unexpected or duplicate backup archive member")
    if not member.isfile():
        raise SystemExit("backup archive member is not a regular file")
    members.add(member.name)
    source = for_archive.extractfile(member)
    if member.name == "manifest.json":
        if members != {"manifest.json"} or member.size > 1048576:
            raise SystemExit("backup manifest must be the first bounded archive member")
        inner = json.loads(source.read())
        if inner.get("format") != outer.get("format") or inner.get("schema_version") != outer.get("schema_version"):
            raise SystemExit("inner and outer backup manifests disagree")
        for key in ("counts", "report_site", "checksums"):
            if inner.get(key) != outer.get(key):
                raise SystemExit("inner and outer backup manifests disagree")
        continue
    if inner is None:
        raise SystemExit("backup manifest is missing")
    if member.name == "database.dump":
        if members != {"manifest.json", "database.dump"}:
            raise SystemExit("backup members are out of order")
        process = subprocess.Popen([
            "podman", "exec", "-i", container, "bash", "-c",
            'export PGPASSWORD="$(cat /run/secrets/db_password)"; exec pg_restore --no-owner --no-acl -U nous -d nous',
        ], stdin=subprocess.PIPE)
    else:
        if members != {"manifest.json", "database.dump", "report-site.tar"}:
            raise SystemExit("backup members are out of order")
        process = subprocess.Popen([
            "podman", "run", "--rm", "-i", "--network", "none",
            "--volume", f"{site_volume}:/site:rw", "--entrypoint", "tar",
            postgres_image, "--no-same-owner", "-C", "/site", "-xpf", "-",
        ], stdin=subprocess.PIPE)
    digest = hashlib.sha256()
    remaining = member.size
    try:
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                raise SystemExit("truncated backup archive member")
            digest.update(chunk)
            process.stdin.write(chunk)
            remaining -= len(chunk)
        process.stdin.close()
    except BrokenPipeError as exc:
        process.kill()
        process.wait()
        raise SystemExit("restore container stopped accepting its archive") from exc
    if process.wait() != 0:
        raise SystemExit(f"container restore failed for {member.name}")
    expected = inner["checksums"]["database_dump_sha256" if member.name == "database.dump" else "report_site_archive_sha256"]
    if digest.hexdigest() != expected:
        raise SystemExit(f"backup member checksum mismatch: {member.name}")
if members != {"manifest.json", "database.dump", "report-site.tar"}:
    raise SystemExit("backup archive is incomplete")
PY
)
if ! gpg --batch --quiet --decrypt -- "$archive" \
      | python3 -c "$archive_parser" "$manifest_plain" "$container" "$site_volume" "$image"; then
  fail "decrypt, stream, checksum or restore failed"
fi

actual=$(podman exec "$container" bash -c \
  'export PGPASSWORD="$(cat /run/secrets/db_password)"; exec psql -v ON_ERROR_STOP=1 -U nous -d nous -AtF "|" -c "SELECT (SELECT version_num FROM alembic_version), (SELECT count(*) FROM sources), (SELECT count(*) FROM items), (SELECT count(*) FROM item_versions), (SELECT count(*) FROM report_runs), (SELECT count(*) FROM report_schedules), (SELECT count(*) FROM reports), (SELECT count(*) FROM report_evidence), COALESCE((SELECT active_digest FROM report_site_state WHERE id = 1), '\''none'\'')"')
expected="${schema_version}|${expected_sources}|${expected_items}|${expected_versions}|${expected_runs}|${expected_schedules}|${expected_reports}|${expected_evidence}|${expected_digest}"
[[ "$actual" == "$expected" ]] || fail "restored schema, row counts or active digest mismatch: expected ${expected}, got ${actual}"

site_mountpoint=$(podman volume inspect --format '{{.Mountpoint}}' "$site_volume")
[[ -d "$site_mountpoint" ]] || fail "cannot inspect restored site volume"
restored_site=$(podman unshare python3 - "$site_mountpoint" "$expected_digest" \
  "$expected_site_files" "$expected_site_assets" "$expected_site_manifest" <<'PY'
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

root = Path(sys.argv[1])
expected_digest, expected_files, expected_assets, expected_manifest = sys.argv[2:]
if root.is_symlink() or not root.is_dir():
    raise SystemExit("restored report-site volume path is unsafe")
current = root / "current"
if not current.exists() and not current.is_symlink():
    if expected_digest != "none" or expected_files != "0" or expected_assets != "0" or expected_manifest != "none":
        raise SystemExit("restored report-site pointer is missing")
    print("none|0|0|none")
    raise SystemExit(0)
if not current.is_symlink():
    raise SystemExit("restored report-site pointer is unsafe")
match = re.fullmatch(r"releases/([a-f0-9]{64})", current.readlink().as_posix())
if not match or match.group(1) != expected_digest:
    raise SystemExit("restored report-site digest does not match database")
digest = match.group(1)
manifest_path = root / ".manifests" / f"{digest}.json"
if manifest_path.is_symlink() or not manifest_path.is_file():
    raise SystemExit("restored active manifest is missing")
manifest_bytes = manifest_path.read_bytes()
manifest = json.loads(manifest_bytes)
files = manifest.get("files")
if manifest.get("digest") != digest or not isinstance(files, dict) or not files:
    raise SystemExit("restored active manifest is invalid")
html = set(manifest.get("html_files", []))
assets = set(manifest.get("assets", []))
if (html != {name for name in files if not name.startswith("_astro/")} or
        assets != {name.removeprefix("_astro/") for name in files if name.startswith("_astro/")}):
    raise SystemExit("restored active asset list is inconsistent")
state = hashlib.sha256()
for relative, expected_hash in sorted(files.items()):
    if not isinstance(relative, str) or not isinstance(expected_hash, str):
        raise SystemExit("restored manifest path or hash is invalid")
    rel = PurePosixPath(relative)
    if (rel.is_absolute() or not rel.parts or any(p in {".", ".."} for p in rel.parts) or
            "\\" in relative or not re.fullmatch(r"[a-f0-9]{64}", expected_hash)):
        raise SystemExit("restored manifest path or hash is invalid")
    if rel.parts[0] == "_astro":
        if len(rel.parts) != 2:
            raise SystemExit("restored asset path is invalid")
        file_path = root / "_astro" / rel.parts[1]
    else:
        file_path = root / "releases" / digest / Path(*rel.parts)
    if file_path.is_symlink() or not file_path.is_file():
        raise SystemExit("restored active release file or asset is missing")
    data = file_path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_hash:
        raise SystemExit("restored active file or asset hash mismatch")
    state.update(relative.encode())
    state.update(b"\0")
    state.update(data)
    state.update(b"\0")
release = root / "releases" / digest
actual_html = {p.relative_to(release).as_posix() for p in release.rglob("*")
               if p.is_file() and not p.is_symlink()}
if actual_html != html or state.hexdigest() != digest:
    raise SystemExit("restored active digest or HTML assets are incomplete")
print(f"{digest}|{len(files)}|{len(assets)}|{hashlib.sha256(manifest_bytes).hexdigest()}")
PY
)
expected_site="${expected_digest}|${expected_site_files}|${expected_site_assets}|${expected_site_manifest}"
[[ "$restored_site" == "$expected_site" ]] || fail "restored report-site digest/assets do not match manifest"

printf 'Restore verified: schema=%s sources=%s items=%s versions=%s reports=%s evidence=%s site_digest=%s site_files=%s site_assets=%s\n' \
  "$schema_version" "$expected_sources" "$expected_items" "$expected_versions" \
  "$expected_reports" "$expected_evidence" "$expected_digest" "$expected_site_files" "$expected_site_assets"
