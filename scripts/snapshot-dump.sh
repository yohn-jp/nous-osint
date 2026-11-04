#!/usr/bin/env bash
# Run as the rootless `nous` account on the VM. Emits a bounded-memory framed
# stream containing a PostgreSQL custom dump and the report-site volume; caller
# encrypts stdout directly. No database or site archive is staged on disk.
set -Eeuo pipefail
umask 077

fail() { printf 'nous-snapshot: %s\n' "$*" >&2; exit 1; }

if [[ ${NOUS_SNAPSHOT_DATABASE_ONLY:-0} == 1 ]]; then
  # The host branch invokes this same script inside PostgreSQL to produce one
  # dump from the exported snapshot used for all row counts and active_digest.
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

for command_name in podman systemctl findmnt python3; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done

[[ $(findmnt -n -o FSTYPE /dev/shm 2>/dev/null || true) == tmpfs ]] \
  || fail "/dev/shm must be a tmpfs for the uploaded helper"
[[ -n ${XDG_RUNTIME_DIR:-} && -d $XDG_RUNTIME_DIR ]] \
  || fail "rootless systemd runtime directory is unavailable"

volume=${NOUS_REPORT_SITE_VOLUME:-nous-report-site}
postgres_image=${NOUS_BACKUP_POSTGRES_IMAGE:-docker.io/library/postgres@sha256:f4b419e350fd98d4a8429603295208976dea4c8fb8326d818d346d3e29f1db6f}
[[ "$volume" =~ ^[a-zA-Z0-9_.-]+$ && "$volume" != -* ]] || fail "invalid report volume name"
[[ "$postgres_image" =~ ^[a-zA-Z0-9./:@_-]+$ ]] || fail "invalid PostgreSQL image reference"
podman volume inspect "$volume" >/dev/null 2>&1 || fail "report-site volume does not exist"

worker_was_active=0
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if (( worker_was_active )); then
    if ! systemctl --user start nous-report-worker.service; then
      printf 'nous-snapshot: failed to restart previously active report Worker\n' >&2
      status=1
    fi
  fi
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

python3 - "${BASH_SOURCE[0]}" "$volume" "$postgres_image" <<'PY'
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import struct
import subprocess
import sys
import tarfile
import threading

helper_path, volume, postgres_image = sys.argv[1:]
try:
    chunk_size = int(os.environ.get("NOUS_BACKUP_STREAM_CHUNK_BYTES", "1048576"))
except ValueError as exc:
    raise SystemExit("invalid backup stream chunk size") from exc
if not 4096 <= chunk_size <= 8 * 1024 * 1024:
    raise SystemExit("backup stream chunk size must be between 4096 and 8388608")
max_small_output = 8 * 1024 * 1024
max_stderr = 64 * 1024
digest_re = re.compile(r"^[a-f0-9]{64}$")
snapshot_re = re.compile(
    r"^([A-Za-z0-9._-]+)\|([0-9]+)\|([0-9]+)\|([0-9]+)\|([0-9]+)\|"
    r"([0-9]+)\|([0-9]+)\|([0-9]+)\|(none|[a-f0-9]{64})$"
)
magic = b"NOUS-REPORT-BACKUP-STREAM\x00\x01"
stdout = sys.stdout.buffer


def _drain(pipe, result):
    kept = bytearray()
    too_large = False
    while True:
        chunk = pipe.read(8192)
        if not chunk:
            break
        if len(kept) < max_stderr:
            kept.extend(chunk[:max_stderr - len(kept)])
        else:
            too_large = True
    result.append((bytes(kept), too_large))


def run_small(command, limit=max_small_output):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stderr_result = []
    stderr_thread = threading.Thread(target=_drain, args=(process.stderr, stderr_result), daemon=True)
    stderr_thread.start()
    output = bytearray()
    while True:
        chunk = process.stdout.read(min(chunk_size, limit + 1 - len(output)))
        if not chunk:
            break
        output.extend(chunk)
        if len(output) > limit:
            process.kill()
            process.wait()
            stderr_thread.join()
            raise RuntimeError("bounded command output exceeded limit")
    status = process.wait()
    stderr_thread.join()
    if status or stderr_result[0][1]:
        raise RuntimeError("bounded Podman helper command failed")
    return bytes(output)


def site_run(*command):
    return ["podman", "run", "--rm", "--network", "none",
            f"--volume={volume}:/site:ro", "--entrypoint", command[0],
            postgres_image, *command[1:]]


def _record_header(name):
    encoded = name.encode("ascii")
    if len(encoded) > 255:
        raise RuntimeError("backup record name is too long")
    stdout.write(struct.pack(">H", len(encoded)))
    stdout.write(encoded)


def _record_chunk(chunk):
    if not chunk or len(chunk) > chunk_size:
        raise RuntimeError("invalid backup record chunk")
    stdout.write(struct.pack(">I", len(chunk)))
    stdout.write(chunk)


def _record_end():
    stdout.write(b"\x00\x00\x00\x00")


def stream_process_record(name, command, *, stdin=None, stderr_required=None):
    process = subprocess.Popen(command, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stderr_result = []
    stderr_thread = threading.Thread(target=_drain, args=(process.stderr, stderr_result), daemon=True)
    stderr_thread.start()
    _record_header(name)
    checksum = hashlib.sha256()
    length = 0
    try:
        while True:
            chunk = process.stdout.read(chunk_size)
            if not chunk:
                break
            _record_chunk(chunk)
            checksum.update(chunk)
            length += len(chunk)
    except (BrokenPipeError, OSError):
        process.kill()
        process.wait()
        stderr_thread.join()
        raise
    _record_end()
    status = process.wait()
    stderr_thread.join()
    stderr, stderr_too_large = stderr_result[0]
    if status or stderr_too_large or (stderr_required and stderr.count(b"\n") != 1):
        raise RuntimeError("stream producer failed")
    if length == 0:
        raise RuntimeError("backup stream member is empty")
    return checksum.hexdigest(), stderr


def stream_active_files(digest, manifest):
    files = manifest.get("files")
    html_files = manifest.get("html_files")
    assets = manifest.get("assets")
    if (manifest.get("digest") != digest or not isinstance(files, dict) or not files or
            not isinstance(html_files, list) or not isinstance(assets, list)):
        raise RuntimeError("active report-site manifest is incomplete")
    if any(not isinstance(value, str) for value in (*html_files, *assets)):
        raise RuntimeError("active report-site manifest lists are invalid")
    html, asset_names = set(html_files), set(assets)
    if (len(html) != len(html_files) or len(asset_names) != len(assets) or
            html != {name for name in files if not name.startswith("_astro/")} or
            asset_names != {name.removeprefix("_astro/") for name in files if name.startswith("_astro/")}):
        raise RuntimeError("active report-site manifest file lists disagree")
    entries = []
    command_paths = []
    for relative, expected in sorted(files.items()):
        if not isinstance(relative, str) or not isinstance(expected, str) or not digest_re.fullmatch(expected):
            raise RuntimeError("active report-site manifest file entry is invalid")
        path = PurePosixPath(relative)
        if path.is_absolute() or not path.parts or any(part in {".", ".."} for part in path.parts) or "\\" in relative:
            raise RuntimeError("active report-site manifest path is invalid")
        if path.parts[0] == "_astro":
            if len(path.parts) != 2:
                raise RuntimeError("active report-site asset path is invalid")
            archive_path = relative
        else:
            if path.suffix != ".html":
                raise RuntimeError("active report-site release contains a non-HTML file")
            archive_path = f"releases/{digest}/{relative}"
        entries.append((relative, archive_path, expected))
        command_paths.append(archive_path)
    if len(entries) > 20000 or sum(len(path) + 1 for path in command_paths) > 1024 * 1024:
        raise RuntimeError("active report-site file list exceeds limit")

    release_listing = run_small(site_run("bash", "-c", \
        f"find /site/releases/{digest} -type f -printf '%P\\n'"), limit=max_small_output)
    release_names = set(release_listing.decode("utf-8").splitlines())
    if release_names != html:
        raise RuntimeError("active release HTML list does not match manifest")
    unsafe_links = run_small(site_run("bash", "-c", \
        "find /site -type l ! -path /site/current -print -quit"), limit=4096)
    if unsafe_links:
        raise RuntimeError("report-site has an unexpected symlink")

    command = ["podman", "run", "--rm", "-i", "--network", "none",
               f"--volume={volume}:/site:ro", "--entrypoint", "tar", postgres_image,
               "--no-recursion", "-C", "/site", "-cf", "-", "--", *command_paths]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stderr_result = []
    stderr_thread = threading.Thread(target=_drain, args=(process.stderr, stderr_result), daemon=True)
    stderr_thread.start()
    tar_stream = tarfile.open(fileobj=process.stdout, mode="r|")
    state = hashlib.sha256()
    for relative, archive_path, expected_hash in entries:
        member = tar_stream.next()
        if member is None or member.name != archive_path or not member.isfile():
            process.kill()
            process.wait()
            stderr_thread.join()
            raise RuntimeError("active report-site file list differs from volume")
        file_state = hashlib.sha256()
        state.update(relative.encode())
        state.update(b"\0")
        source = tar_stream.extractfile(member)
        remaining = member.size
        while remaining:
            data = source.read(min(chunk_size, remaining))
            if not data:
                process.kill()
                process.wait()
                stderr_thread.join()
                raise RuntimeError("active report-site file stream is truncated")
            file_state.update(data)
            state.update(data)
            remaining -= len(data)
        state.update(b"\0")
        if file_state.hexdigest() != expected_hash:
            process.kill()
            process.wait()
            stderr_thread.join()
            raise RuntimeError("active report-site file hash mismatch")
    if tar_stream.next() is not None:
        process.kill()
        process.wait()
        stderr_thread.join()
        raise RuntimeError("active report-site tar contains an unexpected file")
    status = process.wait()
    stderr_thread.join()
    if status or stderr_result[0][1] or state.hexdigest() != digest:
        raise RuntimeError("active report-site digest verification failed")
    return len(files), len(asset_names)


try:
    pointer_bytes = run_small(site_run("bash", "-c", \
        "if [[ -L /site/current ]]; then readlink -- /site/current; elif [[ -e /site/current ]]; then exit 2; else printf 'none\\n'; fi"), limit=256)
    current_target = pointer_bytes.decode("ascii").strip()
    match = re.fullmatch(r"releases/([a-f0-9]{64})", current_target)
    site_digest = match.group(1) if match else current_target
    if site_digest not in {"none"} and not digest_re.fullmatch(site_digest):
        raise RuntimeError("report-site current pointer is invalid")

    stdout.write(magic)
    helper_stream = open(helper_path, "rb")
    db_sha, db_stderr = stream_process_record(
        "database.dump",
        ["podman", "exec", "-i", "nous-db", "env", "NOUS_SNAPSHOT_DATABASE_ONLY=1", "bash", "-s"],
        stdin=helper_stream,
        stderr_required=True,
    )
    helper_stream.close()
    db_lines = [line for line in db_stderr.decode("utf-8", errors="replace").splitlines()
                if line.startswith("NOUS_SNAPSHOT_METADATA=")]
    if len(db_lines) != 1 or len(db_stderr.splitlines()) != 1:
        raise RuntimeError("database snapshot metadata is missing or ambiguous")
    db_metadata = db_lines[0].removeprefix("NOUS_SNAPSHOT_METADATA=")
    db_match = snapshot_re.fullmatch(db_metadata)
    if not db_match:
        raise RuntimeError("database snapshot metadata is malformed")
    (schema, sources, items, versions, runs, schedules, reports, evidence, db_digest) = db_match.groups()
    if db_digest != site_digest:
        raise RuntimeError("database and report-site active digests differ")

    site_manifest_sha = "none"
    site_file_count = site_asset_count = 0
    manifest = None
    if site_digest != "none":
        manifest_bytes = run_small(site_run("bash", "-c", \
            f"test ! -L /site/.manifests/{site_digest}.json && test -f /site/.manifests/{site_digest}.json && cat /site/.manifests/{site_digest}.json"),
            limit=max_small_output)
        site_manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
        manifest = json.loads(manifest_bytes)
        site_file_count, site_asset_count = stream_active_files(site_digest, manifest)

    site_tar_command = ["podman", "run", "--rm", "-i", "--network", "none",
                        f"--volume={volume}:/site:ro", "--entrypoint", "tar", postgres_image,
                        "--numeric-owner", "-C", "/site", "-cf", "-", "."]
    site_sha, _ = stream_process_record("report-site.tar", site_tar_command)

    created = os.getenv("NOUS_BACKUP_CREATED_AT") or __import__("datetime").datetime.now( \
        __import__("datetime").timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    internal_manifest = {
        "format": "nous-report-site-backup-stream-v1",
        "created_at": created,
        "schema_version": schema,
        "counts": {
            "sources": int(sources), "items": int(items), "item_versions": int(versions),
            "report_runs": int(runs), "report_schedules": int(schedules),
            "reports": int(reports), "report_evidence": int(evidence),
        },
        "report_site": {"active_digest": db_digest, "file_count": site_file_count,
                        "asset_count": site_asset_count, "manifest_sha256": site_manifest_sha},
        "checksums": {"database_dump_sha256": db_sha, "report_site_archive_sha256": site_sha},
    }
    manifest_bytes = json.dumps(internal_manifest, sort_keys=True, separators=(",", ":")).encode()
    if len(manifest_bytes) > 1024 * 1024:
        raise RuntimeError("backup manifest exceeds limit")
    _record_header("manifest.json")
    _record_chunk(manifest_bytes)
    _record_end()
    stdout.flush()
    print(f"NOUS_SNAPSHOT_METADATA={db_metadata}", file=sys.stderr)
    print(f"NOUS_SITE_METADATA={db_digest}|{site_file_count}|{site_asset_count}|{site_manifest_sha}|{db_sha}|{site_sha}", file=sys.stderr)
except (OSError, ValueError, RuntimeError, tarfile.TarError, json.JSONDecodeError) as exc:
    print(f"nous-snapshot: {str(exc) or type(exc).__name__}", file=sys.stderr)
    raise SystemExit(1)
PY
