#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

fail() { printf 'nous-backup: %s\n' "$*" >&2; exit 1; }
for command_name in ssh gpg sha256sum find mktemp date cut flock sed wc python3 findmnt; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done

target=${NOUS_BACKUP_HOST:-nous.osint.vm}
backup_dir=${NOUS_BACKUP_DIR:-$HOME/.local/state/nous-osint/backups}
recipient=${NOUS_BACKUP_GPG_RECIPIENT:-}
retention_days=${NOUS_BACKUP_RETENTION_DAYS:-7}
ssh_config=${NOUS_BACKUP_SSH_CONFIG:-$HOME/.ssh/config}
ssh_options=(-T -o BatchMode=yes -o ConnectTimeout=15)
if [[ -f "$ssh_config" ]]; then ssh_options=(-F "$ssh_config" "${ssh_options[@]}"); fi

[[ "$target" =~ ^[a-zA-Z0-9._@-]+$ && "$target" != -* ]] || fail "invalid SSH host alias"
[[ "$recipient" =~ ^([A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$ ]] || fail "set NOUS_BACKUP_GPG_RECIPIENT to a verified full OpenPGP fingerprint"
[[ "$retention_days" =~ ^[1-9][0-9]*$ ]] || fail "retention days must be a positive integer"
[[ "$backup_dir" = /* ]] || fail "NOUS_BACKUP_DIR must be an absolute path"
[[ $(findmnt -n -o FSTYPE /dev/shm 2>/dev/null || true) == tmpfs ]] \
  || fail "/dev/shm must be a tmpfs for private manifest staging"

candidate_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
repo_root=
if [[ -e "$candidate_root/.git" ]]; then repo_root=$candidate_root; fi
mkdir -p -- "$backup_dir"
backup_dir=$(cd -- "$backup_dir" && pwd -P)
if [[ -n "$repo_root" ]]; then
  case "$backup_dir/" in
    "$repo_root/"*) fail "backup directory must be outside the repository" ;;
  esac
fi
chmod 700 -- "$backup_dir"
exec 9>"$backup_dir/.backup.lock"
flock -n 9 || fail "another backup is already running"

uid=$(ssh "${ssh_options[@]}" "$target" id -u nous) || fail "cannot resolve remote nous UID"
[[ "$uid" =~ ^[0-9]+$ ]] || fail "remote UID is not numeric"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
base="nous-osint-${stamp}"
final_archive="$backup_dir/${base}.tar.gpg"
final_manifest="$backup_dir/${base}.manifest.json.gpg"
[[ ! -e "$final_archive" && ! -e "$final_manifest" ]] || fail "backup already exists for ${stamp}"
tmp_archive=$(mktemp "$backup_dir/.${base}.tar.gpg.XXXXXX")
tmp_manifest_plain=$(mktemp "/dev/shm/${base}.manifest.json.XXXXXX")
tmp_manifest=$(mktemp "$backup_dir/.${base}.manifest.json.gpg.XXXXXX")
tmp_metadata=$(mktemp "/dev/shm/${base}.snapshot-metadata.XXXXXX")
snapshot_script="$(dirname -- "${BASH_SOURCE[0]}")/snapshot-dump.sh"
[[ -r "$snapshot_script" ]] || fail "snapshot helper missing: $snapshot_script"
remote_helper="/dev/shm/nous-snapshot-${stamp}-$$.sh"
remote_uploaded=0
published=0
cleanup() {
  status=$?
  trap - EXIT
  rm -f -- "$tmp_archive" "$tmp_manifest" "$tmp_manifest_plain" "$tmp_metadata"
  if (( remote_uploaded )); then
    ssh "${ssh_options[@]}" "$target" \
      "sudo -n -u nous env HOME=/home/nous XDG_RUNTIME_DIR=/run/user/${uid} rm -f -- ${remote_helper}" \
      >/dev/null 2>&1 || true
  fi
  if (( ! published )); then rm -f -- "$final_archive" "$final_manifest"; fi
  exit "$status"
}
trap cleanup EXIT

# Only helper code is uploaded. Its plaintext staging is on the VM's tmpfs;
# archive stdout goes directly into GPG on this backup host.
upload_command="sudo -n -u nous env HOME=/home/nous XDG_RUNTIME_DIR=/run/user/${uid} bash -c 'cat > ${remote_helper} && chmod 700 ${remote_helper}'"
remote_uploaded=1
ssh "${ssh_options[@]}" "$target" "$upload_command" < "$snapshot_script" \
  || fail "could not stage the backup helper on the VM"
run_command="sudo -n -u nous env HOME=/home/nous XDG_RUNTIME_DIR=/run/user/${uid} NOUS_BACKUP_CREATED_AT=${stamp} bash -c 'bash ${remote_helper}; status=\$?; rm -f -- ${remote_helper}; exit \$status'"
if ! ssh "${ssh_options[@]}" "$target" "$run_command" 2>"$tmp_metadata" \
      | gpg --batch --yes --trust-model always --recipient "$recipient" \
          --output "$tmp_archive" --encrypt; then
  fail "consistent database/site transfer or encryption failed"
fi
remote_uploaded=0
[[ -s "$tmp_archive" ]] || fail "encrypted archive is empty"
chmod 600 -- "$tmp_archive"

snapshot_metadata=$(sed -n 's/^NOUS_SNAPSHOT_METADATA=//p' "$tmp_metadata")
site_metadata=$(sed -n 's/^NOUS_SITE_METADATA=//p' "$tmp_metadata")
[[ $(wc -l < "$tmp_metadata") -eq 2 ]] || fail "snapshot helper returned unexpected metadata"
[[ "$snapshot_metadata" =~ ^[A-Za-z0-9._-]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|(none|[a-f0-9]{64})$ ]] \
  || fail "invalid database snapshot metadata"
[[ "$site_metadata" =~ ^(none|[a-f0-9]{64})\|[0-9]+\|[0-9]+\|(none|[a-f0-9]{64})\|[a-f0-9]{64}\|[a-f0-9]{64}$ ]] \
  || fail "invalid report-site snapshot metadata"
IFS='|' read -r schema_version source_count item_count version_count run_count schedule_count report_count evidence_count db_digest <<< "$snapshot_metadata"
IFS='|' read -r site_digest site_file_count site_asset_count site_manifest_hash db_sha site_sha <<< "$site_metadata"
[[ "$db_digest" == "$site_digest" ]] || fail "database and report-site active digests differ"

encrypted_sha=$(sha256sum -- "$tmp_archive" | cut -d ' ' -f 1)
python3 - "$tmp_manifest_plain" "$stamp" "$target" "${base}.tar.gpg" "$encrypted_sha" \
  "$schema_version" "$source_count" "$item_count" "$version_count" "$run_count" \
  "$schedule_count" "$report_count" "$evidence_count" "$db_digest" "$site_file_count" \
  "$site_asset_count" "$site_manifest_hash" "$db_sha" "$site_sha" <<'PY'
import json
from pathlib import Path
import re
import sys

(_, path, created, host, artifact, encrypted_sha, schema, sources, items, versions,
 runs, schedules, reports, evidence, active, site_files, site_assets, site_manifest,
 database_sha, site_sha) = sys.argv
sha_re = re.compile(r"[a-f0-9]{64}")
for value in (sources, items, versions, runs, schedules, reports, evidence, site_files, site_assets):
    if not value.isdigit():
        raise SystemExit("invalid backup row count")
for value in (encrypted_sha, database_sha, site_sha):
    if not sha_re.fullmatch(value):
        raise SystemExit("invalid backup checksum")
if active != "none" and not sha_re.fullmatch(active):
    raise SystemExit("invalid report-site active digest")
if site_manifest != "none" and not sha_re.fullmatch(site_manifest):
    raise SystemExit("invalid report-site manifest checksum")
manifest = {
    "format": "nous-report-site-backup-v1",
    "created_at": created,
    "source_host": host,
    "artifact": artifact,
    "sha256": encrypted_sha,
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
    "checksums": {"database_dump_sha256": database_sha,
                   "report_site_archive_sha256": site_sha},
}
Path(path).write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8")
Path(path).chmod(0o600)
PY
chmod 600 -- "$tmp_manifest_plain"
gpg --batch --yes --trust-model always --recipient "$recipient" \
  --output "$tmp_manifest" --encrypt "$tmp_manifest_plain"
chmod 600 -- "$tmp_manifest"
mv -- "$tmp_archive" "$final_archive"
mv -- "$tmp_manifest" "$final_manifest"
published=1

# Retain N days; prune only matching encrypted artifact/manifest pairs.
while IFS= read -r -d '' old_archive; do
  old_manifest=${old_archive%.tar.gpg}.manifest.json.gpg
  rm -f -- "$old_archive" "$old_manifest"
done < <(find "$backup_dir" -maxdepth 1 -type f \
  -name 'nous-osint-*.tar.gpg' -mtime "+$((retention_days - 1))" -print0)
while IFS= read -r -d '' old_manifest; do
  old_archive=${old_manifest%.manifest.json.gpg}.tar.gpg
  [[ -e "$old_archive" ]] || rm -f -- "$old_manifest"
done < <(find "$backup_dir" -maxdepth 1 -type f \
  -name 'nous-osint-*.manifest.json.gpg' -mtime "+$((retention_days - 1))" -print0)

printf 'Created encrypted database + report-site backup: %s\n' "$final_archive"
printf 'Manifest: %s\n' "$final_manifest"
