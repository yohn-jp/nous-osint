#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

fail() { printf 'nous-backup: %s\n' "$*" >&2; exit 1; }

for command_name in ssh gpg sha256sum find mktemp date cut flock; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done

target=${NOUS_BACKUP_HOST:-nous.osint.vm}
backup_dir=${NOUS_BACKUP_DIR:-$HOME/.local/state/nous-osint/backups}
recipient=${NOUS_BACKUP_GPG_RECIPIENT:-}
retention_days=${NOUS_BACKUP_RETENTION_DAYS:-7}

[[ "$target" =~ ^[a-zA-Z0-9._@-]+$ && "$target" != -* ]] || fail "invalid SSH host alias"
[[ "$recipient" =~ ^([A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$ ]] || fail "set NOUS_BACKUP_GPG_RECIPIENT to a verified full OpenPGP fingerprint"
[[ "$retention_days" =~ ^[1-9][0-9]*$ ]] || fail "retention days must be a positive integer"
[[ "$backup_dir" = /* ]] || fail "NOUS_BACKUP_DIR must be an absolute path"

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

uid=$(ssh -T -o BatchMode=yes -o ConnectTimeout=15 "$target" id -u nous) || fail "cannot resolve remote nous UID"
[[ "$uid" =~ ^[0-9]+$ ]] || fail "remote UID is not numeric"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
base="nous-osint-${stamp}"
final_dump="$backup_dir/${base}.dump.gpg"
final_manifest="$backup_dir/${base}.manifest.json"
[[ ! -e "$final_dump" && ! -e "$final_manifest" ]] || fail "backup already exists for ${stamp}"
tmp_dump=$(mktemp "$backup_dir/.${base}.dump.gpg.XXXXXX")
tmp_manifest=$(mktemp "$backup_dir/.${base}.manifest.json.XXXXXX")
trap 'rm -f -- "$tmp_dump" "$tmp_manifest"' EXIT

remote=(cd /tmp '&&' sudo -u nous env HOME=/home/nous "XDG_RUNTIME_DIR=/run/user/${uid}" podman exec nous-db pg_dump -U nous -d nous -Fc)
if ! ssh -T -o BatchMode=yes -o ConnectTimeout=15 "$target" "${remote[*]}" \
    | gpg --batch --yes --trust-model always --recipient "$recipient" \
        --output "$tmp_dump" --encrypt; then
  fail "dump transfer or encryption failed"
fi
[[ -s "$tmp_dump" ]] || fail "encrypted dump is empty"
chmod 600 -- "$tmp_dump"

metadata_sql="SELECT (SELECT version_num FROM alembic_version), (SELECT count(*) FROM sources), (SELECT count(*) FROM items), (SELECT count(*) FROM item_versions)"
metadata=$(ssh -T -o BatchMode=yes -o ConnectTimeout=15 "$target" \
  "cd /tmp && sudo -u nous env HOME=/home/nous XDG_RUNTIME_DIR=/run/user/${uid} podman exec nous-db psql -v ON_ERROR_STOP=1 -U nous -d nous -AtF '|' -c \"${metadata_sql}\"") \
  || fail "could not read backup manifest metadata"
IFS='|' read -r schema_version source_count item_count version_count <<< "$metadata"
[[ "$schema_version" =~ ^[A-Za-z0-9._-]+$ && "$source_count" =~ ^[0-9]+$ && \
   "$item_count" =~ ^[0-9]+$ && "$version_count" =~ ^[0-9]+$ ]] \
   || fail "database returned malformed manifest metadata"

digest=$(sha256sum -- "$tmp_dump" | cut -d ' ' -f 1)
cat > "$tmp_manifest" <<EOF
{
  "format": "pg_dump-custom-encrypted",
  "created_at": "${stamp}",
  "source_host": "${target}",
  "schema_version": "${schema_version}",
  "sources": ${source_count},
  "items": ${item_count},
  "item_versions": ${version_count},
  "artifact": "${base}.dump.gpg",
  "sha256": "${digest}"
}
EOF
chmod 600 -- "$tmp_manifest"
mv -- "$tmp_dump" "$final_dump"
mv -- "$tmp_manifest" "$final_manifest"

# Retain N days; remove only matching backup artifacts after both new files exist.
while IFS= read -r -d '' old_dump; do
  old_manifest=${old_dump%.dump.gpg}.manifest.json
  rm -f -- "$old_dump" "$old_manifest"
done < <(find "$backup_dir" -maxdepth 1 -type f \
  -name 'nous-osint-*.dump.gpg' -mtime "+$((retention_days - 1))" -print0)
while IFS= read -r -d '' old_manifest; do
  old_dump=${old_manifest%.manifest.json}.dump.gpg
  [[ -e "$old_dump" ]] || rm -f -- "$old_manifest"
done < <(find "$backup_dir" -maxdepth 1 -type f \
  -name 'nous-osint-*.manifest.json' -mtime "+$((retention_days - 1))" -print0)

printf 'Created encrypted backup: %s\n' "$final_dump"
printf 'Manifest: %s\n' "$final_manifest"
