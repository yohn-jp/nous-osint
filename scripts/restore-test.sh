#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

fail() { printf 'nous-restore-test: %s\n' "$*" >&2; exit 1; }
for command_name in gpg sha256sum cut python3 podman seq sleep; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done

archive=${1:-}
[[ -n "$archive" && -f "$archive" ]] || fail "usage: restore-test.sh BACKUP.dump.gpg [MANIFEST.json]"
manifest=${2:-${archive%.dump.gpg}.manifest.json}
[[ -f "$manifest" ]] || fail "backup manifest not found: $manifest"

read -r schema_version expected_sources expected_items expected_versions expected_hash expected_artifact < <(
  python3 - "$manifest" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    m = json.load(stream)
print(m["schema_version"], m["sources"], m["items"], m["item_versions"], m["sha256"], m["artifact"])
PY
)
[[ "$(basename -- "$archive")" == "$expected_artifact" ]] || fail "manifest artifact name mismatch"
actual_hash=$(sha256sum -- "$archive" | cut -d ' ' -f 1)
[[ "$actual_hash" == "$expected_hash" ]] || fail "encrypted artifact checksum mismatch"

image=${NOUS_RESTORE_POSTGRES_IMAGE:-docker.io/library/postgres@sha256:f4b419e350fd98d4a8429603295208976dea4c8fb8326d818d346d3e29f1db6f}
[[ "$image" =~ ^[a-zA-Z0-9./:@_-]+$ ]] || fail "invalid PostgreSQL image reference"
suffix=$(python3 -c 'import secrets; print(secrets.token_hex(6))')
container="nous-restore-${suffix}"
volume="nous-restore-${suffix}"
secret="nous-restore-${suffix}"
tmp_password=$(mktemp)
trap 'podman rm -f "$container" >/dev/null 2>&1 || true; podman volume rm "$volume" >/dev/null 2>&1 || true; podman secret rm "$secret" >/dev/null 2>&1 || true; rm -f "$tmp_password"' EXIT
python3 -c 'import secrets; print(secrets.token_hex(32), end="")' > "$tmp_password"
chmod 600 "$tmp_password"
podman secret create "$secret" "$tmp_password" >/dev/null
podman volume create "$volume" >/dev/null
podman run -d --name "$container" --volume "$volume:/var/lib/postgresql" \
  --network none \
  --secret "$secret,type=mount,target=/run/secrets/db_password" \
  --env POSTGRES_DB=nous --env POSTGRES_USER=nous \
  --env POSTGRES_PASSWORD_FILE=/run/secrets/db_password "$image" >/dev/null
rm -f "$tmp_password"

ready=0
for _ in $(seq 1 60); do
  if podman exec "$container" pg_isready -U nous -d nous >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
(( ready == 1 )) || fail "isolated PostgreSQL did not become ready"

if ! gpg --batch --quiet --decrypt -- "$archive" | podman exec -i "$container" bash -c \
    'export PGPASSWORD="$(cat /run/secrets/db_password)"; exec pg_restore --no-owner --no-acl -U nous -d nous'; then
  fail "decrypt or restore failed"
fi

actual=$(podman exec "$container" bash -c \
  'export PGPASSWORD="$(cat /run/secrets/db_password)"; exec psql -v ON_ERROR_STOP=1 -U nous -d nous -AtF "|" -c "SELECT (SELECT version_num FROM alembic_version), (SELECT count(*) FROM sources), (SELECT count(*) FROM items), (SELECT count(*) FROM item_versions)"')
expected="${schema_version}|${expected_sources}|${expected_items}|${expected_versions}"
[[ "$actual" == "$expected" ]] || fail "restored counts mismatch: expected ${expected}, got ${actual}"
printf 'Restore verified in isolated container and volume: schema=%s sources=%s items=%s versions=%s\n' \
  "$schema_version" "$expected_sources" "$expected_items" "$expected_versions"
