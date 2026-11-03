#!/usr/bin/env bash
# Invoked in PostgreSQL container via podman exec -i bash -s.
# stdout: PostgreSQL custom archive; stderr: snapshot-aligned metadata.
set -Eeuo pipefail

coproc SNAPSHOT_SQL { psql -X -qAt -F '|' -v ON_ERROR_STOP=1 -U nous -d nous; }
sql_in=${SNAPSHOT_SQL[1]}
sql_out=${SNAPSHOT_SQL[0]}
sql_pid=$SNAPSHOT_SQL_PID

printf '%s\n' \
  'BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;' \
  'SELECT pg_export_snapshot();' \
  'SELECT (SELECT version_num FROM alembic_version), (SELECT count(*) FROM sources), (SELECT count(*) FROM items), (SELECT count(*) FROM item_versions);' \
  >&"$sql_in"
IFS= read -r snapshot <&"$sql_out" || exit 1
IFS= read -r metadata <&"$sql_out" || exit 1
[[ "$snapshot" =~ ^[0-9A-Fa-f-]+$ ]] || exit 1
[[ "$metadata" =~ ^[A-Za-z0-9._-]+\|[0-9]+\|[0-9]+\|[0-9]+$ ]] || exit 1

# pg_dump and the row counts use the exact same exported snapshot.
pg_dump --snapshot="$snapshot" -U nous -d nous -Fc
printf 'COMMIT;\n\\q\n' >&"$sql_in"
wait "$sql_pid"
printf 'NOUS_SNAPSHOT_METADATA=%s\n' "$metadata" >&2
