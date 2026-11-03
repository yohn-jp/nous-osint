#!/usr/bin/env bash
# Apply one CI-published application digest to all Nous rootless Quadlets.
# Run as the dedicated nous user on the VM, never as root.
set -euo pipefail

image="${1:-}"
if [[ ! "$image" =~ ^ghcr\.io/yohn-jp/nous-osint@sha256:[a-f0-9]{64}$ ]]; then
  echo "usage: $0 ghcr.io/yohn-jp/nous-osint@sha256:<64-lowercase-hex>" >&2
  exit 2
fi
if [[ "$(id -u)" == "0" ]]; then
  echo "run as the rootless nous OS user" >&2
  exit 2
fi

unit_dir="${NOUS_QUADLET_DIR:-${HOME}/.config/containers/systemd}"
services=(nous-api nous-mcp nous-scheduler nous-worker)
backup_dir="$(mktemp -d)"
applied=false
cleanup() { rm -rf "$backup_dir"; }
rollback() {
  if [[ "$applied" == "true" ]]; then
    echo "readiness failed, restoring previous Quadlet references" >&2
    for name in "${services[@]}"; do
      cp "$backup_dir/$name.container" "$unit_dir/$name.container"
    done
    systemctl --user daemon-reload
    systemctl --user restart "${services[@]/%/.service}" || true
  fi
}
trap 'rollback; cleanup' EXIT

for name in "${services[@]}"; do
  file="$unit_dir/$name.container"
  test -f "$file" || { echo "missing Quadlet: $file" >&2; exit 2; }
  grep -q '^Image=' "$file" || { echo "missing Image= in $file" >&2; exit 2; }
  cp "$file" "$backup_dir/$name.container"
done

# Pull by digest; registry credentials must already be available in the
# rootless user's Podman auth store (read-only credentials if GHCR is private).
podman pull "$image"
podman image inspect "$image" > /dev/null

for name in "${services[@]}"; do
  sed -i "s|^Image=.*$|Image=$image|" "$unit_dir/$name.container"
done
applied=true
systemctl --user daemon-reload
systemctl --user restart "${services[@]/%/.service}"

# Confirm that the new application API is serving against the migrated DB.
ready=false
for attempt in $(seq 1 30); do
  if curl -fsS --max-time 2 http://127.0.0.1:8000/health/ready >/dev/null; then
    ready=true
    break
  fi
  sleep 2
done
if [[ "$ready" != "true" ]]; then
  echo "API readiness failed" >&2
  exit 1
fi
for name in "${services[@]}"; do
  systemctl --user is-active --quiet "$name.service" || {
    echo "$name.service is not active" >&2
    exit 1
  }
done

applied=false
echo "Deployed immutable application image: $image"
