# Nous OSINT — Single-VM Podman / Quadlet Deployment Design

Status: **initial VM deployment verified on 2026-11-03; see the deployment record below**
Updated: 2026-11-03

## 1. Operating assumptions

- One Linux VM, systemd, cgroup v2 and a distribution-supported Podman release with Quadlet.
- A dedicated non-privileged OS user, e.g. `nous`; rootless services and volumes belong to that user.
- Initial sizing **guideline**, not a benchmark: 4 vCPU, 8 GiB RAM, 100 GiB SSD, then observe queue, memory and database growth.
- The VM provides outgoing HTTPS and DNS. No incoming internet traffic is necessary.
- Use local PostgreSQL in a **separate Podman container**, not host-installed PostgreSQL.
- SELinux/AppArmor and the distribution's rootless networking model must be checked on the chosen host. Do not disable MAC confinement to make a deployment work.

## 2. Service layout

The repository contains reproducible Quadlet definitions in `deploy/quadlet/`:

| Quadlet file | Generated systemd unit | Responsibility |
| --- | --- | --- |
| `nous.network` | `nous-network.service` | Private application network |
| `nous-ingress.network` | `nous-ingress-network.service` | Isolated MCP ingress; cloudflared does not join the database network |
| `nous-db.volume` | `nous-db-volume.service` | Persistent PostgreSQL files |
| `nous-db.container` | `nous-db.service` | PostgreSQL |
| `nous-api.container` | `nous-api.service` | FastAPI retrieval API |
| `nous-mcp.container` | `nous-mcp.service` | Read-only MCP origin on backend and ingress networks |
| `nous-tunnel.container` | `nous-tunnel.service` | Outbound-only cloudflared connector on ingress network |
| `nous-scheduler.container` | `nous-scheduler.service` | One scheduling process |
| `nous-worker.container` | `nous-worker.service` | Fetch/parse/normalize worker |

App containers use the same pinned image but distinct startup commands. Use explicit units/dependencies for DB before API/scheduler/worker; app processes must independently retry until the DB is genuinely ready. Unit ordering is **not** a readiness guarantee.

No `podman-compose` or Docker daemon. No API container receives a mounted Podman socket. Network DNS/aliases must be checked against the installed Podman version. PostgreSQL must not publish a host port. Bind the read API only to `127.0.0.1:8000` (or to a private authenticated ingress introduced later).

### Rootless Quadlet conventions

Files live under `~nous/.config/containers/systemd/`; install with the dedicated user's ownership and permissions. Reload and manage generated services using `systemctl --user` within that user's systemd manager. Configure lingering with `loginctl enable-linger nous` so services survive logout and start after reboot. Do **not** attempt to make rootless Quadlets by adding `User=nous` to a system-level Quadlet.

Example **design sketch only**, not an executable deployment artifact:

```ini
# nous-api.container (planned)
[Unit]
Description=Nous OSINT API
Requires=nous-db.service
After=nous-db.service

[Container]
Image=ghcr.io/OWNER/nous-osint@sha256:REPLACE_WITH_REVIEWED_DIGEST
Network=nous.network
PublishPort=127.0.0.1:8000:8000
# Load DB secret through a Podman secret mount; no password literals.
Exec=python -m nous.api

[Service]
Restart=on-failure
TimeoutStartSec=300

[Install]
WantedBy=default.target
```

Replace the image placeholder, command, secret wiring and health checks only after those components exist. `Network=nous.network` and `Volume=nous-db.volume:/path` create implicit Quadlet service dependencies on their respective network/volume units.

## 3. PostgreSQL persistence and versioning

Prefer an explicitly pinned PostgreSQL **major and image digest**. PostgreSQL 18 is the proposed initial implementation target, **not** an assertion of the newest available major. The official image for version 18+ stores version-specific PGDATA under `/var/lib/postgresql/<major>/docker` and its documented persistent volume root is `/var/lib/postgresql`. Mount the named volume there when using PostgreSQL 18. Do not copy the older PostgreSQL 17-and-earlier mount pattern blindly.

- Keep data in the Quadlet-managed `nous-db.volume`; no ephemeral container writable layer for DB files.
- DB startup must use a securely provisioned password secret. Do not enable `trust` host authentication.
- Expose DB only to the private Podman network; the API/worker use the least-privilege SQL roles needed for their responsibilities.
- Restrict connections; design separate migration and runtime roles.
- Disable automatic registry-driven updates for PostgreSQL. Backup, verify restoration and review migration compatibility before upgrades.
- Apply schema changes via a dedicated one-off migration command before restarting app services. Failed migration must stop deployment.

## 4. Secrets, images and updates

- Secrets are created and stored **only on the VM** with appropriate permissions (Podman secrets or systemd credentials). Application code reads them from mounted files. No password in Quadlet source, logs, command-line arguments, committed `.env` files or image layers.
- Explicitly pin image digests in deployed units. Review image updates, rebuild with a reproducible Containerfile, then roll out and health-check.
- Treat major PostgreSQL upgrades as a separate migration procedure. Verify an off-VM backup **and successful test restore** before altering data volumes.
- Provide resource limits and safe restart policy; avoid retry storms. The scheduler must remain single-instance even if other services are restarted.
- Keep dependencies and application images updated by an explicit review process; unattended database auto-update is forbidden.

## 5. Operations runbook (to validate during implementation)

Before installing:
```sh
podman info --format '{{.Host.CgroupsVersion}}'  # expect v2
podman --version
systemctl --version
# Run once as an authorized administrator:
sudo loginctl enable-linger nous
```

After Quadlet files are installed as the `nous` user:
```sh
systemctl --user daemon-reload
systemctl --user start nous-db.service
systemctl --user start nous-api.service nous-scheduler.service nous-worker.service
systemctl --user status nous-db.service nous-api.service nous-scheduler.service nous-worker.service
journalctl --user -u nous-worker.service -n 100 --no-pager
```

Generated systemd unit names are derived from Quadlet filenames; after installation verify the generated services and their dependency graph. On failed generation use Podman's Quadlet generator in dry-run mode for the installed version. The initial VM-specific procedures were exercised; see the record below.

## 6. Initial VM deployment record (2026-11-03)

- `nous` is a non-root account with lingering enabled. Its user manager has an active D-Bus user bus at `/run/user/1001`; services remained available across separate SSH sessions.
- The MCP process uses Podman Secret `nous-mcp-database-url` for the dedicated `nous_mcp` role. The role can `SELECT` and cannot `INSERT`, `UPDATE` or `DELETE` application tables. Future tables created by the `nous` migration role receive default `SELECT` grants.
- `nous-mcp.service` uses the pinned local application image, publishes no host port, and joins `nous-private` plus `nous-ingress`. `nous-tunnel.service` uses the pinned cloudflared 2026.10.3 image and joins only `nous-ingress`. Both units use restart-on-failure and are in the user manager's default target.
- `~/.config/nous/mcp.env` on the VM is mode 0600 and contains the configured Access issuer and audience. The Tunnel token remains only in Podman Secret `nous-tunnel-token`.
- Verified on the VM: an in-process MCP protocol harness using a synthetic test identity completed `initialize`, `tools/list` and read-only `get_source_status` `tools/call` against the deployed image and live SELECT-only database role. The actual listener rejects missing/forged assertions. `tests/test_access_auth.py` passed 10 tests, including invalid signature, audience and expiry cases. `/health`, `/docs` and `/api/v1` return 404 at the origin; external HTTPS returned 401 after reboot (403 before reboot); the Tunnel registered four edge connections.
- `nous-mcp.service` and `nous-tunnel.service` were each killed once and systemd restarted them automatically. A full VM reboot at 11:35:52 UTC restored all six user services; PostgreSQL became healthy, the API readiness endpoint returned `{"status":"ok","schema":"0004"}`, and the Tunnel re-registered four connections.
- The Tunnel's loaded runtime route in its local startup log shows `nous.yohn.jp` -> `http://nous-mcp:8001`, Access `required=true`, team `zenprax` and the configured audience. No Cloudflare resources or Access/IdP/OAuth settings were changed. The application policy's allowed IdP/email, Managed OAuth/DCR behavior, GitHub login and a real OAuth client remain unverified.

## 7. Backup, restore and disaster recovery

- Daily logical `pg_dump`-based backup (plus schema/version manifest); encrypt and push backups to a location **outside the VM**.
- Keep at least a 7-day rolling retention initially, configurable subject to volume, source terms and restore testing.
- For consistent backup, use the PostgreSQL-supported backup mechanism; do not copy a live PGDATA directory as a generic file archive.
- Perform a periodic restore into a separate isolated instance, run migrations/readiness checks and verify source/item/version counts and a representative history query.
- Initial **targets**, to validate rather than promise: RPO ≤24 hours and RTO ≤4 hours. If tests fail, report actual recovery performance and revise capacity/plan.
- Monitor free disk, failed backup, stale source polls, failed services and persistent queue backlog.

## 8. Definition of deployed

Deployment is not complete until these are observed on the target VM:

1. Rootless user services survive logout and reboot; no lingering-dependent failure.
2. API and PostgreSQL can restart independently; DB records persist.
3. Database port is not internet- or host-published; API is bound to loopback.
4. Secrets are not present in repository, `podman inspect` environment output, or logs.
5. Scheduler/worker recover claimed jobs after a crash without creating duplicate versions.
6. Backups restore successfully to another isolated volume/instance.
7. The monitored source integration produces traceable records and meaningful source-level health.

## References

- [Podman Quadlet official manual](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [Podman Quadlet basic usage](https://docs.podman.io/en/latest/markdown/podman-quadlet-basic-usage.7.html)
- [Official PostgreSQL container image documentation](https://github.com/docker-library/docs/blob/master/postgres/README.md)
