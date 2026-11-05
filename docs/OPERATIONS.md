# Nous OSINT operations

This runbook targets the dedicated `nous` OS account on the single VM. It assumes
rootless Podman 5.7, cgroup v2, PostgreSQL 18 and systemd user services. Run
commands as `nous` with `XDG_RUNTIME_DIR=/run/user/$(id -u nous)`.

## Installation and updates

1. Install Podman and `uidmap`; create a dedicated unprivileged `nous` account.
   Enable lingering with `loginctl enable-linger nous`.
2. Build the application image from `Containerfile` and the isolated report
   Worker image from `Containerfile.reports`. Record each immutable image digest
   from CI. Update the MCP and API references to the reviewed application digest
   and the report Worker Quadlet to the report image digest. Pin PostgreSQL to
   its reviewed registry digest. Copy the Quadlets and volume units into
   `~nous/.config/containers/systemd/`.
3. Create 0600 temporary files containing a randomly generated DB password and
   `postgresql+psycopg://nous:<password>@nous-db:5432/nous`. Import them as
   Podman secrets `nous-db-password`, `nous-database-url` (migrations),
   `nous-api-database-url` and
   `nous-runtime-database-url` after provisioning separate `nous_api` and
   `nous_runtime` SQL roles. For remote MCP, provision a `nous_mcp` role with
   SELECT-only grants and import its URL as `nous-mcp-database-url`. Provision
   `nous_report_worker` before migrations `0009`/`0010` so their conditional CVE/KEV
   grant can apply. Create `nous_admin` before applying the report admin grants
   below. Import the Worker URL as `nous-report-worker-database-url`. Securely
   remove temporary files. Never put a password in Git or a Quadlet.
4. Run `systemctl --user daemon-reload`; start `nous-db.service`. Wait for
   `podman exec nous-db pg_isready -U nous -d nous` to succeed.
5. Run the migration as a one-off container on `nous-private` with the database
   migration/admin URL secret mounted at `/run/secrets/database_url` and
   `DATABASE_URL_FILE=/run/secrets/database_url`, invoking `alembic upgrade head`.
   After migration `0004`, run `python -m nous.maintenance` once with the
   runtime database secret to populate typed organization and publisher dates
   from existing immutable versions.
6. Start `nous-api.service nous-scheduler.service nous-worker.service` and check
   `/health/ready` over VM loopback. For remote MCP, install
   `nous-mcp.container` and `nous-ingress.network`, set `CF_ACCESS_ISSUER` and
   `CF_ACCESS_AUDIENCE` in mode-0600 `~/.config/nous/mcp.env`, then start
   `nous-mcp.service` and `nous-tunnel.service`. The same origin serves the
   static UI at `/` and its allowlisted GET API under `/v1`. The tunnel joins
   only `nous-ingress`; PostgreSQL has no host-published port. Quadlet's `[Install]` section generates
   `default.target.wants` links; generated units cannot be enabled with
   `systemctl --user enable`.

After role creation and `alembic upgrade head` has applied migration `0010`,
apply the report and admin table grants below. Provision `nous_report_worker`
before migrations `0009`/`0010` when possible, or apply their conditional
table grants explicitly afterward as described below. The report Worker reads only the source observation
tables it needs and has no DELETE privilege:

```sql
GRANT CONNECT ON DATABASE nous TO nous_report_worker;
GRANT USAGE ON SCHEMA public TO nous_report_worker;
GRANT SELECT ON sources, items, item_versions, cve_item_links TO nous_report_worker;
GRANT SELECT, INSERT, UPDATE ON report_runs, report_schedules TO nous_report_worker;
GRANT SELECT, INSERT ON reports, report_evidence TO nous_report_worker;
GRANT SELECT, INSERT, UPDATE ON report_site_state TO nous_report_worker;

GRANT SELECT, INSERT, UPDATE ON report_runs, report_schedules TO nous_admin;
GRANT SELECT ON reports TO nous_admin;
```

Migrations `0009`/`0010` conditionally grant access to the immutable CVE relation and KEV catalog journal tables
when these pre-existing roles are present. If a role is provisioned after the
migration, apply only these table grants as the database owner:

```sql
GRANT INSERT ON cve_item_version_links TO nous_runtime;
GRANT SELECT ON cve_item_version_links TO nous_api, nous_mcp, nous_report_worker;
GRANT INSERT ON kev_catalog_contents, kev_catalog_observations TO nous_runtime;
GRANT SELECT ON kev_catalog_contents, kev_catalog_observations TO nous_api, nous_mcp, nous_report_worker;
```

The collection runtime inserts immutable CVE relations and complete KEV catalog observations; read surfaces have SELECT-only access. Do not grant UPDATE, DELETE, TRUNCATE or blanket default privileges on these tables. Existing grants on other tables remain as provisioned above. Before the first successful post-0010 catalog observation, historical membership is not reconstructable: as-of reads must remain unknown rather than inventing evidence.

To verify the migration grant boundary, use a separate disposable database
migrated through `0008`. Set `DATABASE_URL` or `DATABASE_URL_FILE` to its admin
URL and run `.venv/bin/python scripts/test-cve-role-grants.py`. The script
creates the four canonical roles with temporary passwords, upgrades the
database through `0010`, tests each grant through that role's own connection,
then removes the roles and any fixture rows. Do not run it against the shared
application database; the URL must allow role creation and connections from the
test process.

The Access-subject allowlist still gates the admin API; `nous_admin` receives no
write grant on `reports` or `report_evidence`. Do not add blanket default
privileges for future tables. Reapply explicit least-privilege grants after a
migration that adds report tables. The Worker mounts `nous-report-site` read/write,
while the MCP gateway mounts it read-only. Private stage artifacts and Codex
state use separate persistent volumes. Keep the Worker secret role separate
from API, MCP, collection and migration roles.

Start `nous-report-worker.service` only after the `nous-report-worker-database-url`
Podman secret and named volume units exist. The container is rootless, has a
read-only root filesystem, mounts no Podman socket and exposes no listener. It
runs `python -m nous.report_worker`; its bundled Node/Astro dependencies are used
only for one-shot static builds. The image explicitly sets
`NOUS_REPORTS_DIR=/app/reports`: installed Python packages otherwise resolve
`__file__` under site-packages, not the application checkout. Astro's
`cacheDir` is a writable per-build project directory, and npm/tmp build cache
is placed under the private volume; do not make the image's read-only
`node_modules` writable or remove the Quadlet's `/tmp` size limit. A
PR image smoke check builds an empty Astro site with a read-only root filesystem
and the same 128 MiB `/tmp` tmpfs as production. After deploying the reviewed
image digest, remove any previous local override that dropped `size=128m`,
then start and verify `nous-report-worker.service` and the `/reports/` index.
This smoke check does not prove owner-authenticated Codex article generation.

The owner must authenticate the official CLI inside the private Codex volume.
Run the product-supported device flow as the isolated child identity, using a
terminal attached to the VM:

```sh
podman exec -it --user 10002:10002 \
  --env HOME=/var/lib/nous-codex --env CODEX_HOME=/var/lib/nous-codex \
  nous-report-worker codex login --device-auth
podman exec nous-report-worker codex --version
```

The expected CLI is `codex-cli 0.166.0`. Do not copy browser cookies, personal
tokens or ChatGPT credentials into Nous. Authentication, subscription limits,
VM networking, and the first owner-authorized generation require separate
operator verification; they are **NOT_CHECKED** by fixture-based CI.

The VM-side MCP services and read-only role were deployed and verified on
2026-11-03, including automatic recovery and a full VM reboot. The loaded Tunnel
route points to the MCP origin with Access required; Cloudflare resources and
application policy/IdP/OAuth settings were not changed. A real OAuth client
flow remains unverified; see [REMOTE_MCP_ACCESS.md](REMOTE_MCP_ACCESS.md).

Run migrations before rolling out a new image. The API and worker retry database
connection failures. Inspect user journals with `journalctl --user -u nous-worker`.

## Backup and restore

Run the backup pull from a separate, always-on backup host with SSH access to the
VM. Install `scripts/backup-pull.sh` and `scripts/snapshot-dump.sh` together on
that host. The helper is uploaded to the VM's `/dev/shm` for the duration of the
capture. GPG must be installed on the backup host, and its keyring must contain
a public key whose full fingerprint was verified out of band. Keep the matching
private key separately from the backup files.

```sh
install -d -m 700 ~/.config/nous-osint ~/.config/systemd/user ~/.local/libexec \
  ~/.local/state/nous-osint/backups
# Import the recipient public key after verifying its fingerprint out of band.
gpg --import /secure/path/nous-backup-recipient.asc
gpg --fingerprint
install -m 700 scripts/backup-pull.sh ~/.local/libexec/nous-backup-pull.sh
install -m 700 scripts/snapshot-dump.sh ~/.local/libexec/snapshot-dump.sh
install -m 600 deploy/backup/backup.env.example ~/.config/nous-osint/backup.env
# Set NOUS_BACKUP_GPG_RECIPIENT to the verified 40- or 64-hex public-key fingerprint.
systemctl --user daemon-reload
install -m 644 deploy/backup/nous-backup.service \
  ~/.config/systemd/user/nous-backup.service
install -m 644 deploy/backup/nous-backup.timer \
  ~/.config/systemd/user/nous-backup.timer
systemctl --user daemon-reload
systemctl --user enable --now nous-backup.timer
systemctl --user start nous-backup.service  # first-run check
```

Set `NOUS_BACKUP_HOST`, `NOUS_BACKUP_DIR`, and `NOUS_BACKUP_RETENTION_DAYS` in
`backup.env` as needed. The default destination is
`~/.local/state/nous-osint/backups`; it is off-VM when this service runs on the
separate backup host. For a second failure domain, choose a path on externally
mounted backup storage. If using a different directory, add it to
`ReadWritePaths=` in `nous-backup.service`. The configured host must be covered
by a verified SSH host key and allow non-interactive `sudo -u nous` for the
rootless Podman backup command. For a persistent backup host, enable lingering
for its user or use a system service. The timer runs daily and catches missed
runs with `Persistent=true`. It retains seven days by default and only prunes
old encrypted dumps after a new dump and manifest have been written.
`NOUS_BACKUP_SSH_CONFIG` can select an explicit SSH config file when the backup
host's systemd sandbox cannot read its system-wide SSH config.

The capture stops an active report Worker and remembers whether it must restart.
While publication is paused, it takes `pg_dump -Fc` and SQL row counts from one
exported repeatable-read snapshot, then streams the private report-site volume.
The database active digest must equal the volume's `current` symlink. The active
`.manifests/<digest>.json` file map is checked against every HTML page and
referenced static asset. A mismatch aborts the backup and still restarts a
previously active Worker. The dump and volume archive are framed and streamed
through bounded chunks directly to GPG; neither is staged in `/dev/shm` or on
persistent storage. Only the uploaded helper and small metadata/manifests use
tmpfs. The stream chunk size defaults to 1 MiB and can be set with
`NOUS_BACKUP_STREAM_CHUNK_BYTES` from 4 KiB to 8 MiB. Both the external
`.manifest.json.gpg` and `.backup.gpg` are encrypted to the verified recipient.
The encrypted stream contains `database.dump`, `report-site.tar` and an
internal manifest. Run `python3 scripts/test-snapshot-stream.py` to exercise a
multi-megabyte fixture through the bounded stream at a 4 KiB chunk size; it
checks the encrypted artifact and confirms no plaintext archive staging files
or new `/dev/shm` files are created.

Each external JSON manifest includes the encrypted artifact SHA-256, schema
version, source and report-table counts, active digest, active HTML/asset counts,
manifest hash, and inner database/site archive hashes. Validate it with:

```sh
scripts/restore-test.sh ~/.local/state/nous-osint/backups/<backup>.backup.gpg
```

The restore check accepts the current framed `.backup.gpg` stream and legacy
`.tar.gpg` report backups. It decrypts both formats incrementally: the DB dump
goes directly to an isolated PostgreSQL container and the site archive goes into
a disposable rootless Podman volume. No decrypted archive or dump is staged on
disk. It verifies schema and row counts, DB/site active digest, the release
manifest, each HTML page and asset hash, then removes the temporary container,
volumes, secret and tmpfs password. Run
`.venv/bin/python scripts/test-restore-formats.py` to create a disposable database
using the current Alembic migrations, build encrypted fixtures in memory, and
exercise both restore formats against real rootless Podman/PostgreSQL containers.
The fixture uses synthetic source data; this is not a full VM restore rehearsal.
Keep a verified off-VM copy of the decryption key; the backup host's public key
alone cannot restore data. Never copy live PGDATA as a generic archive. Do not
commit dumps or keys. A database-only `.dump.gpg` is rejected because it has no
report-site volume.

The report DB snapshot and filesystem archive are not a kernel-level atomic
cross-resource snapshot. The report Worker is stopped for the entire capture,
and the SQL active digest, `current` pointer, active manifest, page/asset hashes,
and checksums are compared. If publication is interrupted between a filesystem
promotion and its DB commit, the mismatch is detected and capture fails closed.
This coordination does not freeze unrelated API writes, but the PostgreSQL dump
and its row counts still use one database snapshot.

Automated report backup/restore and owner-authenticated VM acceptance are
**NOT_CHECKED** until an actual off-VM encrypted capture and restore plus the
separate authorized VM procedure have been run. CI only verifies fixture and
isolated restore paths.

## Network and sources

PostgreSQL has no host port publication. The API publishes only
`127.0.0.1:8000`. Source policy notes and intervals are in `sources/`; every
change to that registry requires review. Missing jobs do not imply closure.
The scheduler is a singleton; do not start another copy of its Quadlet.
