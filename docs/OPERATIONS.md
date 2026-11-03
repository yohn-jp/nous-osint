# Nous OSINT operations

This runbook targets the dedicated `nous` OS account on the single VM. It assumes
rootless Podman 5.7, cgroup v2, PostgreSQL 18 and systemd user services. Run
commands as `nous` with `XDG_RUNTIME_DIR=/run/user/$(id -u nous)`.

## Installation and updates

1. Install Podman and `uidmap`; create a dedicated unprivileged `nous` account.
   Enable lingering with `loginctl enable-linger nous`.
2. Build the application image from `Containerfile`. Record its immutable image
   ID and insert it into the three app Quadlets. Pin PostgreSQL to its reviewed
   registry digest. Copy the Quadlets into `~nous/.config/containers/systemd/`.
3. Create 0600 temporary files containing a randomly generated DB password and
   `postgresql+psycopg://nous:<password>@nous-db:5432/nous`. Import them as
   Podman secrets `nous-db-password`, `nous-database-url` (migrations),
   `nous-api-database-url` and
   `nous-runtime-database-url` after provisioning separate `nous_api` and
   `nous_runtime` SQL roles. For remote MCP, provision a `nous_mcp` role with
   SELECT-only grants and import its URL as `nous-mcp-database-url`, then securely
   remove the temporary files. Never put a password in Git or a Quadlet.
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

The VM-side MCP services and read-only role were deployed and verified on
2026-11-03, including automatic recovery and a full VM reboot. The loaded Tunnel
route points to the MCP origin with Access required; Cloudflare resources and
application policy/IdP/OAuth settings were not changed. A real OAuth client
flow remains unverified; see [REMOTE_MCP_ACCESS.md](REMOTE_MCP_ACCESS.md).

Run migrations before rolling out a new image. The API and worker retry database
connection failures. Inspect user journals with `journalctl --user -u nous-worker`.

## Backup and restore

Run the backup pull from a separate, always-on backup host with SSH access to the
VM.
Install both `scripts/backup-pull.sh` and `scripts/snapshot-dump.sh` together on
the backup host. The latter is streamed over SSH into the DB container. Keep its backup directory on storage outside the VM; the script streams
`pg_dump -Fc` over SSH directly into GPG encryption, so
no plaintext dump is written to disk. GPG must be installed on the backup host,
and its keyring must contain a public key whose full fingerprint was verified
out of band. Keep the matching private key separately from the backup files.

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

The archive and schema/row counts use a single PostgreSQL exported
repeatable-read snapshot (`pg_dump --snapshot`), not a later live query.
Each `.dump.gpg` has a JSON manifest with schema version, row counts, and the
encrypted artifact SHA-256. Validate it with:

```sh
scripts/restore-test.sh ~/.local/state/nous-osint/backups/<backup>.dump.gpg
```

This decrypts into a temporary, isolated PostgreSQL container and volume,
restores without ACL/owner assumptions, verifies all recorded row counts, then
removes the test database resources. Keep a verified off-VM copy of the
decryption key; the backup host's public key alone cannot restore data. Never
copy live PGDATA as a generic archive. Do not commit dumps or keys.

On 2026-11-03 the off-VM backup host produced an encrypted dump and manifest,
then decrypted that exact artifact into an isolated PostgreSQL 18 container and
volume. Schema `0004`, five sources, 540 items and 540 versions matched the
manifest. The backup timer is enabled on that host; the recipient private key
remains outside the repository under the backup user's GPG keyring.

## Network and sources

PostgreSQL has no host port publication. The API publishes only
`127.0.0.1:8000`. Source policy notes and intervals are in `sources/`; every
change to that registry requires review. Missing jobs do not imply closure.
The scheduler is a singleton; do not start another copy of its Quadlet.
