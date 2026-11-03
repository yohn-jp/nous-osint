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
   Podman secrets `nous-db-password` and `nous-database-url`, then securely
   remove the temporary files. Never put a password in Git or a Quadlet.
4. Run `systemctl --user daemon-reload`; start `nous-db.service`. Wait for
   `podman exec nous-db pg_isready -U nous -d nous` to succeed.
5. Run the migration as a one-off container on `nous-private` with the database
   URL secret mounted at `/run/secrets/database_url` and
   `DATABASE_URL_FILE=/run/secrets/database_url`, invoking `alembic upgrade head`.
6. Start `nous-api.service nous-scheduler.service nous-worker.service` and check
   `/health/ready` over VM loopback. Quadlet's `[Install]` section generates
   `default.target.wants` links; generated units cannot be enabled with
   `systemctl --user enable`.

Run migrations before rolling out a new image. The API and worker retry database
connection failures. Inspect user journals with `journalctl --user -u nous-worker`.

## Backup and restore

Produce a PostgreSQL custom dump with
`podman exec nous-db pg_dump -U nous -d nous -Fc`. Encrypt it before transfer
off the VM, retain the decryption key separately with 0600 permissions, and keep
at least seven daily copies. A backup is valid only after a restore test in a
separate PostgreSQL container and volume, including checks of `sources`, `items`,
`item_versions` and a representative item history. Never copy live PGDATA as
a generic archive. Do not commit dumps or keys.

The initial manual test restored a 519-item, 519-version dump into an isolated
PostgreSQL 18 container and volume. An encrypted off-VM backup was also produced
and decrypted successfully. Automated daily off-VM backups remain to be set up.

## Network and sources

PostgreSQL has no host port publication. The API publishes only
`127.0.0.1:8000`. Source policy notes and intervals are in `sources/`; every
change to that registry requires review. Missing jobs do not imply closure.
The scheduler is a singleton; do not start another copy of its Quadlet.
