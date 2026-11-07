#!/usr/bin/env python3
"""Real rootless Podman/PostgreSQL rehearsal for both report backup formats."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
RESTORE = ROOT / "scripts" / "restore-test.sh"
DEFAULT_IMAGE = "docker.io/library/postgres@sha256:f4b419e350fd98d4a8429603295208976dea4c8fb8326d818d346d3e29f1db6f"


def run(command: list[str], *, input: bytes | None = None, env=None, check=True) -> bytes:
    result = subprocess.run(command, input=input, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, check=False)
    if check and result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"{result.stderr.decode(errors='replace')}"
        )
    return result.stdout


def run_tar(source: Path) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        archive.add(source, arcname=".", recursive=True)
    return buffer.getvalue()


def file_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_site(root: Path) -> tuple[str, dict, bytes]:
    content = {
        "index.html": b"<!doctype html><title>Restore fixture</title><h1>Fixture release</h1>\n",
        "_astro/app.js": b"document.documentElement.dataset.restoreFixture = 'ok';\n",
    }
    state = hashlib.sha256()
    hashes = {}
    for relative, data in sorted(content.items()):
        hashes[relative] = file_digest(data)
        state.update(relative.encode())
        state.update(b"\0")
        state.update(data)
        state.update(b"\0")
    digest = state.hexdigest()
    (root / "releases" / digest).mkdir(parents=True)
    (root / "_astro").mkdir()
    (root / ".manifests").mkdir()
    (root / "releases" / digest / "index.html").write_bytes(content["index.html"])
    (root / "_astro" / "app.js").write_bytes(content["_astro/app.js"])
    manifest = {
        "digest": digest,
        "files": hashes,
        "html_files": ["index.html"],
        "assets": ["app.js"],
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    (root / ".manifests" / f"{digest}.json").write_bytes(manifest_bytes)
    (root / "current").symlink_to(f"releases/{digest}")
    metadata = {
        "active_digest": digest,
        "file_count": len(hashes),
        "asset_count": 1,
        "manifest_sha256": file_digest(manifest_bytes),
    }
    return digest, metadata, run_tar(root)


def frame_stream(records: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    output.write(b"NOUS-REPORT-BACKUP-STREAM\0\1")
    for name, payload in records:
        encoded = name.encode("ascii")
        output.write(struct.pack(">H", len(encoded)))
        output.write(encoded)
        for offset in range(0, len(payload), 65536):
            block = payload[offset:offset + 65536]
            output.write(struct.pack(">I", len(block)))
            output.write(block)
        output.write(b"\0\0\0\0")
    return output.getvalue()


def legacy_tar(records: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, payload in records:
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mode = 0o600
            member.mtime = 0
            archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


def encrypt_file(gnupg: Path, fingerprint: str, target: Path, content: bytes, env: dict) -> None:
    run(["gpg", "--batch", "--yes", "--homedir", str(gnupg), "--trust-model", "always",
         "--recipient", fingerprint, "--output", str(target), "--encrypt"], input=content, env=env)


def write_backup(work: Path, gnupg: Path, fingerprint: str, env: dict, *, kind: str,
                 database_dump: bytes, site_archive: bytes, schema: str, counts: dict,
                 site: dict) -> Path:
    stamp = "20261104T000000Z"
    format_name = ("nous-report-site-backup-stream-v1" if kind == "stream"
                   else "nous-report-site-backup-v1")
    suffix = ".backup.gpg" if kind == "stream" else ".tar.gpg"
    artifact_name = f"nous-osint-{kind}-{stamp}{suffix}"
    checksums = {
        "database_dump_sha256": file_digest(database_dump),
        "report_site_archive_sha256": file_digest(site_archive),
    }
    internal = {
        "format": format_name,
        "created_at": stamp,
        "schema_version": schema,
        "counts": counts,
        "report_site": site,
        "checksums": checksums,
    }
    internal_bytes = json.dumps(internal, sort_keys=True, separators=(",", ":")).encode()
    if kind == "stream":
        payload = frame_stream([
            ("database.dump", database_dump),
            ("report-site.tar", site_archive),
            ("manifest.json", internal_bytes),
        ])
    else:
        payload = legacy_tar([
            ("manifest.json", internal_bytes),
            ("database.dump", database_dump),
            ("report-site.tar", site_archive),
        ])
    artifact = work / artifact_name
    encrypt_file(gnupg, fingerprint, artifact, payload, env)
    outer = {
        "format": format_name,
        "created_at": stamp,
        "source_host": "rootless-podman-fixture",
        "artifact": artifact_name,
        "sha256": file_digest(artifact.read_bytes()),
        "schema_version": schema,
        "counts": counts,
        "report_site": site,
        "checksums": checksums,
    }
    manifest_name = artifact_name.removesuffix(suffix) + ".manifest.json.gpg"
    manifest = work / manifest_name
    encrypt_file(gnupg, fingerprint, manifest,
                 json.dumps(outer, sort_keys=True, separators=(",", ":")).encode(), env)
    return artifact


def seed_database(database_url: str, digest: str) -> tuple[str, dict]:
    from sqlalchemy import create_engine, text

    engine = create_engine(database_url)
    with engine.begin() as connection:
        result = connection.execute(text("""
            INSERT INTO sources (
                source_key, kind, url, adapter, item_kind, config_revision, config,
                enabled, interval_minutes, max_requests_per_hour, next_due_at,
                origin, overrides
            ) VALUES (
                'restore-fixture', 'fixture', 'https://example.invalid/feed', 'fixture',
                'fixture-item', :hash, '{}'::json, true, 60, 60, now(), 'official', '{}'::json
            ) RETURNING id
        """), {"hash": "a" * 64})
        source_id = result.scalar_one()
        result = connection.execute(text("""
            INSERT INTO items (
                source_id, external_id, canonical_url, kind, title, state,
                first_seen_at, last_seen_at, current_version, current_hash
            ) VALUES (
                :source_id, 'fixture-1', 'https://example.invalid/item/1', 'fixture-item',
                'Restore fixture item', 'current', now(), now(), 1, :hash
            ) RETURNING id
        """), {"source_id": source_id, "hash": "b" * 64})
        item_id = result.scalar_one()
        connection.execute(text("""
            INSERT INTO item_versions (item_id, version, observed_at, sha256, attributes, provenance)
            VALUES (:item_id, 1, now(), :hash, '{}'::json, '{}'::json)
        """), {"item_id": item_id, "hash": "b" * 64})
        connection.execute(text("""
            INSERT INTO report_site_state (id, active_digest, pending_digest, pending_run_id, updated_at)
            VALUES (1, :digest, NULL, NULL, now())
            ON CONFLICT (id) DO UPDATE SET active_digest = EXCLUDED.active_digest,
              pending_digest = NULL, pending_run_id = NULL, updated_at = now()
        """), {"digest": digest})
        schema = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        counts = {}
        for output, table in (
            ("sources", "sources"), ("items", "items"),
            ("item_versions", "item_versions"), ("report_runs", "report_runs"),
            ("report_schedules", "report_schedules"), ("reports", "reports"),
            ("report_evidence", "report_evidence"),
        ):
            counts[output] = connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()
    engine.dispose()
    return schema, counts


def wait_for_postgres(container: str, port: int) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        result = subprocess.run(["podman", "exec", container, "pg_isready", "-U", "nous", "-d", "nous"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    return
            except OSError:
                pass
        time.sleep(1)
    raise RuntimeError("source rootless PostgreSQL did not become ready")


def main() -> int:
    if shutil.which("podman") is None or shutil.which("gpg") is None:
        raise SystemExit("Podman and GPG are required")
    image = os.environ.get("NOUS_RESTORE_POSTGRES_IMAGE", DEFAULT_IMAGE)
    if subprocess.run(["podman", "info", "--format", "{{.Host.Security.Rootless}}"],
                      capture_output=True, text=True, check=True).stdout.strip() != "true":
        raise SystemExit("this rehearsal requires rootless Podman")
    run(["podman", "image", "inspect", image])

    token = secrets.token_hex(6)
    source_container = f"nous-restore-source-{token}"
    source_db_volume = f"nous-restore-source-db-{token}"
    source_site_volume = f"nous-restore-source-site-{token}"
    with tempfile.TemporaryDirectory(prefix="nous-restore-formats-") as temporary:
        work = Path(temporary)
        gnupg = work / "gnupg"
        gnupg.mkdir(mode=0o700)
        env = os.environ.copy()
        env["GNUPGHOME"] = str(gnupg)
        env["NOUS_RESTORE_POSTGRES_IMAGE"] = image
        created_container = False
        created_volumes: list[str] = []
        try:
            run(["gpg", "--batch", "--homedir", str(gnupg), "--passphrase", "",
                 "--quick-generate-key", "NOUS restore fixture <restore-fixture@example.invalid>",
                 "rsa2048", "encr", "1d"], env=env)
            key_records = run(["gpg", "--batch", "--homedir", str(gnupg), "--with-colons",
                               "--list-secret-keys"], env=env).decode().splitlines()
            fingerprint = next(line.split(":")[9] for line in key_records if line.startswith("fpr:"))

            run(["podman", "volume", "create", source_db_volume])
            created_volumes.append(source_db_volume)
            run(["podman", "volume", "create", source_site_volume])
            created_volumes.append(source_site_volume)
            run(["podman", "run", "-d", "--name", source_container,
                 "--volume", f"{source_db_volume}:/var/lib/postgresql",
                 "--publish", "127.0.0.1::5432", "--env", "POSTGRES_DB=nous",
                 "--env", "POSTGRES_USER=nous", "--env", "POSTGRES_PASSWORD=fixture-password",
                 image])
            created_container = True
            port_record = run(["podman", "port", source_container, "5432/tcp"]).decode().splitlines()[0]
            port = int(port_record.rsplit(":", 1)[1])
            wait_for_postgres(source_container, port)
            database_url = f"postgresql+psycopg://nous:fixture-password@127.0.0.1:{port}/nous"
            migration_env = env | {"DATABASE_URL": database_url}
            run([sys.executable, "-m", "alembic", "upgrade", "head"], env=migration_env)

            site_root = work / "site"
            site_root.mkdir()
            digest, site_metadata, _ = build_site(site_root)
            schema, counts = seed_database(database_url, digest)
            if schema != "0011" or counts["sources"] != 1 or counts["items"] != 1 or counts["item_versions"] != 1:
                raise RuntimeError(f"unexpected source fixture schema or counts: {schema} {counts}")

            install_tar = run_tar(site_root)
            run(["podman", "run", "--rm", "-i", "--network", "none",
                 "--volume", f"{source_site_volume}:/site:rw", "--entrypoint", "tar",
                 image, "--no-same-owner", "-C", "/site", "-xpf", "-"], input=install_tar)
            database_dump = run(["podman", "exec", source_container,
                                 "pg_dump", "-Fc", "-U", "nous", "-d", "nous"])
            site_archive = run(["podman", "run", "--rm", "--network", "none",
                                "--volume", f"{source_site_volume}:/site:ro", "--entrypoint", "tar",
                                image, "--numeric-owner", "-C", "/site", "-cf", "-", "."])

            artifact_dir = work / "backups"
            artifact_dir.mkdir(mode=0o700)
            outputs = []
            for kind in ("stream", "legacy"):
                artifact = write_backup(artifact_dir, gnupg, fingerprint, env,
                                        kind=kind, database_dump=database_dump,
                                        site_archive=site_archive, schema=schema,
                                        counts=counts, site=site_metadata)
                result = subprocess.run([str(RESTORE), str(artifact)], cwd=ROOT, env=env,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, check=False)
                if result.returncode:
                    raise RuntimeError(
                        f"{kind} rootless restore rehearsal failed ({result.returncode}):\n"
                        f"{result.stdout}{result.stderr}"
                    )
                output = result.stdout.strip()
                if f"schema={schema} sources=1 items=1 versions=1" not in output or digest not in output:
                    raise RuntimeError(f"{kind} restore did not verify expected DB/site fixture: {output}")
                outputs.append(f"{kind}: {output}")
            print("Rootless Podman/PostgreSQL restore rehearsals passed:")
            for line in outputs:
                print(f"  {line}")
            print(f"source container={source_container}; source DB volume={source_db_volume}; site volume={source_site_volume}")
            print("Both restore-test invocations used real pg_restore and GNU tar containers; backup plaintext archives remained in memory.")
        finally:
            if created_container:
                subprocess.run(["podman", "rm", "-f", source_container], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            if created_volumes:
                subprocess.run(["podman", "volume", "rm", *created_volumes], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            if shutil.which("gpgconf"):
                subprocess.run(["gpgconf", "--homedir", str(gnupg), "--kill", "gpg-agent"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
