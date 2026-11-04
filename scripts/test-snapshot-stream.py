#!/usr/bin/env python3
"""Exercise snapshot-dump's bounded stream path with a synthetic Podman fixture."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile


def fake_podman() -> int:
    root = Path(os.environ["NOUS_TEST_SITE"])
    args = sys.argv[1:]
    if args[:2] == ["volume", "inspect"]:
        return 0
    if args[:2] == ["exec", "-i"]:
        sys.stdin.buffer.read()  # consume the database snapshot helper
        blob = (b"DB-FIXTURE-STREAM-" + b"d" * 4080 + b"\n") * 2048
        sys.stdout.buffer.write(blob)
        digest = os.environ["NOUS_TEST_DIGEST"]
        print(f"NOUS_SNAPSHOT_METADATA=0009|1|2|3|4|5|6|7|{digest}", file=sys.stderr)
        return 0
    if not args or args[0] != "run":
        print("unexpected mock podman command", file=sys.stderr)
        return 2
    entry_index = args.index("--entrypoint")
    entrypoint = args[entry_index + 1]
    command = args[entry_index + 3 :]
    if entrypoint == "bash":
        script = command[-1]
        if "readlink -- /site/current" in script:
            print(f"releases/{os.environ['NOUS_TEST_DIGEST']}")
            return 0
        if "find /site/releases/" in script:
            print("index.html")
            return 0
        if "find /site -type l" in script:
            return 0
        if "cat /site/.manifests/" in script:
            sys.stdout.buffer.write((root / ".manifests" / f"{os.environ['NOUS_TEST_DIGEST']}.json").read_bytes())
            return 0
        print("unexpected mock bash command", file=sys.stderr)
        return 2
    if entrypoint != "tar":
        print("unexpected mock entrypoint", file=sys.stderr)
        return 2
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
        if command[0] == "--no-recursion":
            paths = command[command.index("--") + 1 :]
            for relative in paths:
                archive.add(root / relative, arcname=relative, recursive=False)
        else:
            archive.add(root, arcname=".", recursive=True)
    return 0


def read_exact(stream, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        part = stream.read(size - len(result))
        if not part:
            raise AssertionError("encrypted fixture stream was truncated")
        result.extend(part)
    return bytes(result)


def build_fixture(root: Path) -> tuple[str, bytes]:
    html = b"<html>NOUS-STREAM-HTML-MARKER</html>\n" + b"h" * (3 * 1024 * 1024)
    asset = b"// NOUS-STREAM-ASSET-MARKER\n" + b"a" * (5 * 1024 * 1024)
    files = {"_astro/app.js": asset, "index.html": html}
    digest_state = hashlib.sha256()
    hashes = {}
    for name, data in sorted(files.items()):
        hashes[name] = hashlib.sha256(data).hexdigest()
        digest_state.update(name.encode())
        digest_state.update(b"\0")
        digest_state.update(data)
        digest_state.update(b"\0")
    digest = digest_state.hexdigest()
    (root / "releases" / digest).mkdir(parents=True)
    (root / "_astro").mkdir()
    (root / ".manifests").mkdir()
    (root / "releases" / digest / "index.html").write_bytes(html)
    (root / "_astro" / "app.js").write_bytes(asset)
    manifest = {
        "digest": digest,
        "files": hashes,
        "html_files": ["index.html"],
        "assets": ["app.js"],
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    (root / ".manifests" / f"{digest}.json").write_bytes(manifest_bytes)
    (root / "current").symlink_to(f"releases/{digest}")
    return digest, asset


def verify_encrypted_stream(path: Path, passphrase: str) -> tuple[dict, dict[str, int]]:
    decrypt = subprocess.Popen(
        ["gpg", "--batch", "--quiet", "--pinentry-mode", "loopback", "--passphrase", passphrase,
         "--decrypt", "--output", "-", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert decrypt.stdout is not None
    source = decrypt.stdout
    magic = b"NOUS-REPORT-BACKUP-STREAM\0\1"
    if read_exact(source, len(magic)) != magic:
        raise AssertionError("encrypted backup does not contain the framed stream header")
    expected_names = ("database.dump", "report-site.tar", "manifest.json")
    record_sizes: dict[str, int] = {}
    record_hashes: dict[str, str] = {}
    internal = None
    max_chunk = 0
    for expected_name in expected_names:
        name_length = struct.unpack(">H", read_exact(source, 2))[0]
        name = read_exact(source, name_length).decode("ascii")
        if name != expected_name:
            raise AssertionError(f"unexpected backup stream record: {name}")
        checksum = hashlib.sha256()
        record = bytearray() if name == "manifest.json" else None
        total = 0
        while True:
            length = struct.unpack(">I", read_exact(source, 4))[0]
            if length == 0:
                break
            max_chunk = max(max_chunk, length)
            if length > 4096:
                raise AssertionError(f"chunk of {length} exceeded the configured 4 KiB bound")
            chunk = read_exact(source, length)
            checksum.update(chunk)
            total += length
            if record is not None:
                record.extend(chunk)
        record_sizes[name] = total
        record_hashes[name] = checksum.hexdigest()
        if record is not None:
            internal = json.loads(record)
    if source.read(1):
        raise AssertionError("unexpected bytes after final backup stream record")
    status = decrypt.wait()
    stderr = decrypt.stderr.read() if decrypt.stderr else b""
    if status:
        raise AssertionError(f"gpg could not decrypt fixture: {stderr.decode(errors='replace')}")
    if internal is None or internal.get("format") != "nous-report-site-backup-stream-v1":
        raise AssertionError("internal backup manifest is missing or invalid")
    if record_hashes["database.dump"] != internal["checksums"]["database_dump_sha256"]:
        raise AssertionError("database stream checksum differs from manifest")
    if record_hashes["report-site.tar"] != internal["checksums"]["report_site_archive_sha256"]:
        raise AssertionError("site stream checksum differs from manifest")
    if max_chunk != 4096:
        raise AssertionError(f"fixture did not exercise full-size chunks (max was {max_chunk})")
    return internal, record_sizes


def main() -> int:
    # The same executable acts as the mocked Podman CLI when invoked through PATH.
    if Path(sys.argv[0]).name == "podman":
        return fake_podman()

    script = Path(__file__).with_name("snapshot-dump.sh").resolve()
    if not script.is_file():
        raise SystemExit(f"snapshot helper not found: {script}")
    with tempfile.TemporaryDirectory(prefix="nous-snapshot-stream-test-") as temporary:
        work = Path(temporary)
        site = work / "site"
        site.mkdir()
        digest, _asset = build_fixture(site)
        bin_dir = work / "bin"
        bin_dir.mkdir()
        fake_link = bin_dir / "podman"
        fake_link.symlink_to(Path(__file__).resolve())
        systemctl = bin_dir / "systemctl"
        systemctl.write_text(
            "#!/bin/sh\n"
            "if [ \"$2\" = show ]; then printf 'inactive\\n'; fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        systemctl.chmod(0o700)
        runtime = work / "runtime"
        runtime.mkdir(mode=0o700)
        encrypted = work / "fixture.backup.gpg"
        passphrase = "synthetic-fixture-only"
        environment = os.environ.copy()
        environment.update({
            "PATH": f"{bin_dir}:{environment.get('PATH', '')}",
            "XDG_RUNTIME_DIR": str(runtime),
            "NOUS_TEST_SITE": str(site),
            "NOUS_TEST_DIGEST": digest,
            "NOUS_BACKUP_STREAM_CHUNK_BYTES": "4096",
            "NOUS_REPORT_SITE_VOLUME": "fixture-site",
        })
        before_shm = {path.name for path in Path("/dev/shm").iterdir()}
        producer = subprocess.Popen(["bash", str(script)], env=environment,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert producer.stdout is not None
        encryptor = subprocess.Popen(
            ["gpg", "--batch", "--quiet", "--yes", "--pinentry-mode", "loopback",
             "--passphrase", passphrase, "--symmetric", "--cipher-algo", "AES256",
             "--output", str(encrypted)],
            stdin=producer.stdout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        producer.stdout.close()
        encrypt_status = encryptor.wait()
        producer_status = producer.wait()
        producer_stderr = producer.stderr.read() if producer.stderr else b""
        encrypt_stderr = encryptor.stderr.read() if encryptor.stderr else b""
        if producer_status or encrypt_status:
            raise AssertionError(
                "snapshot-to-GPG fixture failed:\n"
                + producer_stderr.decode(errors="replace")
                + encrypt_stderr.decode(errors="replace")
            )
        if not encrypted.is_file() or encrypted.stat().st_size == 0:
            raise AssertionError("GPG did not produce an encrypted backup")
        if b"NOUS-STREAM-ASSET-MARKER" in encrypted.read_bytes():
            raise AssertionError("plaintext site fixture appears in encrypted artifact")
        internal, sizes = verify_encrypted_stream(encrypted, passphrase)
        if min(sizes["database.dump"], sizes["report-site.tar"]) <= 4096:
            raise AssertionError("large fixture did not exceed the configured 4 KiB buffer")
        if internal["report_site"]["active_digest"] != digest:
            raise AssertionError("captured report-site digest does not match fixture")
        after_shm = {path.name for path in Path("/dev/shm").iterdir()}
        if after_shm - before_shm:
            raise AssertionError(f"snapshot wrote unexpected files to /dev/shm: {after_shm - before_shm}")
        for forbidden in ("database.dump", "report-site.tar", "plain.stream"):
            if (work / forbidden).exists():
                raise AssertionError(f"plaintext staging file was created: {forbidden}")
        print(
            "snapshot stream fixture passed: "
            f"database={sizes['database.dump']} bytes, site_tar={sizes['report-site.tar']} bytes, "
            "chunk=4096 bytes, plaintext staging=none"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
