"""Safe, bounded diagnostics for non-interactive Codex stages."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any
from urllib.parse import urlsplit, urlunsplit

MAX_JSONL_BYTES = 262_144
MAX_JSONL_EVENTS = 2_000
MAX_STDERR_BYTES = 65_536
MAX_STDERR_PREVIEW = 4_096
MAX_DIAGNOSTIC_BYTES = 32_768
_EVENT_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,47}$")
_SAFE_PART = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_TOKEN = re.compile(
    r"(?i)\b(?:sk-[A-Za-z0-9_-]{12,}|sess-[A-Za-z0-9_-]{12,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"
)
_ASSIGNMENT = re.compile(
    r"(?i)\b(authorization|bearer|cookie|set-cookie|api[_ -]?key|access[_ -]?token|"
    r"refresh[_ -]?token|password|secret)\b(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ALLOWED_EVENTS = {
    "thread.started", "turn.started", "turn.completed", "turn.failed",
    "item.started", "item.completed", "item.failed", "error",
}
_USAGE_KEYS = {"input_tokens", "cached_input_tokens", "output_tokens", "total_tokens"}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _usage(value: Any) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    result = {
        key: number for key, number in value.items()
        if key in _USAGE_KEYS and isinstance(number, int) and not isinstance(number, bool)
        and 0 <= number <= 100_000_000
    }
    return result or None


def parse_codex_jsonl(data: bytes) -> dict[str, Any]:
    """Summarize JSONL using an allowlist; message and tool content are discarded."""
    bounded = data[:MAX_JSONL_BYTES]
    events: list[dict[str, Any]] = []
    malformed = 0
    usage = None
    failure_text: list[str] = []
    for line in bounded.splitlines()[:MAX_JSONL_EVENTS]:
        if not line:
            continue
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            malformed += 1
            continue
        if not isinstance(value, dict):
            malformed += 1
            continue
        event_type = value.get("type")
        if not isinstance(event_type, str) or not _EVENT_NAME.fullmatch(event_type):
            malformed += 1
            continue
        # Event type is useful operational metadata. Limit item subtype to a fixed
        # set; never preserve IDs, text, commands, or arbitrary event fields.
        normalized_type = event_type if event_type in _ALLOWED_EVENTS else None
        if event_type.startswith("item."):
            item = value.get("item")
            item_type = item.get("type") if isinstance(item, dict) else None
            if item_type in {"agent_message", "reasoning", "command_execution", "mcp_tool_call"}:
                normalized_type = event_type
        if normalized_type:
            event: dict[str, Any] = {"type": normalized_type}
            event_usage = _usage(value.get("usage"))
            if event_usage is None and isinstance(value.get("data"), dict):
                event_usage = _usage(value["data"].get("usage"))
            if event_usage:
                event["usage"] = event_usage
                usage = event_usage
            events.append(event)

        if event_type in {"turn.failed", "error"}:
            error = value.get("error")
            if isinstance(error, str):
                failure_text.append(error[:2_048])
            elif isinstance(error, dict):
                message = error.get("message")
                if isinstance(message, str):
                    failure_text.append(message[:2_048])
            if not error:
                # Current CLI versions may put the safe-to-classify error text
                # at the top level. This string remains ephemeral and is never
                # included in the persisted event summary.
                message = value.get("message")
                if isinstance(message, str):
                    failure_text.append(message[:2_048])

    return {
        "events": events,
        "last_event": events[-1]["type"] if events else None,
        "usage": usage,
        "malformed_lines": min(malformed, MAX_JSONL_EVENTS),
        "truncated": len(data) > MAX_JSONL_BYTES,
        # Ephemeral in-memory classifier input. Callers must not persist this.
        "failure_text": "\n".join(failure_text)[:4_096],
        "stdout_bytes": len(data),
    }


def _redact_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return "[REDACTED_URL]"
    # URL userinfo, query values, and fragments may carry credentials.
    host = parts.hostname or ""
    if port:
        host += f":{port}"
    path = parts.path[:256]
    return urlunsplit((parts.scheme, host, path, "[REDACTED]" if parts.query else "", ""))


def redact_stderr(data: bytes | str) -> str:
    """Return a short redacted preview, never an unbounded child-process log."""
    if isinstance(data, bytes):
        value = data[-MAX_STDERR_BYTES:].decode("utf-8", errors="replace")
    else:
        value = data[-MAX_STDERR_BYTES:]
    value = _ANSI.sub("", value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _ASSIGNMENT.sub(r"\1\2[REDACTED]", value)
    value = _TOKEN.sub("[REDACTED_TOKEN]", value)
    value = _URL.sub(lambda match: _redact_url(match.group(0)), value)
    # Single-line diagnostics reduce the risk of preserving large arbitrary
    # payloads embedded in stderr while retaining a bounded human preview.
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    return "\n".join(lines)[-MAX_STDERR_PREVIEW:]


def classify_codex_failure(detail: str) -> tuple[str, bool]:
    """Map potentially sensitive CLI details to a fixed code and retry policy."""
    detail = detail.lower()
    if any(text in detail for text in ("usage limit", "rate limit", "quota exceeded")):
        return "codex_usage_limit", False
    if any(text in detail for text in ("authentication", "not logged in", "unauthorized", "login required")):
        return "codex_auth", False
    if any(text in detail for text in ("not a git repository", "not inside a trusted directory",
                                       "git repository check")):
        return "codex_git_repo_rejected", False
    if any(text in detail for text in ("invalid response_format", "invalid_json_schema", "invalid json schema",
                                       "invalid output schema", "schema is invalid",
                                       "schema validation error")):
        return "codex_schema_rejected", False
    if any(text in detail for text in ("permission denied", "os error 13")):
        return "codex_permission_denied", False
    if any(text in detail for text in ("unknown option", "unexpected argument", "unrecognized option",
                                       "found argument", "unknown flag")):
        return "codex_cli_argument_rejected", False
    if any(text in detail for text in ("connection refused", "connection reset", "dns error",
                                       "failed to resolve", "network is unreachable",
                                       "failed to connect", "connection timed out", "http 5", "status 5")):
        return "codex_network_unavailable", True
    if any(text in detail for text in ("no space left on device", "os error 28", "disk quota exceeded")):
        return "codex_storage_exhausted", False
    if any(text in detail for text in ("read-only file system", "os error 30")):
        return "codex_read_only_filesystem", False
    if any(text in detail for text in ("operation not permitted", "os error 1", "seccomp",
                                       "sandbox initialization failed")):
        return "codex_sandbox_rejected", False
    if any(text in detail for text in ("model not found", "unsupported model",
                                       "model is not supported", "model does not exist")):
        return "codex_model_unavailable", False
    if any(text in detail for text in ("no such file", "not found", "binary unavailable")):
        return "codex_unavailable", False
    return "codex_execution_failed", False


def _safe_component(value: str | int) -> str:
    component = str(value)
    if not _SAFE_PART.fullmatch(component):
        raise ValueError("unsafe diagnostic path component")
    return component


def write_diagnostic(root: Path, run_id: str, attempt: int, stage: str,
                     payload: dict[str, Any]) -> str:
    """Atomically store bounded JSON beneath a private 0700 root."""
    run_part = _safe_component(run_id)
    stage_part = _safe_component(stage)
    if not isinstance(attempt, int) or isinstance(attempt, bool) or not 1 <= attempt <= 100_000:
        raise ValueError("invalid diagnostic attempt")
    if root.is_symlink():
        raise ValueError("diagnostic root is a symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    parent = root / "runs" / run_part / "attempts" / str(attempt) / stage_part
    for directory in (root / "runs", root / "runs" / run_part,
                      root / "runs" / run_part / "attempts",
                      root / "runs" / run_part / "attempts" / str(attempt), parent):
        if directory.is_symlink():
            raise ValueError("diagnostic path contains a symlink")
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_DIAGNOSTIC_BYTES:
        raise ValueError("diagnostic exceeds size limit")
    fd, temp_name = tempfile.mkstemp(prefix=".diagnostic-", dir=parent)
    temp_path = Path(temp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, parent / "diagnostic.json")
        dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
    return (Path("runs") / run_part / "attempts" / str(attempt) /
            stage_part / "diagnostic.json").as_posix()
