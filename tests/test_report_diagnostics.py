import json

import pytest

from nous.report_diagnostics import (
    classify_codex_failure,
    parse_codex_jsonl,
    redact_stderr,
    write_diagnostic,
)


def test_jsonl_parser_keeps_event_types_and_numeric_usage_only():
    raw = b"\n".join([
        json.dumps({"type": "thread.started", "thread_id": "private-id"}).encode(),
        json.dumps({"type": "item.completed", "item": {
            "type": "agent_message", "text": "private source text"}}).encode(),
        json.dumps({"type": "turn.completed", "usage": {
            "input_tokens": 17, "cached_input_tokens": 3, "output_tokens": 8,
            "authorization": "secret"}}).encode(),
    ])

    result = parse_codex_jsonl(raw)

    assert result["events"] == [
        {"type": "thread.started"},
        {"type": "item.completed"},
        {"type": "turn.completed", "usage": {
            "input_tokens": 17, "cached_input_tokens": 3, "output_tokens": 8}},
    ]
    assert "private source text" not in json.dumps(result)
    assert "private-id" not in json.dumps(result)
    assert result["usage"]["input_tokens"] == 17


def test_jsonl_parser_extracts_error_for_classification_but_not_persistence():
    result = parse_codex_jsonl(json.dumps({
        "type": "error", "message": "authentication failed for user@example.test",
    }).encode())

    assert result["failure_text"] == "authentication failed for user@example.test"
    assert result["events"] == [{"type": "error"}]
    assert classify_codex_failure(result["failure_text"]) == ("codex_auth", False)
    assert "user@example.test" not in json.dumps(result["events"])


def test_stderr_redacts_bearer_and_url_query_and_bounds_preview():
    preview = redact_stderr(
        "Authorization: Bearer super-secret-value\n"
        "request https://service.example/path?access_token=very-secret#fragment\n" + "x" * 9_000
    )

    assert len(preview) <= 4_096
    assert "super-secret-value" not in preview
    assert "very-secret" not in preview
    assert "fragment" not in preview


def test_failure_taxonomy_retries_only_recognized_transient_network_errors():
    assert classify_codex_failure("authentication failed") == ("codex_auth", False)
    assert classify_codex_failure("failed to connect to api.openai.com") == (
        "codex_network_unavailable", True
    )
    assert classify_codex_failure("unrelated temporary failure") == (
        "codex_execution_failed", False
    )


def test_diagnostic_is_atomic_private_and_reference_is_relative(tmp_path):
    root = tmp_path / "private"
    ref = write_diagnostic(root, "run-123", 2, "claims", {
        "run_id": "run-123", "stderr_preview": "Bearer [REDACTED]",
        "jsonl_events": [{"type": "turn.failed"}],
    })

    path = root / ref
    assert ref == "runs/run-123/attempts/2/claims/diagnostic.json"
    assert json.loads(path.read_text()) == {
        "run_id": "run-123", "stderr_preview": "Bearer [REDACTED]",
        "jsonl_events": [{"type": "turn.failed"}],
    }
    assert root.stat().st_mode & 0o777 == 0o700
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("run_id", ["../escape", "run/../../escape", ""])
def test_diagnostic_rejects_path_traversal(tmp_path, run_id):
    with pytest.raises(ValueError):
        write_diagnostic(tmp_path / "private", run_id, 1, "claims", {})


def test_diagnostic_never_replaces_symlink_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "private"
    root.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError):
        write_diagnostic(root, "run-1", 1, "claims", {})
    assert not list(outside.iterdir())
