import json
import subprocess

import pytest

from nous import report_pipeline
from nous.report_pipeline import CodexRunner, ReportError


def make_runner(tmp_path, event_sink):
    runner = object.__new__(CodexRunner)
    runner.binary = "codex"
    runner.model = "gpt-5.3-codex"
    runner.reasoning_effort = "max"
    runner.uid = runner.gid = 10002
    runner.setpriv = "setpriv"
    runner.prlimit = "prlimit"
    runner.workdir = tmp_path / "work"
    runner.workdir.mkdir()
    runner.version = "0.166.0"
    runner.attempt = 2
    runner.event_sink = event_sink
    runner._diagnostic_root = tmp_path / "private"
    runner._set_group_mode = lambda *_args: None
    runner._identity_args = lambda: ["setpriv", "--no-new-privs"]
    runner._preflight = lambda: None
    runner._kill_process_group = lambda process: setattr(process, "returncode", -9)
    return runner


class FakeCodexProcess:
    def __init__(self, *, stdout, stderr, command, result, returncode=0, timeout=False):
        self.stdout = stdout
        self.stderr = stderr
        self.command = command
        self.result = result
        self.returncode = returncode
        self.timeout = timeout

    def communicate(self, *, input, timeout):
        assert input
        assert timeout == 60
        self.stdout.write(self.result["jsonl"])
        self.stderr.write(self.result.get("stderr", b""))
        output_path = self.command[self.command.index("--output-last-message") + 1]
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(self.result.get("output", {"ok": True})))
        if self.timeout:
            raise subprocess.TimeoutExpired(self.command, timeout)


def invoke(monkeypatch, tmp_path, *, jsonl, stderr=b"", returncode=0, timeout=False):
    events = []
    runner = make_runner(tmp_path, events.append)
    observed = {}

    def popen(command, **kwargs):
        observed["command"] = command
        return FakeCodexProcess(stdout=kwargs["stdout"], stderr=kwargs["stderr"],
                                command=command,
                                result={"jsonl": jsonl, "stderr": stderr},
                                returncode=returncode, timeout=timeout)

    monkeypatch.setattr(report_pipeline.subprocess, "Popen", popen)
    monkeypatch.setattr(report_pipeline, "_codex_response_schema", lambda _name: {})
    monkeypatch.setattr(report_pipeline, "_validate_schema", lambda *_args: None)
    return runner, events, observed


def test_runner_invokes_json_mode_and_persists_success_diagnostics(monkeypatch, tmp_path):
    runner, events, observed = invoke(
        monkeypatch, tmp_path,
        jsonl=(b'{"type":"thread.started","thread_id":"private"}\n'
               b'{"type":"turn.completed","usage":{"input_tokens":11,"output_tokens":2}}\n'),
    )

    value = runner.run("claims", {"private_source_text": "do not persist"},
                       run_id="run-success", timeout=60)

    assert value == {"ok": True}
    command = observed["command"]
    assert "--json" in command
    assert command[command.index("--model") + 1] == "gpt-5.3-codex"
    assert command[command.index("-c") + 1] == 'model_reasoning_effort="max"'
    assert command[-1] == "-"
    assert [event["event_type"] for event in events] == [
        "codex_stage_started", "codex_stage_completed",
    ]
    complete = events[-1]
    assert complete["attempt"] == 2
    assert complete["usage"] == {"input_tokens": 11, "output_tokens": 2}
    diagnostic = runner._diagnostic_root / complete["diagnostic_ref"]
    contents = diagnostic.read_text()
    assert "do not persist" not in contents
    assert "private" not in contents


def test_runner_preserves_diagnostics_on_timeout_and_does_not_retry(monkeypatch, tmp_path):
    runner, events, _observed = invoke(
        monkeypatch, tmp_path,
        jsonl=b'{"type":"turn.started"}\n', timeout=True,
    )

    with pytest.raises(ReportError, match="codex_timeout") as error:
        runner.run("claims", {"theme": "fixture"}, run_id="run-timeout", timeout=60)

    assert error.value.retryable is False
    failed = events[-1]
    assert failed["event_type"] == "codex_stage_failed"
    assert failed["error_code"] == "codex_timeout"
    assert failed["diagnostic_ref"]
    assert (runner._diagnostic_root / failed["diagnostic_ref"]).is_file()


def test_runner_fails_on_turn_failed_even_when_cli_exit_is_zero(monkeypatch, tmp_path):
    runner, events, _observed = invoke(
        monkeypatch, tmp_path,
        jsonl=json.dumps({"type": "turn.failed", "error": {
            "message": "authentication failed for private@example.test",
        }}).encode() + b"\n",
        stderr=b"Authorization: Bearer super-secret-value\n",
    )

    with pytest.raises(ReportError, match="codex_auth") as error:
        runner.run("claim_review", {"theme": "fixture"}, run_id="run-event-failed", timeout=60)

    assert error.value.retryable is False
    failed = events[-1]
    assert failed["exit_status"] == 0
    assert failed["jsonl_last_event"] == "turn.failed"
    diagnostic = (runner._diagnostic_root / failed["diagnostic_ref"]).read_text()
    assert "private@example.test" not in diagnostic
    assert "super-secret-value" not in diagnostic


def test_runner_classifies_nonzero_exit_and_keeps_redacted_diagnostic(monkeypatch, tmp_path):
    runner, events, _observed = invoke(
        monkeypatch, tmp_path,
        jsonl=b'{"type":"turn.started"}\n',
        stderr=b"Not logged in: Authorization: Bearer secret-token\n",
        returncode=1,
    )

    with pytest.raises(ReportError, match="codex_auth"):
        runner.run("claims", {"theme": "fixture"}, run_id="run-exit-failed", timeout=60)

    failed = events[-1]
    assert failed["exit_status"] == 1
    diagnostic = json.loads((runner._diagnostic_root / failed["diagnostic_ref"]).read_text())
    assert diagnostic["error_code"] == "codex_auth"
    assert "secret-token" not in diagnostic["stderr_preview"]
