import hashlib
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from nous.db import Base
from nous.models import ReportRun, ReportRunEvent
import nous.report_worker as worker


def _db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'reports.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    now = datetime.now(timezone.utc)
    run_id, token = "1ef2c2c0-b057-4f1b-866b-c62f0c78b221", "lease-1"
    with factory() as db:
        db.add(ReportRun(
            id=run_id, trigger="manual", template_id="security-daily",
            template_revision="1", template_snapshot={}, parameters={}, state="running",
            stage="claims", attempts=1, available_at=now,
            lease_until=now + timedelta(minutes=5), lease_token=token,
            stage_artifacts={}, created_at=now,
        ))
        db.commit()
    root = tmp_path / "private"
    monkeypatch.setenv("NOUS_REPORT_PRIVATE_DIR", str(root))
    claim = {"id": run_id, "lease_token": token, "attempts": 1}
    return factory, claim, root


def test_stage_checkpoint_is_atomic_private_and_reused_only_for_same_inputs(
        tmp_path, monkeypatch):
    factory, claim, root = _db(tmp_path, monkeypatch)
    persist = worker.StagePersistence(factory, claim, attempt=1, model="gpt-test")
    output = {"decision": "publish", "claims": [{"claim_id": "C1"}]}
    input_digest = hashlib.sha256(b"exact stage input").hexdigest()

    digest = persist("claims", output, input_digest=input_digest,
                     schema_revision="claims-v1", prompt_revision="claims-p1")

    artifact = root / "runs" / claim["id"] / "attempts" / "1" / "claims" / "artifact.json"
    envelope = json.loads(artifact.read_text())
    assert artifact.stat().st_mode & 0o777 == 0o600
    assert envelope["artifact_sha256"] == digest
    assert hashlib.sha256(worker._json_bytes({k: v for k, v in envelope.items()
                                              if k != "artifact_sha256"})).hexdigest() == digest
    assert persist.load("claims", input_digest=input_digest, schema_revision="claims-v1",
                        prompt_revision="claims-p1") == output
    assert persist.load("claims", input_digest="a" * 64, schema_revision="claims-v1",
                        prompt_revision="claims-p1") is None
    with factory() as db:
        run = db.get(ReportRun, claim["id"])
        events = db.scalars(select(ReportRunEvent).where(
            ReportRunEvent.run_id == claim["id"])).all()
        assert run.stage_artifacts["claims"][0]["artifact_sha256"] == digest
        assert [(event.event_type, event.artifact_sha256) for event in events] == [
            ("stage_succeeded", digest),
        ]


def test_checkpoint_rejects_corruption_and_appends_sanitized_runner_events(
        tmp_path, monkeypatch):
    factory, claim, root = _db(tmp_path, monkeypatch)
    persist = worker.StagePersistence(factory, claim, attempt=1, model="gpt-test")
    input_digest = hashlib.sha256(b"in").hexdigest()
    persist("claim_review", {"reviews": []}, input_digest=input_digest)
    artifact = root / "runs" / claim["id"] / "attempts" / "1" / "claim_review" / "artifact.json"
    artifact.write_text("{}", encoding="utf-8")
    assert persist.load("claim_review", input_digest=input_digest) is None

    persist.event({
        "run_id": claim["id"], "attempt": 1, "stage": "claim_review",
        "event_type": "codex_stage_failed", "error_code": "codex_auth",
        "exit_status": 1, "elapsed_ms": 50, "usage": {"input_tokens": 10, "secret": 20},
        "diagnostic_ref": "runs/abc/diagnostic.json", "retryable": False,
        "raw_stderr": "must never persist",
    })
    with factory() as db:
        run = db.get(ReportRun, claim["id"])
        events = db.scalars(select(ReportRunEvent).where(
            ReportRunEvent.run_id == claim["id"]).order_by(ReportRunEvent.seq)).all()
        failed = events[-1]
        assert run.failed_stage == "claim_review"
        assert failed.event_type == "codex_stage_failed"
        assert failed.error_code == "codex_auth"
        assert failed.usage == {"input_tokens": 10}
        assert failed.diagnostic_ref == "runs/abc/diagnostic.json"
        assert not hasattr(failed, "raw_stderr")


def test_failure_keeps_progress_stage_and_separates_retry_state(tmp_path, monkeypatch):
    factory, claim, _root = _db(tmp_path, monkeypatch)
    worker._set_failure(factory, claim, state="failed", code="codex_network_unavailable",
                        retryable=True)
    with factory() as db:
        run = db.get(ReportRun, claim["id"])
        assert run.state == "queued"
        assert run.stage == "claims"
        assert run.failed_stage == "claims"
        assert run.retry_at == run.available_at
        event = db.scalar(select(ReportRunEvent).where(
            ReportRunEvent.run_id == claim["id"]))
        assert event.event_type == "run_failed"
        assert event.retryable is True
