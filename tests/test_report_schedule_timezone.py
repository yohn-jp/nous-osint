"""Scheduled report windows follow the schedule's configured time zone."""
from datetime import datetime, timedelta, timezone
import uuid

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from nous.db import Base
from nous.models import ReportRun, ReportSchedule
from nous.report_templates import resolve_template
import nous.report_worker as worker


def test_scheduled_security_window_uses_non_tokyo_zone(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///" + str(tmp_path / "schedule.db"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    template = resolve_template("security-daily")
    slot = datetime(2026, 11, 5, 17, tzinfo=timezone.utc)
    current = slot + timedelta(minutes=1)
    schedule_id = str(uuid.uuid4())
    schedule = ReportSchedule(
        id=schedule_id, template_id=template["id"],
        template_revision=template["revision_key"], template_snapshot=template,
        parameters={"category": "advisory"}, timezone="America/Los_Angeles",
        cadence="daily", local_time="09:00", next_slot_at=slot, enabled=True,
        created_by="timezone-fixture", created_at=current, updated_at=current,
    )
    with factory() as db:
        db.add(schedule)
        db.commit()

    monkeypatch.setattr(worker, "now", lambda: current)
    worker.schedule_due(factory)

    with factory() as db:
        run = db.scalar(select(ReportRun).where(ReportRun.schedule_id == schedule_id))
        assert run is not None
        assert run.parameters["target_date"] == "2026-11-05"
        assert run.parameters["timezone"] == "America/Los_Angeles"
        assert run.parameters["window_start"] == "2026-11-05T08:00:00+00:00"
        assert run.parameters["window_end"] == "2026-11-06T08:00:00+00:00"
