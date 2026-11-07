"""FIRST EPSS contract, freshness and DB-backed bounded refresh tests."""
import json
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from nous import epss
from nous.db import Base
from nous.models import CveItemLink, EpssObservation, EpssPollState, Item, Source


CVE = "CVE-2026-12345"
OTHER = "CVE-2026-12346"
TODAY = datetime(2026, 11, 7, 14, tzinfo=timezone.utc)


def response(rows):
    return json.dumps({
        "status": "OK", "status-code": 200, "data": rows,
    }).encode()


def row(cve=CVE, score="0.123456789", percentile="0.956700000", value_date="2026-11-07"):
    return {"cve": cve, "epss": score, "percentile": percentile, "date": value_date}


def test_first_epss_contract_accepts_only_bounded_exact_cv_es():
    valid = epss.parse_epss_response(response([row()]), {CVE}, TODAY.date())
    assert valid[CVE][1] == epss.Decimal("0.123456789")
    assert valid[CVE][2] == epss.Decimal("0.956700000")

    for invalid in (
        response([row(cve="CVE-2026-99999")]),
        response([row(score="-0.001")]),
        response([row(percentile="1.2")]),
        response([row(score="NaN")]),
        response([row(value_date="2099-01-01")]),
        response([row(), row()]),
        json.dumps({"status": "FAIL", "status-code": 429, "data": []}).encode(),
        b"<html>not an EPSS response</html>",
    ):
        with pytest.raises(ValueError):
            epss.parse_epss_response(invalid, {CVE}, TODAY.date())


@pytest.fixture
def tracked_db(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "epss.sqlite"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    with factory() as db:
        source = Source(
            source_key="test-alerts", kind="rss", adapter="rss_v1",
            item_kind="advisory", url="https://source.example/feed",
            config_revision="fixture", config={"max_concurrency": 1},
            enabled=True, interval_minutes=360, max_requests_per_hour=2,
        )
        db.add(source)
        db.flush()
        for cve in (CVE, OTHER):
            item = Item(
                source_id=source.id, external_id=cve,
                canonical_url="https://source.example/" + cve,
                kind="advisory", title=cve, state="current",
                current_version=1, current_hash="a" * 64,
            )
            db.add(item)
            db.flush()
            db.add(CveItemLink(item_id=item.id, cve_id=cve, relation="reference"))
        db.add(EpssPollState(
            id=1, next_due_at=TODAY-timedelta(hours=1),
        ))
        db.commit()
    try:
        yield factory
    finally:
        engine.dispose()


def test_first_epss_refresh_and_immutable_cutoff(tracked_db, monkeypatch):
    calls = []

    def fake_fetch(url):
        assert url.startswith(epss.EPSS_API + "?")
        ids = set(parse_qs(urlparse(url).query)["cve"][0].split(","))
        calls.append(ids)
        # One CVE has no published score: persist explicit absence, never zero.
        matched = [row(value_date="2026-11-07")] if CVE in ids else []
        return 200, response(matched), {}, url

    monkeypatch.setattr(epss, "fetch", fake_fetch)
    assert epss.refresh_epss(tracked_db, current=TODAY) is True
    assert set.union(*calls) == {CVE, OTHER}
    with tracked_db() as db:
        assert len(db.scalars(select(EpssObservation)).all()) == 2
        assert epss.epss_as_of(db, CVE, TODAY-timedelta(seconds=1))["status"] == "unknown"
        value = epss.epss_as_of(db, CVE, TODAY+timedelta(hours=1))
        assert value["status"] == "current"
        assert value["score"] == 0.123456789
        assert value["percentile"] == 0.9567
        missing = epss.epss_as_of(db, OTHER, TODAY+timedelta(hours=1))
        assert missing["status"] == "not_scored"
        assert missing["score"] is None
        stale = epss.epss_as_of(db, CVE, TODAY+timedelta(days=3))
        assert stale["status"] == "stale"

    assert epss.refresh_epss(tracked_db, current=TODAY+timedelta(minutes=5)) is False
    assert len(calls) == 1


def test_first_epss_rejects_partial_response_and_backs_off(tracked_db, monkeypatch):
    monkeypatch.setattr(epss, "fetch", lambda url: (
        200, response([row(cve="CVE-2026-99999")]), {}, url))
    assert epss.refresh_epss(tracked_db, current=TODAY) is True
    with tracked_db() as db:
        assert db.scalars(select(EpssObservation)).all() == []
        state = db.get(EpssPollState, 1)
        assert state.last_error == "ValueError"
        assert state.last_success_at is None
        assert epss._utc(state.next_due_at) == TODAY + timedelta(minutes=30)
    assert epss.refresh_epss(tracked_db, current=TODAY+timedelta(minutes=10)) is False
