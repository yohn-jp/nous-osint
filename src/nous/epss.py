"""FIRST EPSS evidence snapshots for CVEs already observed by Nous.

FIRST's API is a lookup service, not a bulk synchronization endpoint. Only
known CVEs are requested, in bounded batches, and each daily observation is
immutable. Scores are never interpreted as a CVSS-derived risk probability.
"""
from __future__ import annotations

import json
import logging
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from urllib.parse import urlencode

from sqlalchemy import func, select

from .cve_index import valid_cve_id
from .fetch import fetch
from .models import CveItemLink, EpssObservation, EpssPollState

log = logging.getLogger(__name__)
EPSS_API = "https://api.first.org/data/v1/epss"
_MAX_TRACKED = 5000
_MAX_PER_POLL = 90
_MAX_QUERY_BYTES = 1750
_SCORE_PRECISION = Decimal("0.000000001")
_FRESH_AGE = timedelta(hours=48)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        # SQLite test databases deserialize timezone-aware columns as naive UTC.
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _probability(value: object) -> Decimal:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise ValueError("invalid EPSS score type")
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("invalid EPSS score") from exc
    if not result.is_finite() or not 0 <= result <= 1:
        raise ValueError("EPSS score out of bounds")
    return result.quantize(_SCORE_PRECISION)


def parse_epss_response(content: bytes, requested: set[str], current_day: date) -> dict:
    """Validate all returned rows before accepting even one observation."""
    if len(content) > 500_000:
        raise ValueError("EPSS lookup exceeds expected size")
    try:
        payload = json.loads(content)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid EPSS JSON") from exc
    if (not isinstance(payload, dict) or payload.get("status") != "OK"
            or payload.get("status-code") != 200
            or not isinstance(payload.get("data"), list)
            or len(payload["data"]) > len(requested)):
        raise ValueError("invalid EPSS response envelope")
    result = {}
    for row in payload["data"]:
        if not isinstance(row, dict):
            raise ValueError("invalid EPSS row")
        cve_id = row.get("cve")
        if (not valid_cve_id(cve_id) or cve_id not in requested
                or cve_id in result):
            raise ValueError("EPSS response identity mismatch")
        try:
            score_date = date.fromisoformat(row["date"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid EPSS score date") from exc
        if score_date > current_day or score_date < current_day - timedelta(days=10):
            raise ValueError("EPSS score date outside bounded window")
        result[cve_id] = (
            score_date, _probability(row.get("epss")),
            _probability(row.get("percentile")),
        )
    return result


def _batches(cves: list[str]):
    batch = []
    size = 0
    for identifier in cves:
        if not valid_cve_id(identifier):
            raise ValueError("invalid CVE in tracked collection")
        size_next = size + len(identifier) + (1 if batch else 0)
        if batch and size_next > _MAX_QUERY_BYTES:
            yield batch
            batch, size = [], 0
        batch.append(identifier)
        size += len(identifier) + (1 if len(batch) > 1 else 0)
    if batch:
        yield batch


def _oldest_tracked(db) -> tuple[list[str], bool]:
    # Only current CVE links, not retired title mentions or arbitrary user input.
    cves = db.scalars(select(CveItemLink.cve_id).distinct()
                      .order_by(CveItemLink.cve_id).limit(_MAX_TRACKED + 1)).all()
    last = {}
    if cves:
        last = dict(db.execute(select(
            EpssObservation.cve_id, func.max(EpssObservation.fetched_at),
        ).where(EpssObservation.cve_id.in_(cves[:_MAX_TRACKED])).group_by(
            EpssObservation.cve_id)).all())
    tracked = sorted(cves[:_MAX_TRACKED], key=lambda cve: (
        _utc(last[cve]) if cve in last else datetime.min.replace(tzinfo=timezone.utc),
        cve,
    ))
    return tracked[:_MAX_PER_POLL], len(cves) > _MAX_PER_POLL


def refresh_epss(factory, *, current: datetime | None = None) -> bool:
    """Claim one bounded refresh tick. Network I/O occurs outside DB locks."""
    timestamp = _utc(current or datetime.now(timezone.utc))
    with factory() as db:
        state = db.scalar(select(EpssPollState).where(EpssPollState.id == 1)
                          .with_for_update(skip_locked=True))
        if state is None or _utc(state.next_due_at) > timestamp:
            return False
        # Crash-safe retry window; no network I/O while holding a lock.
        state.next_due_at = timestamp + timedelta(minutes=30)
        db.commit()
    try:
        with factory() as db:
            cves, backlog = _oldest_tracked(db)
        observations = {}
        for batch in _batches(cves):
            endpoint = EPSS_API + "?" + urlencode({"cve": ",".join(batch)})
            status, content, _headers, _url = fetch(endpoint)
            if status != 200:
                raise ValueError("EPSS HTTP response not OK")
            observations.update(parse_epss_response(content, set(batch), timestamp.date()))
        with factory() as db:
            for cve in cves:
                if db.get(EpssObservation, (cve, timestamp.date())) is not None:
                    continue
                value = observations.get(cve)
                db.add(EpssObservation(
                    cve_id=cve, checked_on=timestamp.date(), fetched_at=timestamp,
                    score_date=value[0] if value else None,
                    score=value[1] if value else None,
                    percentile=value[2] if value else None,
                ))
            state = db.get(EpssPollState, 1)
            state.last_success_at = timestamp
            state.last_error = None
            state.next_due_at = timestamp + timedelta(minutes=15 if backlog else 1440)
            db.commit()
        log.info("EPSS refresh accepted: %d CVEs (%d scored)", len(cves), len(observations))
    except Exception as exc:
        # Preserve previous snapshots and the retry time written on claim.
        with factory() as db:
            state = db.get(EpssPollState, 1)
            if state is not None:
                state.last_error = type(exc).__name__[:60]
                db.commit()
        log.warning("EPSS refresh rejected: %s", type(exc).__name__)
    return True


def epss_as_of(db, cve_id: str, observed_cutoff: datetime) -> dict:
    """No outbound I/O. 'unavailable' is distinct from zero probability."""
    cutoff = _utc(observed_cutoff)
    row = db.scalar(select(EpssObservation).where(
        EpssObservation.cve_id == cve_id,
        EpssObservation.fetched_at <= cutoff,
    ).order_by(EpssObservation.fetched_at.desc()).limit(1))
    if row is None:
        return {"status": "unknown", "score": None, "percentile": None,
                "score_date": None, "observed_at": None, "source_url": EPSS_API}
    if row.score is None or row.percentile is None or row.score_date is None:
        status = "not_scored"
    elif (cutoff - _utc(row.fetched_at) > _FRESH_AGE
          or row.score_date < cutoff.date() - timedelta(days=2)):
        status = "stale"
    else:
        status = "current"
    return {"status": status, "score": float(row.score) if row.score is not None else None,
            "percentile": float(row.percentile) if row.percentile is not None else None,
            "score_date": row.score_date, "observed_at": row.fetched_at,
            "source_url": EPSS_API}
