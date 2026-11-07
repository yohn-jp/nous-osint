"""Opt-in, cost-bounded X public-author timeline ingestion.

Official X API only. Never use scraper, proxy, browser cookie or unofficial
mirror. A server-side bearer token is sent only to api.x.com over a pinned TLS
connection, with no redirects. No network requests without explicit budget.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse

import httpx
from sqlalchemy import func, select

from .fetch import validate_url
from .models import FetchAttempt, FetchJob, Item, Source

X_HOST = "api.x.com"
X_MAX_RESULTS = 10
X_MAX_PAGES = 3
X_ESTIMATED_PRICE_USD_PER_POST = 0.005
_USER_PATH = re.compile(r"^/2/users/([1-9][0-9]{0,19})/tweets$")
_ID = re.compile(r"^[1-9][0-9]{0,19}$")
_CURSOR = re.compile(r"^[A-Za-z0-9_=-]{1,500}$")
_URL = "https://api.x.com"
_MAX_BODY = 500_000


def author_id_from_url(url: str) -> str:
    parsed = urlparse(url)
    if (parsed.scheme != "https" or parsed.hostname != X_HOST
            or parsed.port not in (None, 443) or parsed.username or parsed.password
            or parsed.query or parsed.fragment or not _USER_PATH.fullmatch(parsed.path)):
        raise ValueError("X collection requires an official immutable user-ID timeline")
    return _USER_PATH.fullmatch(parsed.path).group(1)


def configured_max_daily_post_reads() -> int:
    """0 is hard-off. This is a *conservative* estimate, not provider billing."""
    raw = os.getenv("NOUS_X_MAX_DAILY_POST_READS", "0")
    if not raw.isascii() or not raw.isdigit() or len(raw) > 6:
        return 0
    value = int(raw)
    return value if 0 < value <= 100000 else 0


def x_source_allowed(db, current: datetime, pages: int) -> bool:
    """Call while holding the existing api.x.com host advisory lock.

    The lock + one-active-request-per-host invariant in runtime.claim ensures
    no second X reservation can start before the first attempt is committed.
    We conservatively charge MAX_RESULTS for *each request*, even if X returns
    zero posts. This enforces an upper bound but is NOT measured dollar spend.
    """
    if (not os.getenv("NOUS_X_BEARER_TOKEN")
            or configured_max_daily_post_reads() == 0
            or not 1 <= pages <= X_MAX_PAGES):
        return False
    beginning = current.astimezone(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0)
    observed = db.scalar(select(func.coalesce(func.sum(FetchAttempt.request_count), 0))
                         .select_from(FetchAttempt)
                         .join(FetchJob, FetchAttempt.job_id == FetchJob.id)
                         .join(Source, FetchJob.source_id == Source.id)
                         .where(Source.adapter == "x_user_posts_v1",
                                FetchAttempt.started_at >= beginning))
    return (int(observed or 0) + pages) * X_MAX_RESULTS <= configured_max_daily_post_reads()


def latest_post_id(db, source_id: int) -> str | None:
    recent = db.scalars(select(Item.external_id).where(
        Item.source_id == source_id,
    ).order_by(Item.id.desc()).limit(256)).all()
    ids = [int(value) for value in recent if isinstance(value, str) and
           _ID.fullmatch(value)]
    return str(max(ids)) if ids else None


def _request_page(url: str, bearer: str) -> tuple[int, bytes, dict, str]:
    if (not url.startswith(_URL + "/2/users/") or
            urlparse(url).hostname != X_HOST):
        raise ValueError("non-X API URL blocked")
    target = httpx.URL(url)
    # DNS validation and HTTPS SNI pinning use the existing crawler security
    # contract, but no generic redirect-following fetcher sees this credential.
    ip = validate_url(url)
    request_url = target.copy_with(host=ip)
    with httpx.Client(timeout=httpx.Timeout(20, connect=5),
                      follow_redirects=False, trust_env=False) as client:
        with client.stream("GET", request_url,
                           headers={"Host": X_HOST,
                                    "Authorization": "Bearer " + bearer,
                                    "Accept": "application/json"},
                           extensions={"sni_hostname": X_HOST}) as response:
            if response.is_redirect:
                raise ValueError("X API redirect rejected")
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > _MAX_BODY:
                    raise ValueError("X API response exceeded reviewed size")
            return response.status_code, bytes(body), dict(response.headers), url


def parse_x_page(content: bytes, author_id: str) -> tuple[list[dict], str | None]:
    if len(content) > _MAX_BODY:
        raise ValueError("X page too large")
    try:
        data = json.loads(content)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid X API JSON") from exc
    if not isinstance(data, dict) or data.get("errors"):
        raise ValueError("X API returned an incomplete response")
    meta = data.get("meta")
    if not isinstance(meta, dict):
        raise ValueError("X timeline requires authoritative pagination metadata")
    rows = data.get("data", [])
    if not isinstance(rows, list) or len(rows) > X_MAX_RESULTS:
        raise ValueError("X timeline result count exceeded budget")
    if not isinstance(meta.get("result_count"), int) or meta["result_count"] != len(rows):
        raise ValueError("X timeline count mismatch")
    next_cursor = meta.get("next_token")
    if next_cursor is not None and (
            not isinstance(next_cursor, str) or not _CURSOR.fullmatch(next_cursor)):
        raise ValueError("malformed X pagination token")
    result = []
    seen = set()
    for entry in rows:
        if not isinstance(entry, dict) or not _ID.fullmatch(str(entry.get("id", ""))):
            raise ValueError("malformed X post ID")
        post_id = str(entry["id"])
        if entry.get("author_id") != author_id or post_id in seen:
            raise ValueError("X post author/identity mismatch")
        seen.add(post_id)
        if entry.get("referenced_tweets"):
            refs = entry["referenced_tweets"]
            if not isinstance(refs, list):
                raise ValueError("invalid X reference metadata")
            if any(isinstance(ref, dict) and ref.get("type") in ("retweeted", "replied_to")
                   for ref in refs):
                continue
        text, created = entry.get("text"), entry.get("created_at")
        if not isinstance(text, str) or not isinstance(created, str):
            raise ValueError("X post metadata incomplete")
        try:
            when = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid X post timestamp") from exc
        if when.tzinfo is None:
            raise ValueError("X post timestamp must be timezone-aware")
        excerpt = " ".join(text.split())[:160]
        if not excerpt:
            # Media-only post cannot be reconstructed within metadata-only policy.
            continue
        result.append({
            "id": post_id,
            "url": f"https://x.com/i/web/status/{post_id}",
            "title": excerpt,
            "published": created,
        })
    return result, next_cursor


def fetch_x_timeline(source_url: str, *, since_id: str | None, max_pages: int,
                     on_request, request_page=_request_page
                     ) -> tuple[int, list[dict], dict, str]:
    user_id = author_id_from_url(source_url)
    if since_id is not None and not _ID.fullmatch(since_id):
        raise ValueError("invalid X highwater ID")
    if not 1 <= max_pages <= X_MAX_PAGES:
        raise ValueError("X page budget exceeded")
    if configured_max_daily_post_reads() == 0:
        raise ValueError("X API read budget disabled")
    token = os.getenv("NOUS_X_BEARER_TOKEN")
    if not token or any(c.isspace() for c in token) or len(token) > 4096:
        raise ValueError("X bearer credential unavailable")
    result, seen = [], set()
    next_cursor = None
    for page in range(max_pages):
        params = {"max_results": str(X_MAX_RESULTS),
                  "exclude": "retweets,replies",
                  "tweet.fields": "created_at,author_id,referenced_tweets"}
        if since_id is not None:
            params["since_id"] = since_id
        if next_cursor is not None:
            params["pagination_token"] = next_cursor
        requested_url = source_url + "?" + urlencode(params)
        on_request()
        status, content, headers, final_url = request_page(requested_url, token)
        if final_url != requested_url:
            raise ValueError("X API response was redirected")
        if status != 200:
            return status, [], headers, final_url
        posts, next_cursor = parse_x_page(content, user_id)
        for post in posts:
            if post["id"] in seen:
                raise ValueError("duplicate X post across pages")
            seen.add(post["id"])
            result.append(post)
        if next_cursor is None:
            return 200, result, headers, final_url
    # Do not advance highwater and permanently lose the unretrieved portion.
    raise ValueError("X timeline exceeds configured page budget")
