"""Bounded source-authenticated Bluesky public post metadata."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from nous.adapters import extract
from nous.registry import SourceConfig
from nous.social_feeds import author_from_url, extract_bluesky_author

DID = "did:plc:6bk4sb3yjxcbvpap7tnclaic"
OTHER = "did:plc:idwhjzs5boatwv4zxwwcjk5i"
URL = (f"https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?"
       f"actor={DID}&filter=posts_no_replies&limit=100")
URI = f"at://{DID}/app.bsky.feed.post/3maz3re4c2s2p"


def payload(*, did=DID, uri=URI, text="First observation CVE-2026-12345", reason=None,
            reply=None):
    post = {"uri": uri, "author": {"did": did}, "record": {
        "$type": "app.bsky.feed.post", "text": text,
        "createdAt": "2026-11-06T09:00:00Z",
    }, "indexedAt": "2026-11-06T10:05:00Z"}
    item = {"post": post}
    if reason is not None:
        item["reason"] = reason
    if reply is not None:
        item["reply"] = reply
    return {"feed": [item]}


def test_public_author_feed_returns_only_direct_metadata_and_stable_urls():
    data = payload()
    records = extract_bluesky_author(json.dumps(data).encode(), URL, URL)
    assert records == [{
        "id": URI,
        "url": f"https://bsky.app/profile/{DID}/post/3maz3re4c2s2p",
        "title": "First observation CVE-2026-12345",
        "published": "2026-11-06T10:05:00Z",
    }]
    assert "createdAt" not in json.dumps(records)
    assert "record" not in json.dumps(records)
    assert extract(SimpleNamespace(adapter="bluesky_author_v1", url=URL),
                   json.dumps(data).encode(), URL) == records


def test_did_and_response_identity_fencing():
    assert author_from_url(URL) == DID
    for bad in [
        URL.replace("public.api.bsky.app", "attacker.example"),
        URL.replace("filter=posts_no_replies", "filter=posts_with_replies"),
        URL.replace("limit=100", "limit=1000"),
        URL + "&cursor=arbitrary",
        URL.replace(DID, "some.handle"),
    ]:
        with pytest.raises(ValueError):
            author_from_url(bad)
    with pytest.raises(ValueError, match="redirect"):
        extract_bluesky_author(json.dumps(payload()).encode(), URL, "https://evil.example")
    with pytest.raises(ValueError, match="identity mismatch"):
        extract_bluesky_author(json.dumps(payload(did=OTHER)).encode(), URL, URL)
    with pytest.raises(ValueError, match="identity mismatch"):
        extract_bluesky_author(json.dumps(payload(uri=URI.replace(DID, OTHER))).encode(), URL, URL)


def test_reposts_and_replies_not_misrepresented_as_author_publications():
    assert extract_bluesky_author(
        json.dumps(payload(reason={"$type": "app.bsky.feed.defs#reasonRepost"})).encode(),
        URL, URL) == []
    assert extract_bluesky_author(
        json.dumps(payload(reply={"parent": {"uri": URI}})).encode(), URL, URL) == []


def test_reject_broken_or_oversized_feed():
    for candidate in [
        {"feed": None},
        {"feed": [{}]},
        {"feed": [payload()["feed"][0]] * 101},
        {"feed": [payload()["feed"][0]] * 2},
        {"feed": [{"post": {"uri": URI, "record": {"text": "x"}}}]},
    ]:
        with pytest.raises(ValueError):
            extract_bluesky_author(json.dumps(candidate).encode(), URL, URL)


def test_research_catalog_uses_checked_source_types():
    names = [
        "bsky-kevin-beaumont", "bsky-marcus-hutchins", "bsky-jake-williams",
        "google-project-zero", "portswigger-research",
        "watchtowr-labs", "google-gtig-research",
    ]
    for name in names:
        doc = yaml.safe_load(Path("sources", name + ".yaml").read_text())
        source = SourceConfig.model_validate(doc)
        assert source.category == "threat_research"
        assert source.enabled is True
        assert source.interval_minutes == 15
        assert source.max_requests_per_hour == 4
        assert source.policy.content_storage == "metadata_only"
        assert source.policy.report_quote_allowed is False
        if name.startswith("bsky-"):
            assert source.adapter == "bluesky_author_v1"
            assert author_from_url(source.url).startswith("did:plc:")
        else:
            assert source.adapter == "rss_v1"
