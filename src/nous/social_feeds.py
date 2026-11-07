"""Metadata-only ingestion of a single verified public Bluesky author.

Only public AppView GET responses are accepted. The post URL and bounded
headline-length excerpt are retained; reposts, replies, full bodies, embeds,
media, follower graphs, and private data are not collected.
"""
import json
import re
from urllib.parse import parse_qs, urlparse

_DID = re.compile(r"did:plc:[a-z2-7]{24}")
_POST_URI = re.compile(r"at://(did:plc:[a-z2-7]{24})/app[.]bsky[.]feed[.]post/([a-z0-9]{1,50})")
_MAX_POSTS = 100
_MAX_EXCERPT = 240


def author_from_url(url: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    if (parsed.scheme != "https" or parsed.hostname != "public.api.bsky.app"
            or parsed.path != "/xrpc/app.bsky.feed.getAuthorFeed"
            or parsed.username or parsed.password or parsed.fragment
            or set(query) != {"actor", "filter", "limit"}
            or query.get("filter") != ["posts_no_replies"]
            or query.get("limit") != ["100"]):
        raise ValueError("Bluesky adapter requires the fixed public author-feed endpoint")
    actors = query.get("actor", [])
    if len(actors) != 1 or _DID.fullmatch(actors[0]) is None:
        raise ValueError("Bluesky feed must use a verified immutable author DID")
    return actors[0]


def extract_bluesky_author(content: bytes, source_url: str, final_url: str) -> list[dict]:
    actor = author_from_url(source_url)
    if final_url != source_url:
        raise ValueError("Bluesky author endpoint redirected")
    try:
        payload = json.loads(content)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid Bluesky JSON") from exc
    if (not isinstance(payload, dict) or not isinstance(payload.get("feed"), list)
            or len(payload["feed"]) > _MAX_POSTS):
        raise ValueError("invalid Bluesky author feed shape")
    results = []
    seen = set()
    for item in payload["feed"]:
        if not isinstance(item, dict):
            raise ValueError("invalid Bluesky feed entry")
        # The read API may include boosts or thread context; do not silently
        # represent a repost by the requested actor as their own research.
        if item.get("reason") or item.get("reply"):
            continue
        post = item.get("post")
        if not isinstance(post, dict):
            raise ValueError("missing Bluesky post")
        author = post.get("author")
        record = post.get("record")
        if not isinstance(author, dict) or not isinstance(record, dict):
            raise ValueError("invalid Bluesky author or post record")
        uri = post.get("uri")
        match = _POST_URI.fullmatch(uri) if isinstance(uri, str) else None
        if match is None or match.group(1) != actor or author.get("did") != actor:
            raise ValueError("Bluesky author identity mismatch")
        if record.get("$type", "app.bsky.feed.post") != "app.bsky.feed.post":
            raise ValueError("unexpected Bluesky record type")
        text = record.get("text")
        indexed_at = post.get("indexedAt")
        if (not isinstance(text, str) or not text.strip()
                or not isinstance(indexed_at, str) or len(indexed_at) > 50):
            raise ValueError("missing Bluesky public metadata")
        if uri in seen:
            raise ValueError("duplicate Bluesky post URI")
        seen.add(uri)
        headline = " ".join(text.split())[:_MAX_EXCERPT]
        results.append({
            "id": uri,
            "url": f"https://bsky.app/profile/{actor}/post/{match.group(2)}",
            "title": headline,
            # AppView-indexed publication time, not the user's editable
            # record.createdAt; do not claim exact ingest latency.
            "published": indexed_at,
        })
    return results
