# X primary-source ingestion — official API only

## Release intent

Nous's Live Feed must expose original security-researcher publications as soon
as the approved publisher interface can be polled. It does not wait for a
security news site or generated report. The existing source-specific publishing,
provenance, multi-source search and report pipelines remain authoritative.

This integration is **opt-in** because the official X API requires a developer
application and consumption-based billing. X's posted developer pricing on
2026-11-07 listed **USD 0.005 per fetched Post**; rates, quotas and permitted
use may change. Exact provider billing must be confirmed in the X console.

Official docs and policy:
- https://developer.twitter.com/ (official pay-per-use)
- https://docs.x.com/overview
- https://github.com/xdevplatform/samples/blob/main/python/users/timeline/get_posts.py
- https://docs.x.com/developer-terms/policy
- https://x.com/en/tos (October 9, 2026 terms prohibit unauthorized scraping)

No scraping, X cookies, unreviewed public mirrors, or simulated API key is used.

## Source configuration

Admin UI: Sources -> Add -> JSON API -> **X official API (public account)**.
The SourceConfig URL must use the immutable **numeric** X user ID:

```text
https://api.x.com/2/users/2244994945/tweets
```

The numeric ID above is from X's public SDK example. It is *not* an
automatically selected security researcher. A real researcher is added only
after their own profile and official numeric ID have been verified. Sources
created through the Admin UI remain **disabled** by default.

Required configuration: `kind=json_api`, `adapter=x_user_posts_v1`,
`item_kind=news`, `category=threat_research`, `interval_minutes>=15`,
`max_pages=1..3`, and `max_requests_per_hour>=max_pages`. The official
endpoint and user ID are reviewed by SourceConfig before any collection.

On the backend **worker** environment only (never public Edge/Frontend):

```text
NOUS_X_BEARER_TOKEN=(secret from X Developer Console)
NOUS_X_MAX_DAILY_POST_READS=1000
```

Neither variable is populated in repository configuration. The daily budget
defaults to **zero**: no X HTTP requests are attempted without a nonblank
bearer token and positive, explicit daily budget. The example value `1000`
is an *illustrative configuration*, **not** a provisioned spend budget.

The budget is conservative: each X page request reserves **10 potential
read resources** and at most 3 pages are allowed per source poll. Existing
PostgreSQL `FetchAttempt.request_count` is summed over all X sources since
00:00 UTC, under the existing per-host advisory lock and one-active-request
invariant. For example, 1000 reserved Post reads corresponds to a provisional
USD 5/day maximum at the displayed rate; actual billing can differ, and
the budget should be checked against provider's billing records.

A disabled/missing credential or exceeded budget keeps the job queued and
sets a bounded `x_api_budget_or_token_not_configured` source error; it
doesn't attempt X connectivity. Rate-limit responses follow the existing
429 retry/backoff logic. No bearer token appears in provenance or errors.

## Collection semantics

- X app-only bearer author timeline, one fixed endpoint, TLS-pinned to the
  validated `api.x.com` host with redirects disabled. No search API,
  followers, likes, private data or other API requests.
- Request `exclude=retweets,replies` and
  `tweet.fields=created_at,author_id,referenced_tweets`.
  Recheck returned `author_id` against the immutable numeric source ID.
- The newest stored numeric post ID becomes `since_id` to avoid re-reading
  the same public posts on every poll. When the provider reports pagination,
  retrieve at most the source's `max_pages`; reject incomplete traversal
  rather than advancing highwater and silently losing posts.
- Save only Post ID, direct X URL, creation timestamp, and a whitespace-normalized
  **160-character excerpt**. No complete post bodies, media, interactions,
  inferred threat scores or author graph. Presentation links back to X.
- This is an **incremental** feed, never a complete account snapshot. Previous
  posts must not be marked `unknown` merely because `since_id` returned
  only new content. Each change remains an immutable `ItemVersion` and is
  immediately accessible at `GET /v1/stream` / Quasar `/live`.

## Known constraints and acceptance

The official X API is paid and subject to X Developer Agreement, display,
retention, deletion and rate-limit rules. The source policy must be reviewed
for the actual intended account and deployment; metadata may need to be
removed or refreshed as policy changes. Until a bearer key, spend budget,
approved author IDs and a successful **real VM poll** are observed, X data
collection is **not live**.

Before calling this feature operational, verify:
1. API token is present only in the backend, never API/Edge/UI secret tables,
   logs, events or direct responses.
2. The provider's real billing and per-user timelines match the schema;
   X error responses, 429 and auth failures are visible on the source.
3. 1/2/3-page polling, retry behavior, UTC budget rollover, request-count
   reservation and cross-source host concurrency under PostgreSQL.
4. Unchanged fetch creates no extra event; X incremental fetch does not
   invalidate earlier posts. Live Feed shows platform `X`, original link,
   author, publisher time and observed time.
5. Real-source latency and legal permission to retain the 160-char excerpt
   are verified separately. API tests and CI do not validate live pricing.

## Next intelligence milestones

Improve collection latency by measuring source-to-observation timestamps,
widen the verified researcher directory with policy-reviewed author IDs, and
add attributed source-to-source references. Preserve raw observations as the
primary surface; optional deduplicated priority alerts and daily reports are
derived views, not substitutes for the original feed.
