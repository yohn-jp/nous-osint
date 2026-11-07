# Primary-source intelligence: low-latency collection and Live Feed

## Product contract

Nous is first an **observation terminal** and secondly a report publisher.
A user opening `/live` should discover the newest *observed primary-source
changes* without waiting for Codex, report publication, editorial verification,
CVE enrichment, or a news publisher's secondary coverage. Each result links
directly to the publisher and identifies its source and observation time.

This work is stacked on PR #44 because source categories are shared by
`/v1/sources`, `/v1/stream`, Explorer and report source selection. Source
taxonomy is not a severity score.

## Ingestion and display

```text
Researcher Bluesky posts (public AppView)   Original-research RSS/Atom
                |                                     |
                +----> existing SourceConfig catalog--+
                              |
                   scheduler / fetch worker
             conditional requests, retry, lease fencing
                              |
           Item + append-only ItemVersion + provenance
                      |                |
               /v1/stream         /v1/items
                      |                |
               Live Feed           Explorer
                      \                /
                scoped report evidence selection
```

### What the implementation does

- `bluesky_author_v1` reads only
  `https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed` with an
  immutable `did:plc:` identity, `filter=posts_no_replies` and `limit=100`.
  Fetch and response author identities must agree. The adapter excludes
  reposts and replies and persists the post URI, a **160-character maximum**
  whitespace-normalized excerpt, AppView `indexedAt`, and a direct Bluesky
  link. It does not store full bodies, media, embeds, repost graphs, or likes.
  Posts with no text are not represented by invented titles.
- The monitored personal author identities were verified against public
  Bluesky profiles on 2026-11-07: Kevin Beaumont
  (`did:plc:6bk4sb3yjxcbvpap7tnclaic`), Marcus Hutchins
  (`did:plc:idwhjzs5boatwv4zxwwcjk5i`) and Jake Williams
  (`did:plc:imfamhliw5q2fwk6x36hjfj4`). Author name is from the reviewed
  registry; the post link is addressed by DID and record key.
- Publisher research sources: Google Project Zero's Blogger Atom,
  PortSwigger Research RSS, watchTowr Labs RSS and Google's GTIG FeedBurner
  feed. All are configured as `threat_research` / `news` because the
  canonical item schema does not claim that every post is an advisory or CVE.
- Each reviewed source is configured for a **15-minute poll** and a per-source
  cap of **4 requests/hour**. These are requested polling settings, *not*
  guaranteed source-to-screen freshness. The worker's host concurrency,
  retry/backoff, upstream caching, API availability and publication delay
  all matter. Registered sources start enabled but actual ingestion remains
  unverified until VM egress and observed items are inspected.
- `GET /v1/stream` returns append-only `ItemVersion` events in descending
  immutable database ID order. This fixes the old `/v1/items` search
  ordering **without breaking its pagination contract**. Each event is
  `new` or `updated`; a byte-identical fetch never creates another
  event. `cursor=<observation_id>` walks older events; source/category
  filtering uses the existing catalog taxonomy. Careers are excluded by
  default; the API can opt in. Publisher timestamps are informational only
  and never reorder historical observations.
- The Quasar `/live` page is the default landing screen. It fetches
  status **every 60 seconds while visible**, provides source filters,
  manual refresh, original-link actions and historical pagination.
  An incoming-data banner avoids replacing the viewed list until the
  reader deliberately chooses to show new observations. No push transport
  or SLA is claimed. `/explore`, `/reports/` and `/sources` remain reachable.

### What is not implemented

- X authentication, scraping, third-party mirrors, or rate-limit evasion.
- Bluesky firehose/Jetstream. A polled author's latest 100 posts is **not**
  a lossless real-time stream: bursts, deletions and upstream outages can
  cause gaps. The same is true for last-N-entry RSS feeds.
- Complete post reproduction, translation, social previews, LLM ranking,
  report generation triggered by posts, social graph crawling, author
  discovery, duplicate clustering across publishers or proof of exploitation.
- Validated production source-to-render latency. At deployment, measure
  `published_at` (publisher/Bluesky AppView index) and
  `ItemVersion.observed_at` separately; for RSS publisher timestamps may
  be absent or backdated. Track observed source errors and stale
  `Source.last_success_at`. Do not advertise faster collection based
  solely on configured intervals.

## Follow-up architecture decisions

1. **Source discovery and approval:** Identify research communities and
   individual researchers from first-party publications, cited repositories
   and publicly verified identities. Record a reviewed DID/feed/API,
   category, license and rate limit. Suggest additions, never auto-enable
   third-party personal accounts without scope validation.
2. **Coverage and timeliness:** Track source gap, HTTP 429/5xx, last success,
   and publish-to-observe delay distributions. Establish a no-loss ingestion
   contract or explicitly label lossy sources (including AppView and RSS).
3. **Priority without loss:** Maintain an unranked complete Live Feed;
   add optional evidence-grounded triage in a separate view. No unsupported
   risk score or AI-inferred threat severity.
4. **Editorial derived layer:** Add time-window source selection from PR #44,
   cross-source identity/deduplication, cited daily briefs and high-confidence
   alerts after direct source coverage has been measured. Reports must
   always link to exact original observations.

## Rollout checks

1. Merge PR #44 first, then this PR, preserving main branch migration and
   CI contracts. No DB migration is required by this PR.
2. Verify source registration and `enabled` overrides in the runtime DB.
3. Confirm successful HTTP GETs from the actual VM and
   `Source.last_success_at`; inspect rejected/429 responses explicitly.
4. Fetch `/v1/stream` and check ID ordering, exact original URLs,
   author identity, update-only-on-change, cursor consistency and absence
   of jobs in default feed. Check desktop and mobile interactions.
5. Verify frontend automatic deployment independently of VM runtime rollout;
   PR checks do not release new runtime images.

## Reverse-proxy and Cloudflare route acceptance

This feature requires matching allowlists at every hop. The first Live Feed
merge introduced `/live` and `/v1/stream` but did not originally update the
origin Access/RemoteGateway and Cloudflare UI-only Worker route contracts.
Follow-up integration fixes add `/live` to:

- `src/nous/access_auth.py` SPA route and Access route gate;
- `edge/frontend/src/index.ts` static-only Worker router;
- `deploy/cloudflare/terraform/main.tf` explicit `nous.yohn.jp/live*`
  Worker zone route (never use catch-all);
- frontend and gateway routing tests.

The origin `/v1/stream` now belongs to GET-only authenticated API routes and
accepts only `category`, `source`, `include_careers`, `limit`, `cursor`
under the existing query length/duplicate-key restrictions. `/v1/items`
also accepts the already documented filters `state`, `organization`,
`category`, `since`, `published_since` as well as its prior keys.
**All API/MCP/OAuth/report routes bypass the UI-only Worker.**

Cloudflare routes are Terraform-managed; a successful CI validate is *not*
a Terraform apply. The VM API/Gateway must be updated to a compatible image
and database schema before Live Feed can return real observations. Frontend
deployment alone is not feature availability. Verify `/live`,
`/v1/stream`, category-based `/v1/items` through the Access hostname after
the actual infrastructure rollout.
