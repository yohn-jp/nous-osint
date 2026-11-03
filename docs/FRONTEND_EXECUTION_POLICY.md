# Frontend execution and resource policy

Status: browser-rendered Quasar SPA implementation in progress  
Updated: 2026-11-03

## Objective

Nous OSINT's compute VM must spend resources on collection, normalization, durable storage, and bounded query execution—not server-side UI rendering or an always-on low-code application stack.

PostgreSQL remains the authoritative store for observations, normalized items, provenance, versions, and query state. Existing ingestion and deployment decisions in ARCHITECTURE.md remain authoritative.

## Execution boundaries

- **Client/browser:** render the UI, manage local interaction state, perform display-only transformations on bounded result pages, navigate and cache non-sensitive responses with appropriate controls.
- **Static hosting/CDN:** serve versioned, pre-built HTML, JavaScript, CSS and fonts. No UI application server, server-side rendering, Node.js runtime, MongoDB, or Redis on the Nous VM for presentation.
- **Nous API:** authenticate/authorize at a verified trust boundary, validate and bound queries, expose a stable read API, RSS/Atom exports, provenance and revisions. Do not accept raw SQL from the browser.
- **PostgreSQL:** perform full-text search, filtering, ranking, sorting, pagination, aggregates and provenance/history queries. Never ship an entire corpus to the browser for searching.
- **Workers:** ingest permitted public sources, deduplicate and persist revisions independently of frontend availability.

## Selected frontend (implementation in ui/; not deployed)

- Quasar 2 + Vue 3 + TypeScript, Quasar CLI with Vite, static SPA with browser-only rendering. [UI_DESIGN.md](UI_DESIGN.md) is the UI design contract.
- Feed-reader-inspired, source-first information layout using Quasar components; not a Feedly copy. Vue pages and a small shared stylesheet still require maintenance.
- Serve static assets through Cloudflare (behind Access if private); expose the API via the separately authenticated/tunneled origin with same-origin reverse proxy preferred to avoid CORS complexity.
- Reuse PostgreSQL views/functions as the canonical query contract; PostgREST is a candidate for read endpoints, while existing FastAPI can remain for domain-specific operations and feed output. Avoid redundant API surfaces unless justified.
- PGroonga is a candidate for Japanese search; verify extension/container compatibility and search relevance before adoption.
- Avoid Appsmith and other persistent low-code UI backends in the initial architecture due to compute/memory costs unrelated to Nous's core processing.

## Security constraints

- Never expose PostgreSQL to the browser or public network.
- Browser code contains no database credentials, signing keys, or static bearer tokens. Static CDN access is not by itself API authorization.
- Implement authentication for both static UI and API; validate Access identity/token at a trusted boundary or use an equivalent authenticated API gateway. If public RSS is desired, create a separate expressly reviewed metadata-only export policy.
- API credentials are server-side; PostgREST uses a least-privilege role, controlled views/functions, and RLS where required. Do not grant write access to search clients.
- Bound search query complexity, response size, pagination, and rate. Sanitize untrusted source text rendered in browsers; strict CSP when practical.
- Do not persist private search results in shared edge caches. HTTP caching and ETags must respect identity and freshness.

## Performance and acceptance

- UI assets are produced at build time; VM does not run a UI renderer.
- Verify browser-side list/detail/filter navigation and usability on desktop/mobile; prevent loading an entire result set into memory.
- Measure JS transfer size, initial render and interaction responsiveness in browsers; avoid claiming a measured budget before testing.
- Measure API latency, PostgreSQL query plans/index use and memory separately; compare with an API-only baseline.
- One query contract backs UI, REST and RSS where possible; source provenance and update timestamps remain available. RSS/watch APIs remain unimplemented and are not exposed as functional UI features.
- The preexisting implementation phases remain in order. UI rollout is a later phase and is not evidence that ingestion/API endpoints already work.
