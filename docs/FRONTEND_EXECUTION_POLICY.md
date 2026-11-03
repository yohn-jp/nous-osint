# Frontend execution and resource policy

Status: Quasar SPA implementation complete; VM rollout is being validated
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

## Selected frontend (implementation in ui/)

- Quasar 2 + Vue 3 + TypeScript, Quasar CLI with Vite, static SPA with browser-only rendering. [UI_DESIGN.md](UI_DESIGN.md) is the UI design contract.
- Feed-reader-inspired, source-first information layout using Quasar components; not a Feedly copy. Vue pages and a small shared stylesheet still require maintenance.
- Build the static assets into the digest-pinned MCP origin image and serve them at `/` through the existing Access-required Tunnel. The browser's same-origin `/v1` API is a strict GET-only proxy behind the Access JWT verifier; the underlying FastAPI listener stays loopback-only on the host.
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

- UI assets are produced at image build time; the VM runs no Node or UI renderer, only serves the static files from the existing MCP process.
- Verify browser-side list/detail/filter navigation and usability on desktop/mobile; prevent loading an entire result set into memory.
- Measure JS transfer size, initial render and interaction responsiveness in browsers; avoid claiming a measured budget before testing.
- Measure API latency, PostgreSQL query plans/index use and memory separately; compare with an API-only baseline.
- One query contract backs UI, REST and RSS where possible; source provenance and update timestamps remain available. RSS/watch APIs remain unimplemented and are not exposed as functional UI features.
- UI availability remains independent of ingestion/API acceptance; backend readiness and UI behavior are verified separately.
