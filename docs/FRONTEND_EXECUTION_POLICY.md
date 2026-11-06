# Frontend execution and resource policy

Status: Browser-rendered Quasar and separate runtime-generated Astro reports; edge UI delivery APPROVED AS PLAN, NOT YET DEPLOYED
Updated: 2026-11-06

## Objective

Nous OSINT's compute VM must spend resources on collection, normalization, durable storage, and bounded query execution—not server-side UI rendering or an always-on low-code application stack.

PostgreSQL remains the authoritative store for observations, normalized items, provenance, versions, and query state. Existing ingestion and deployment decisions in ARCHITECTURE.md remain authoritative.

## Execution boundaries

- **Client/browser:** render the UI, manage local interaction state, perform display-only transformations on bounded result pages, navigate and cache non-sensitive responses with appropriate controls.
- **Static hosting/CDN:** serve versioned, pre-built HTML, JavaScript, CSS and fonts. No UI application server, server-side rendering, Node.js runtime, MongoDB, or Redis on the Nous VM for presentation.
- **Nous API:** authenticate/authorize at a verified trust boundary, validate and bound queries, expose a stable read API, RSS/Atom exports, provenance and revisions. Do not accept raw SQL from the browser.
- **PostgreSQL:** perform full-text search, filtering, ranking, sorting, pagination, aggregates and provenance/history queries. Never ship an entire corpus to the browser for searching.
- **Workers:** ingest permitted public sources, deduplicate and persist revisions independently of frontend availability.
- **Report Worker:** run the official Codex CLI and start Astro only as a bounded, one-shot static build after an article passes deterministic checks. Publish verified static HTML/assets to the private report volume. The Astro process exits after the build; it is not a UI server.

## Selected frontend (implementation in ui/)

- Quasar 2 + Vue 3 + TypeScript, Quasar CLI with Vite, static SPA with browser-only rendering. [UI_DESIGN.md](UI_DESIGN.md) is the UI design contract.
- Feed-reader-inspired, source-first information layout using Quasar components; not a Feedly copy. Vue pages and a small shared stylesheet still require maintenance.
- **Current implementation:** build Quasar static assets into the digest-pinned MCP origin image and serve them at `/` through the Access-required Tunnel. The same-origin `/v1` path includes read-only query APIs and explicitly allowlisted administrator methods, all behind Access JWT and role validation.
- **Approved migration (not deployed):** publish only Quasar assets via explicit path-specific static routes using assets-first delivery (`runWorkerFirst: false`), without billable Worker invocations for asset hits on the same hostname; `/v1`, `/mcp`, and the runtime-generated `/reports/` archive continue directly through the existing Tunnel, without a Worker proxy. A catch-all `nous.yohn.jp/*` Worker Route is prohibited; route feasibility and Access on every static path must be validated before cutover. Root URLs with query strings are not selected by an exact root route and must keep the existing VM UI fallback until resolved. GitHub Actions will deploy UI-only changes without rebuilding the backend image. See [EDGE_FRONTEND_DEPLOYMENT.md](EDGE_FRONTEND_DEPLOYMENT.md).
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

- **Current:** Quasar assets are produced at backend-image build time and served by the MCP origin. **Target after the edge rollout:** assets are built/deployed by an independent GitHub Actions edge job; a UI-only change must not publish a backend image or require a VM update. The cutover must first prove Access/MCP/report continuity and rollback.
- Astro is present only in the separate report Worker image. It runs once per publication to generate static report files; no Node listener, SSR, or persistent presentation process runs on the VM. The MCP gateway serves the private report volume read-only through the existing Access boundary.
- Verify browser-side list/detail/filter navigation and usability on desktop/mobile; prevent loading an entire result set into memory.
- Measure JS transfer size, initial render and interaction responsiveness in browsers; avoid claiming a measured budget before testing.
- Measure API latency, PostgreSQL query plans/index use and memory separately; compare with an API-only baseline.
- One query contract backs UI, REST and RSS where possible; source provenance and update timestamps remain available. RSS/watch APIs remain unimplemented and are not exposed as functional UI features.
- UI availability remains independent of ingestion/API acceptance; backend readiness and UI behavior are verified separately.
