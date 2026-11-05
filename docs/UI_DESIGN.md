# Nous OSINT — Quasar Information Portal UI

Status: **implemented and deployed behind the existing Access-required Tunnel; browser acceptance remains in progress**
Updated: 2026-11-03  
Companion: [FRONTEND_EXECUTION_POLICY.md](FRONTEND_EXECUTION_POLICY.md), [ARCHITECTURE.md](ARCHITECTURE.md)

## Decision

Build a **client-rendered static SPA** using **Quasar 2, Vue 3, TypeScript, and Quasar CLI with Vite**. Use stock Quasar components as the primary design system. Serve built assets from a static host (Cloudflare is the intended target), never from a persistent Node/UI application on the compute VM.

Visual direction: **research feed**, informed by the information hierarchy of feed readers such as Feedly, **not a visual or asset clone**. The product identity is provenance-first: source, timestamp, record type, and change state are immediately visible; the source-linked title is the dominant artifact. Avoid fake counters, decorative charts, and invented summaries.

## Interaction model

### Desktop (≥ 1024 px)
- Small left rail: product, **Explore**, **Changes**, **Sources**. Active navigation is clearly marked.
- Main column: prominent global query input; compact kind/source filters; newest/current metadata-oriented results in an uninterrupted reading list; bounded page loading.
- Optional right preview pane on large viewports: selected record title, source, original URL, timestamps, metadata, provenance and revisions. Never treat a preview as the publisher's full text.
- Main list and preview are independently scrollable when space permits; keyboard focus remains visible.
- Query and selected record appear in the URL, permitting deep links, back/forward, refresh and sharing.

### Mobile (< 1024 px)
- Compact header and bottom navigation or drawer using Quasar primitives.
- Search and filters form a vertical stack; list rows prioritize titles and publisher identity.
- Detail is a full page (not a narrow right pane). Back preserves the search/filter state and position as reasonably possible.
- No required horizontal scrolling; 320px-wide layout must remain usable. Allow Japanese IME composition.

### Information hierarchy and styling
- Reading-focused neutral surfaces, a restrained moss/teal accent for actionable states, thin separators, and high-contrast typography. Do not imitate Feedly logos, colors, or proprietary assets.
- Use built-in Quasar spacing/type/color utilities first. Keep custom styles to a small shared stylesheet for layout, readable line lengths and active-state emphasis; no custom control system.
- Supports light/dark theme with Quasar; respect reduced motion. Status/state is conveyed through text, not just color.
- No external tracking fonts/scripts or untrusted HTML injection.

## Interaction-first design contract (2026-11-05)

The object of work is an observed record, its publisher, its timestamp, its change state, or an operational source. This UI is a **daily research instrument**, not a product-marketing landing page. The interface should communicate the result of a user action before adding ornament.

### Antipatterns and replacements

| Reject | Do instead | Reason / check |
| --- | --- | --- |
| Large narrative headings (`情報を探索する。`) and repeated English micro-kickers | Short Japanese screen names and an explicit task description where needed | Make the first glance about the work |
| KPI cards with no direct action; inferred counts on API failure | Contextual, compact, truthfully sourced operational overview; unresolved is not zero | Distinguish loading, unavailable, disabled, and empty |
| All records as floating cards with shadows and oversized corners | A continuous scan-friendly result list with restrained separators | Density and source comparison serve the user |
| Repeated delayed row-entry animations and hover translations | Instant selection/focus feedback (background/active indicator), reduced-motion parity | No item should shift away from the pointer |
| Treating an information-only tag as a button | Separate static statuses from actionable controls | Shape and contrast must match affordance |
| Showing `停止` for a source not yet installed | Explicit `未導入`, `停止`, or `収集中` | Prevent incorrect operational decisions |
| Generic `アクセス権限を確認してください` with apparently empty datasets | Keep error state separate from true empty results and expose recovery action | Errors are not missing data |
| Decorative dashboards with invented metrics | Surface only real API observations and their associated actions | No unverified telemetry |

### Motion policy

Motion is **feedback**, not an atmosphere. Use short reversible transitions for hover/selection and actual disclosure. No page-entry choreography, staggered list reveal, card lift, fake loading completion, or transforms that displace operational controls. Keep keyboard focus visible during interaction and honor `prefers-reduced-motion`.

### Review and evidence

At 320/390px and desktop widths verify: scan speed with long Japanese/Latin titles, preserved query/filter state, IME composition, touch targets, keyboard selection, 200% text zoom, truthful loading/empty/permission/error states, report-to-library navigation, light/dark modes, and reduced-motion. CI only verifies builds/tests, not rendered visual quality. Browser checks must be marked unverified until actually performed.

Design references used for evaluation (principles, not copied assets): [NN/g usability heuristics](https://www.nngroup.com/articles/ten-usability-heuristics/), [Linear's 2026 UI reasoning](https://linear.app/now/behind-the-latest-design-refresh), [Carbon filtering](https://www.carbondesignsystem.com/building-blocks/core/patterns/filtering), [GOV.UK error guidance](https://design-system.service.gov.uk/components/error-message/), [GOV.UK tag guidance](https://design-system.service.gov.uk/components/tag/), [MDN reduced motion](https://developer.mozilla.org/en-US/docs/Web/CSS/@media/prefers-reduced-motion).

## Pages / feature contracts

1. **Explore** (primary): keyword query, kind and source filters, query submission and reset, stable incremental **cursor** pagination, loading/empty/error states. Render title, organization or source, kind/state, publication/observation time; opening the item shows source attribution and revisions. No entire-corpus fetch.
2. **Detail**: real `GET /v1/items/{id}` data; publisher URL as an explicit external action; provenance shown as readable key-value metadata; `GET /v1/items/{id}/versions` displays immutable versions. Treat source attributes as untrusted plain text.
3. **Changes**: request `GET /v1/changes?since=...`; default lookback is explicit in UI; render newly observed versions with timestamps, with drill-through to detail. Existing API currently accepts `since` and `kind`, not cursors.
4. **Sources**: show real `GET /v1/sources` status, last success, next due, errors and enabled state. **Read only**; the existing API has no management writes.
5. **RSS / Watches**: **not yet present in the API**. Do not fabricate RSS or saved-watch endpoints or enable nonfunctional controls. Add only after their backend contracts and authorization are implemented.

## API boundaries

Existing FastAPI contracts have been verified in `src/nous/api.py`:
- `GET /v1/items?kind=&source=&q=&limit=&cursor=` returns `{items: ItemResponse[], next_cursor: number|null}`, max 100 per request.
- `GET /v1/items/{id}` returns an item with `attributes` and `provenance`.
- `GET /v1/items/{id}/versions` returns a version array.
- `GET /v1/sources` returns source status array.
- `GET /v1/changes?since=&kind=&limit=` returns `{changes: [...]}`.
- `GET /v1/status` provides operational counters; use only when there is a real UI need.

The UI uses the **same-origin `/v1` route** through the MCP origin's authenticated gateway, not an embedded API secret or direct SQL. The origin validates the Cloudflare Access JWT and proxies only the UI's GET allowlist to the loopback-only API. For local development use a Vite dev proxy to a loopback API. Cloudflare resources were not changed for the UI rollout. Endpoint failure, 401/403/404, empty data, and stale sources must remain truthful and actionable.

## Security and operational constraints

- No credentials in static assets or browser persistent storage. Browser query params contain only non-sensitive filters; don't place a private token in the URL.
- No HTML rendering of publisher content; Vue interpolation escapes untrusted strings. External links use `rel="noopener noreferrer"`.
- No unauthorized API/public exposure: VM API stays loopback-only; the origin exposes only the Access-JWT-protected read routes needed by this UI.
- No client-side data fabrication in production. Demo fixtures, if any, are strictly isolated and labeled.
- Frontend CI must compile/typecheck from committed dependency metadata; no UI runtime container.
- Preserve the single-VM Podman/Quadlet/PostgreSQL design; do not introduce Appsmith, MongoDB, Redis, SSR, separate search database, or UI server.

## Acceptance matrix

- [ ] Static SPA compiles and typechecks without an always-running UI backend.
- [ ] Real read-only API integration for Explore, Detail/versions, Changes, Sources.
- [ ] Cursors advance without `COUNT(*)` or unbounded client fetching; filter change discards stale requests and cursor.
- [ ] Mobile 320/390px and desktop 1280px rendering, keyboard focus, Japanese IME, errors, empty/loading states checked.
- [ ] No untrusted HTML rendered, no credentials embedded, API calls remain same-origin.
- [ ] CI build/check passes; on-device/API end-to-end and Cloudflare Access remain explicitly unverified until exercised.
