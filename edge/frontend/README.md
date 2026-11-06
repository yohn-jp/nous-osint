# Edge frontend — Phase A (not deployed)

This project builds the existing Quasar SPA for Workers Static Assets. It does
not create a route or change production. The retained VM UI remains the fallback.

Use Node **24.22.0** (also pinned in `.node-version` and frontend CI). Dependencies
and the beta `cf` / Vite plugin are exact-pinned in the package lock.

```sh
cd ui
npm ci --no-audit --no-fund
npm run typecheck
npm run build
cd ../edge/frontend
npm ci --no-audit --no-fund
npm run typecheck
npm run build
npm test
npx cf deploy --dry-run --prebuilt --mode production
```

`npm run build` copies only `index.html` and flat Quasar assets from the actual
`ui/dist/spa` into an ignored staging directory, rejecting source maps, symlinks
and nested files. All other files are ignored. Vite then emits the Worker and
assets under `.cloudflare/output/v0/`; `cf build` validates that output offline.
There is one authoritative `cloudflare.config.ts`, no Wrangler config.

`npm run build:passthrough` builds the **same Worker name** with
`PASSTHROUGH_ONLY=true`; validate it with
`npx cf deploy --dry-run --prebuilt --mode passthrough`.
Normal builds default the flag to false. A request header/query cannot select it.
Only a later approved rollout may deploy either mode. Never use a preview deploy.
`workers.dev` and version preview URLs are disabled, and preview builds fail.

## Request contract

All requests run the Worker first. Only canonical-host GET/HEAD requests to the
current explicit Python SPA allowlist use `/index.html`. Flat `/assets/*` uses
the asset binding with no fallback; missing files stay 404. Safe unknown screen
paths return a plain 404 with no backend diagnostics. `/mcp*`, reserved paths,
API, reports, discovery, non-GET/HEAD, percent-encoded/ambiguous paths and unknown
methods go to `fetch(request)`. No identity header is used to authorize anything.
URL parser normalization already performed before a Worker receives a Request
cannot be reversed here; encoded or otherwise observable ambiguous paths are
never decoded into an allowed screen path.

Origin requests and responses are returned unchanged: no buffering, response
caching, redirect following, URL rewriting or header reconstruction. Incoming
Worker requests use manual redirect mode. The origin owns signed JWT validation,
API/admin authorization, OAuth responses, streaming and report cache/security
headers. Static responses use `no-store` and `nosniff`, preserving binding CSP
and content types. Immutable caching and asset fast paths are deferred until
Access is proven in the effective deployment.

## Evidence and remaining gates

Pre-implementation checks on 2026-11-06 used main
`d6409f27fb0ed41b2d2ff342d32d8e1609dea4ca` (no open PRs; main CI successful).
The existing Gateway, Terraform, Actions, Containerfile and MCP/Tunnel Quadlets
match the plan: no Edge project/route, Quasar built into the application image,
reports served from their private VM volume. None of those runtime resources
are changed by Phase A.

Cloudflare's [Routes documentation](https://developers.cloudflare.com/workers/configuration/routing/routes/)
confirms same-host `fetch` goes to the proxied DNS origin, rather than recursively
invoking the Route. [Access documentation](https://developers.cloudflare.com/workers/configuration/cloudflare-access/)
states hostname Access runs before Workers. The pinned [cf project workflow](https://developers.cloudflare.com/cf/projects/)
and [configuration](https://developers.cloudflare.com/cf/projects/cloudflare-config/)
support offline builds, assets, disabled public endpoints and versioned modes.
These product contracts do **not** prove compatibility with the effective
Managed OAuth MCP application: retain the live passthrough, JWT, OAuth challenge,
SSE, anonymous asset, browser and rollback gates in Phase C.

Tests cover routing parity with the Python regexes, actual Quasar files in
Miniflare, origin denial/redirect preservation, request identity/body/headers,
MCP session and incremental stream propagation. The emulated outbound origin is
synthetic: it does not simulate Access, Tunnel or Managed OAuth and never calls
production. No live Cloudflare/VM changes or authenticated probes are performed.

The repository is public. CI builds/tests locally on the runner, but does not
publish artifacts or preview URLs; no restricted private artifact destination
has been provided. Private preview artifact publication is **BLOCKED** pending
such a destination. Build output can be reviewed locally with the commands above.

## Ownership for later phases

Terraform (`deploy/cloudflare/terraform/`) owns the zone Worker Route, Access,
Tunnel and DNS. CI will own script + assets only. This config declares no routes,
triggers or custom domains. Phase B must preserve Terraform-owned routes when
selecting script upload/deploy commands; do not apply empty trigger configuration
as a substitute for a script release. Phase A's build-only CI has no Cloudflare
credentials and no deploy job. A future deploy token needs only intended-account
Workers Scripts Write (plus any asset-upload permissions required by the selected
CLI), not Access/Tunnel/DNS/Route write; verify effective token scopes in Phase B.

Rollback stays the approved plan: deploy passthrough and/or remove only the zone
Route using Terraform, restoring the retained VM UI. This has **not** been
rehearsed live. Phase B–D are intentionally not implemented here.
