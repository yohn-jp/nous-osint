# Edge frontend — static UI release

Status (2026-11-07): Cloudflare script and ten narrow zone Routes deployed;
authenticated end-to-end cutover and rollback **NOT VERIFIED**.

The private `nous-frontend` Worker serves only the prebuilt Quasar UI.
`/v1/*`, `/mcp*`, OAuth/discovery and `/reports/*` continue through the
existing Cloudflare Access + Tunnel + VM. No origin-fetch reverse proxy,
catch-all `nous.yohn.jp/*` Route, Workers VPC Service, public workers.dev
endpoint or preview URL is allowed.

## Build and test

Use Node 24.22.0, exact-pinned `cf` and Miniflare dependencies.

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

`prepare-assets.mjs` stages only `index.html` and flat Quasar assets.
Source maps, symlinks, nested and unapproved files are excluded.
`cf build` validates `.cloudflare/output/v0/` offline. The only config is
`cloudflare.config.ts`; obsolete passthrough mode is prohibited.

## Static assets and SPA navigation

`runWorkerFirst: false` keeps **existing** assets on Cloudflare's direct
static-serving path, without invoking user Worker code. Do not claim zero
Worker calls overall: SPA navigations invoke the Worker after the asset
lookup misses. With `notFoundHandling: 'none'`, only canonical GET/HEAD
allowlisted UI paths are rewritten to `/index.html` by the static-only
Worker; unknown paths, non-UI requests and absent JS/CSS files return
HTTP 404, not a generic SPA HTTP 200. Access protects the Worker and
its static assets; origin JWT/role checks protect dynamic traffic.

Terraform owns the ten specific zone Routes in
`deploy/cloudflare/terraform/main.tf`. CI only deploys Worker code and
assets; it must never mutate routes, Access, DNS or Tunnel. The exact
root Route does not match `/?query=...`; the VM UI fallback is retained.
Do not run Terraform apply before live resources/state are reconciled.

## Automatic deployment

Frontend-affecting main changes select `frontend` tests/build, followed
by `frontend-deploy` using the GitHub `frontend-production` Environment.
The immutable SHA-bound artifact is uploaded with the exact-pinned CLI;
`scripts/release.mjs` identifies the newly tagged Worker version through
Cloudflare's paginated Versions API (not human-readable CLI output).
The script checks current main and disabled public endpoints before
activating the exact version. UI-only commits do not rebuild the VM image.

Baseline: `main@a3a85d0`, [CI 42230090976](https://github.com/yohn-jp/nous-osint/actions/runs/42230090976)
passed and Cloudflare API confirmed version `813875ab-a155-45f6-a72e-514ce140a3d5`,
ten active Routes, `run_worker_first=false` and disabled public URLs.
That version still had automatic SPA handling for **missing** assets;
the subsequent 404 fix removes it. These are control-plane observations,
not real-browser, real-MCP or rollback proof.

Rollback removes only UI Routes, retaining the VM fallback; do not
restore the rejected catch-all Worker proxy. See
[release pipeline](../../docs/EDGE_RELEASE_PIPELINE.md) and
[edge decision](../../docs/EDGE_FRONTEND_DEPLOYMENT.md).
