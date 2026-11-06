# Edge release pipeline — current main

Status (2026-11-07): main-triggered frontend release **implemented and
successfully exercised**, but authenticated E2E and rollback **NOT VERIFIED**.

Baseline `a3a85d0bced7efca58bafb318a454b50fb2ed6af`:
[GitHub CI 42230090976](https://github.com/yohn-jp/nous-osint/actions/runs/42230090976)
completed successfully, including `frontend-deploy`. Cloudflare API
showed private Worker version `813875ab-a155-45f6-a72e-514ce140a3d5`
active at 100%, ten explicit UI Routes and no public Worker URLs.
The previous fixed-version-output parser failure is resolved: uploads
are identified via the paginated Versions API, not CLI stdout.

## Changed-file scopes

`scripts/ci/changes.py` classifies the complete push or PR diff.
Pushes include changes since the most recent successful main CI run, so
failed/cancelled releases do not silently lose changes. Renames count as
delete/add and missing Git history causes failure rather than omission.

| Change | Selected work |
| --- | --- |
| `ui/**`, `edge/frontend/**` | Quasar/Edge build + tests, main-only Edge deployment |
| `src/**`, migrations, catalog, Python manifests | Python checks and affected backend/report images |
| `reports/**` | Report checks/image; templates also select API image |
| `src/nous/access_auth.py` | Backend and frontend route-parity checks |
| Tests | Python CI checks, not image publication by themselves |
| Cloudflare Terraform | Offline fmt/init/validate, never automatic apply |
| Shared workflow/unknown build inputs | Conservatively select all lanes |
| Docs only | Small CI contracts/aggregate, no release |

The `ci` aggregate requires all selected lanes to succeed; skipped
nonselected lanes are allowed. The VM image still includes Quasar solely
as fallback. Independent job steps run in parallel where configured.

## Release provenance and authority

`.github/workflows/ci.yml` triggers `frontend-deploy` only on selected
successful main pushes. It binds `frontend-production` GitHub Environment,
using its `CLOUDFLARE_API_TOKEN`, and downloads the artifact keyed to
the same main SHA and workflow run. The account/zone context is pinned
in the workflow. CI never deploys Cloudflare zone Routes or VM services.

`edge/frontend/scripts/release.mjs` refuses unexpected build mode,
SHA/provenance, public Worker URL or preview setting. It snapshots
Worker version IDs before upload, calls `cf workers versions create --prebuilt`,
then requires exactly one **new** version with that SHA tag. It rechecks
main HEAD and private endpoints before `cf workers deployments create`
activates the specific version ID. Stale or ambiguous uploads fail closed.
`production` static-only mode is the sole supported release.

`runWorkerFirst: false` allows existing static assets to be delivered
without Worker invocation. Set `notFoundHandling: 'none'` so missing
assets return HTTP 404; valid SPA navigation paths are handled explicitly
by the Worker on asset lookup misses. The former global SPA 200 fallback
and origin passthrough are rejected. CI asserts these settings.

Terraform owns only the ten explicit UI/static
`cloudflare_workers_route.frontend` patterns; no `nous.yohn.jp/*`.
**Note:** `frontend_route_enabled` defaults to `false` in repository
Terraform, although ten Routes are currently live. Before any apply,
reconcile imports, state and desired flag with live resources. Never
apply as new Access/Tunnel/DNS resources or allow a frontend CI token
to mutate Routes.

## Acceptance still missing

Live authenticated browser and MCP/OAuth exchanges; Access-negative cases;
effective routing and telemetry for `/v1`, `/mcp`, discovery and
`/reports/*`; and controlled rollback to the retained VM-hosted UI
remain **NOT VERIFIED**. An Actions green result and Cloudflare control
plane state are not substitutes. Rollback must remove only the narrow UI
Routes, never deploy an origin-forwarding Worker.

See [edge deployment decision](EDGE_FRONTEND_DEPLOYMENT.md).
