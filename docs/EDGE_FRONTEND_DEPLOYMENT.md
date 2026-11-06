# Nous OSINT — Edge UI delivery and release isolation

Status: **approved implementation plan; NOT IMPLEMENTED / NOT DEPLOYED**
Date: 2026-11-06
Authority: [ARCHITECTURE.md](ARCHITECTURE.md), [FRONTEND_EXECUTION_POLICY.md](FRONTEND_EXECUTION_POLICY.md), [REMOTE_MCP_ACCESS.md](REMOTE_MCP_ACCESS.md), [AUTOMATED_INTELLIGENCE_REPORTS.md](AUTOMATED_INTELLIGENCE_REPORTS.md), [CONTRIBUTING.md](../CONTRIBUTING.md).
Reviewed against main `abd6dbc81db57a627099cc51dd4b3396f8ca4a9a` and read-only Cloudflare account state on 2026-11-06. Implementation must re-read current HEAD and effective Cloudflare configuration.

## 1. Decision and completion target

Retain **one GitHub monorepo**, the **canonical Access-protected hostname `nous.yohn.jp`**, the existing **MCP Managed OAuth application**, the **Cloudflare Tunnel**, PostgreSQL, API, and VM Workers. Separate only the **Quasar 2 / Vue 3 browser SPA delivery** from the VM application image and place its immutable build on **Cloudflare Workers Static Assets**. GitHub Actions will build and deploy changes to `ui/**` without publishing or deploying a VM image.

Attach a **Worker Route** to the existing proxied Tunnel DNS hostname (`nous.yohn.jp/*`), not a Worker Custom Domain. The Route acts in front of the existing Tunnel origin. The Worker serves explicitly approved UI routes and build assets through the `ASSETS` binding and sends **all other existing dynamic requests unchanged to the original origin using same-host `fetch(request)`**. A Route's origin subrequest uses the underlying DNS origin, not another invocation of the same route. Do not introduce a second public hostname or a different CORS/API origin. Cloudflare Access must run before the Worker. Verify this *in the effective deployment*, rather than assuming the configuration alone proves it.

For this migration, **`/reports/*` stays on the VM**: the Astro article archive is regenerated from private SQL data by Report Worker and resides in the private site volume. A GitHub UI build cannot replace this release stream. Do not introduce R2, a public report bucket, additional API keys, report upload jobs, a new OAuth implementation, or database exposure in this scope.

**Done** means: a UI-only main commit publishes an Access-protected SPA release without any VM deployment, all existing API/admin/MCP/report behavior is preserved under one origin, and there is a tested rollback that works without rebuilding the VM.

## 2. Verified current topology and impact

| Item | Current evidence | Consequence |
| --- | --- | --- |
| DNS | Proxied CNAME `nous.yohn.jp` → existing `*.cfargotunnel.com`; active zone; no Worker Routes for this hostname | Keep DNS/Tunnel; attach a Route only after preflight |
| Access | Existing `Nous OSINT MCP` app, type `mcp`, Managed OAuth, single Allow policy, 24h session | Keep app, policy, issuer, audience, OAuth and DCR untouched |
| Tunnel | `nous-osint` healthy; `nous.yohn.jp` → `http://nous-mcp:8001`, Access `required=true`, default 404 | Same private origin remains authoritative for dynamic traffic |
| SPA | `ui/quasar.config.ts` history router; `ui/dist/spa`; same-origin `/v1/*` fetches with credentials | Preserve existing browser paths and API client; no CORS |
| Gateway | `src/nous/access_auth.py` verifies signed Access JWT and strict path/Host rules; `src/nous/remote_gateway.py` serves SPA, API, MCP, reports | Keep gateway JWT/authorization contract; move only UI static responsibility |
| Application image | `Containerfile` builds Quasar with Node and copies `/app/ui` into Python image | Remove only **after** edge cutover and rollback proof |
| CI | `.github/workflows/ci.yml` builds the application image from `Containerfile`, and report Worker separately, for main changes | Separate edge release from image builds by changed-path scope |
| Reports | `Containerfile.reports` builds Astro; Report Worker publishes immutable release to VM volume, MCP origin reads it | Continue `/reports/*` via Tunnel, even when the SPA is on edge |

The effective Cloudflare settings were **read only**. No Worker, DNS, Access, Tunnel or VM resources were changed by this planning document. CLI and Cloudflare resource permissions must be checked again before implementation.

## 3. Target request and trust boundaries

```text
browser / MCP client
    |
    | https://nous.yohn.jp (one host; existing Cloudflare Access + Managed OAuth)
    v
Cloudflare Access (existing allow policy, authentication and token)
    |
    v
Worker Route nous.yohn.jp/*   [edge-ui / Workers Static Assets]
    |                                    |
    | recognized SPA GET/HEAD            | all other methods/paths, preserved Request
    v                                    v
ASSETS: ui/dist/spa                    fetch(request), same host, origin subrequest
(no VM request)                           |
                                          v
                                  existing Cloudflare Tunnel
                                    Access JWT required
                                          |
                                          v
                                     nous-mcp:8001
                                    existing Python JWT check
                                          |
                 +------------------------+--------------------+
                 |                        |                    |
          /v1 read/admin                 /mcp               /reports/*
          FastAPI/SQL                    MCP                 private report volume
                 |                                           ^
          PostgreSQL                               Codex/Report Worker (VM)
```

Security contracts:
- Cloudflare Access authenticates **before** the Worker or its static assets. Keep the same signed assertion for every origin-bound API/MCP/report request; never generate, decode as trusted, or replace identity headers inside the edge router. The Python origin **continues verifying signature, issuer, audience, expiry, Host and method/path allowlists**, and admin endpoints retain their own role checks / dedicated DB credential.
- Forward the original `Request` for origin traffic so the method, body/stream, query, Host, cookies, `Authorization` (MCP), `Cf-Access-Jwt-Assertion`, redirects and response status/headers survive. Avoid buffering MCP streams and do not silently follow upstream redirects. Do not cache origin responses, access cookies, API/MCP payloads, or articles at the edge.
- **No unprotected alternative entry**: disable `workers.dev` and unprotected preview URLs, or explicitly put those endpoints behind Access before use. Never add an Access Bypass, a second public backend hostname, permissive CORS, or direct public VM IP/DNS.
- Do not make a Worker into an OAuth authorization server; the existing Access MCP/DCR endpoints remain in charge. Requests to `/.well-known/*` and edge/Access-managed `/cdn-cgi/*` must not receive an SPA fallback. Confirm actual Cloudflare handling on the existing Access `mcp` app before cutover.
- Keep application code and deployment secrets separate. Worker routing requires no DB password or persistent app bearer token. GitHub Actions receives only a narrowly scoped Cloudflare deploy token/account identifier via secrets.
- A successful static build is **not proof** of Access, Admin, OAuth or origin-JWT correctness.

## 4. Explicit routing contract

The edge implementation shall use the existing `_SPA_ROUTE` and `_is_unknown_ui_path` behavior as the compatibility authority for **current clean URLs only**. Do **not** implement legacy hash URL compatibility.

| Incoming request | Destination and required response |
| --- | --- |
| `GET/HEAD /`, `/index.html`, allowed SPA routes including `/explore`, `/items/{id}`, `/cves/{id}`, `/changes`, `/sources`, `/sources/new` and `/admin/*` UI pages | `ASSETS`, return `index.html` with 200; Vue Router renders the screen |
| `GET/HEAD /assets/<Quasar build asset>` | `ASSETS` only; existing file or real 404; never proxy or substitute `index.html` |
| Safe but unknown browser UI navigation (`/unrecognized`) | Keep HTTP **404**, optionally serve SPA's not-found document with 404; never return 200 or expose backend diagnostics |
| `/v1/*`, including read GET and admin POST/PUT/PATCH | Exact request forwarded to Tunnel; existing Access/JWT/method/role checks and original status preserved; non-GET never reaches SPA |
| `/mcp`, `/mcp/*` | Forward unchanged to Tunnel with streaming, OAuth challenge/headers and Accept negotiation intact |
| `/reports`, `/reports/*` (including `/_astro` assets under `/reports/`) | Forward unchanged; canonical 308, article, 404, HEAD and hashed-asset semantics owned by origin |
| `/.well-known/*`, `/cdn-cgi/*`, other non-UI or invalid paths (`/api/v1/*`, `/health`, encoded traversal, unknown methods) | Never serve SPA; preserve Access edge handling or send to existing origin's fail-closed 404 |
| Non-GET/HEAD to UI routes | Origin's deny response, never an asset response |
| Request with malformed encoding, ambiguous slashes, or path/query restrictions | Reject or transparently defer to stricter origin; do not broaden allowlist |

Use explicit URL path/method classification **before** `ASSETS.fetch` to prevent SPA-fallback or an asset collision from intercepting `/v1`, `/mcp`, `/reports` or Access discovery traffic. Configure the Workers asset binding and route so dynamic paths reach Worker logic first. Use **asset-only fast paths** for `/assets/*` once proven to remain Access protected. First implementation can use `run_worker_first` for all requests for simpler proof; before production optimize to exclude known immutable assets (for example `["/*", "!/assets/*"]` if supported by the selected CLI version). This avoids per-asset Worker invocations while keeping dynamic routing explicit. Do not assume an unchecked `single-page-application` fallback returns the correct status for unknown paths.

Caching: `index.html`, HTML 404, OAuth/MCP, API, admin, and reports: `Cache-Control: no-store`; hashed, identity-independent UI assets may use immutable caching **only after Access**. Respect existing CSP, content types and `X-Content-Type-Options: nosniff`. Recheck direct asset access without an Access session; it must remain denied.

## 5. Ownership and concrete implementation work

The existing `deploy/cloudflare/terraform/` tree remains canonical for **Cloudflare Access, DNS, Tunnel and zone Worker Route** resources. The new edge Worker **script + static artifact** is deployed from GitHub Actions using the Cloudflare CLI (`cf`) and a pinned CLI/package manifest. This repo currently has neither `wrangler.*` nor `cloudflare.config.ts`; create one `cloudflare.config.ts`-based edge project, rather than parallel competing deployment configurations. Avoid Terraform managing script content and CI managing the same route. Record the script/route ownership boundary and deploy token scopes. Check `cf` beta CLI support before relying on flags.

### Implementation PR A — edge router, offline tests, no production route

Owner: `edge/frontend/` (new), `ui/`, edge contract tests, Cloudflare project configuration.

1. Create `edge/frontend/` entrypoint with a small typed route dispatcher, dedicated `ASSETS` binding and a build/deploy definition pointing to the actual `ui/dist/spa` output. Add only needed package/lock files, minimal `cf` config and explicit asset ignores. Do not reimplement Vue, Access or API.
2. Route strict known UI GET/HEAD to `ASSETS` and unknown UI to HTTP 404. Pass dynamic traffic through same-host `fetch(request)` unchanged. Add a **passthrough-only** release flag (off by default) for safe initial activation.
3. Test the routing decision table with synthetic requests including `POST /v1/admin/report-runs`, GET/HEAD reports, unknown paths, encoded traversal, OAuth discovery, fake/static-asset names, MCP POST and streaming response/header propagation. Assert **no API response becomes `index.html`**. Test no client-originated identity header is trusted to authorize a request.
4. Build `ui` with pinned Node 24 / `npm ci`, check `vue-tsc`, emitted index/assets and edge bundle. Publish PR preview artifacts **privately**; do not create a publicly reachable `workers.dev` preview.
5. Supply a local/emulated edge-to-origin contract test; a live test behind Access remains a separate gate.

Acceptance A: route tests pass, Worker/static artifact builds deterministically, current production hostname/Access/VM unchanged.

### Implementation PR B — CI/CD isolation and infrastructure preparation

Owner: `.github/workflows/ci.yml` or a separate small `.github/workflows/frontend-deploy.yml`, `Containerfile`, `deploy/cloudflare/terraform/`.

1. Add a path classifier for changed files and choose independent actions:
   - `ui/**`, `edge/frontend/**`, shared UI build config -> frontend typecheck/build and **edge asset deploy** only.
   - `src/**`, `migrations/**`, `sources/**`, `Containerfile`, relevant Python/runtime config -> backend test/image build and GHCR publish as appropriate.
   - `reports/site/**`, `reports/schemas/**`, `reports/templates/**`, `Containerfile.reports` or report pipeline changes -> report tests/image build; do not auto-upload dynamically generated private articles.
   - `docs/**`/README only -> optional docs checks, **no container build or production rollout**.
   Correctly handle mixed commits, base/merge commits, first-push events and shared dependency paths; avoid "only frontend changed" heuristics that skip required tests.
2. In main, publish UI assets **only after frontend checks** and route tests; guard release with a single GitHub Environment, required permissions, concurrency to prevent an older workflow from overwriting a newer release, and immutable commit-SHA provenance. A workflow deploying an old commit must not supersede newer main HEAD. No manual VM step for UI-only edits.
3. Provide short-lived or least-privilege `CLOUDFLARE_API_TOKEN` (Workers Scripts Write for the intended account/zone as required), `CLOUDFLARE_ACCOUNT_ID` and expected zone context via Actions secrets/environment; do not log token, JWT or origin headers. Access/Tunnel resources are not mutated by a UI deploy job.
4. Codify the `nous.yohn.jp/*` zone Worker **Route** using the existing Terraform state, with DNS preserved and Access/Tunnel unchanged. For a first activation use passthrough mode. Script and route must have **distinct owners**: CI deploys script/assets, Terraform owns the Route. Assert there is no existing conflicting Worker Route or Custom Domain before applying.
5. While rollout is unproven, **keep the old `/app/ui` files in the API/MCP image** for instant origin fallback. Separate the normal Quasar rebuild from the backend-image dependency after script cutover; do not remove the fallback in the first change.

Acceptance B: a UI-only commit does not start GHCR image build and publishes only the edge version; backend-only commit does not republish Quasar; main deployment is serialized and traceable; no unauthorized public preview.

### Implementation rollout C — Access-preserving switch and rollback rehearsal

1. **Preflight** (record evidence): effective main commit, Access application type/UID/audience/allow policy/Managed OAuth, Tunnel Access `required=true`, proxied CNAME, current Worker Route absence, current local and external response/headers; confirm `/explore`, admin session, `/mcp` handshake, report index/article and 404 behavior.
2. Deploy and test the Worker in **passthrough mode** (no UI responses from edge). Apply zone Route on the existing hostname using Terraform, with no DNS/Access edits. Observe same-host origin subrequests, JWT, request method/Host, original status, streaming, OAuth 401 challenge/discovery, report routes, admin authorization and no redirect loops. On any regression remove Route immediately.
3. Enable edge static delivery for allowlisted UI routes as one versioned release. Verify logged-in and unlogged-in paths (including hashed assets), direct History URL refresh, keyboard/mobile UX, admin 403 vs 200 for authorized roles, API query+admin mutation with test-safe fixture, real MCP initialize/tools/list over existing Managed OAuth, HTML report/list/404 links and non-GET denial.
4. Inspect Worker request count/errors, latency, Tunnel origin requests (static should fall, `/mcp`/`/v1`/`/reports` should still reach VM), and negative caching/CSP. Ensure same-domain cookies remain intact and no response is accidentally public cacheable.
5. **Rollback drill**: set passthrough mode and, if needed, remove just the Worker Route using Terraform. Confirm the retained `/app/ui` build on the same hostname works and that MCP/admin/reports still pass. Keep known-good Worker deployment and last-good origin digest recorded; no DNS manipulation or DB migration is required.

Acceptance C: measured UI-only main deployment + unchanged authenticated dynamic behavior + verified rollback. If any protocol or JWT/header behavior differs under the existing Access `mcp` application, **stop and retain the original Tunnel-only topology**. No bypass or second hostname workaround.

### Implementation PR D — remove UI build dependency after stable cutover

Only after C has passed and an edge-release rollback mechanism can serve a known-good UI:

1. Remove the Quasar build stage and `COPY --from=ui-build ... /app/ui` from `Containerfile`; update `src/nous/remote_gateway.py` to preserve original routing/deny semantics without depending on missing SPA artifacts. Keep the unchanged `/v1`, `/mcp`, `/reports` Access security.
2. Adjust backend image CI so `ui/**` cannot cause a backend rebuild. The report Worker image/CI remains independent. Validate OCI image content and runtime behavior on a disposable environment, then deploy backend separately by pinned GHCR digest.
3. Revise `docs/FRONTEND_EXECUTION_POLICY.md`, `docs/REMOTE_MCP_ACCESS.md`, `docs/ARCHITECTURE.md`, `docs/QUADLET_DEPLOYMENT.md` and current Terraform comments to mark the **observed** new state; retain existing backup and release contracts.

Acceptance D: no UI Node build or bundled SPA in API/MCP image; an edge deploy is sufficient for UI changes; documented recovery can restore a known-good edge release **without** requiring old origin UI files.

## 6. Acceptance matrix (execute, do not infer from CI)

| Case | Required observation |
| --- | --- |
| Anonymous `/explore`, `/assets/*.js`, `/reports/`, `/v1/items`, `/mcp` | Access denies or redirects per existing protocol; asset is not anonymously readable |
| Authenticated `/` / `/explore` / `/items/1` / `/cves/CVE-...` / `/sources` / `/changes` / `/admin/reports` | Correct UI, reload/deep link works, no cross-origin requests |
| Missing safe UI route and forbidden `/api/v1/*`, `/health` | HTTP 404; not silently 200 HTML or JSON cache |
| `/v1/items` search/pagination; `/v1/admin/session` and privileged POST | Original data/status, 200 for allowed admin, 403 for other identity; no role bypass or API HTML substitution |
| `/mcp` OAuth/PKCE/DCR challenge and Streamable HTTP | Existing Cloudflare Access challenge and authenticated initialize/tools/list; no stream buffering, redirect rewriting or lost Authorization |
| `/reports`, `/reports/`, article, `/reports/_astro/*`, unknown report | Existing 308/200/200/200/404 behavior and same-origin return to dashboard; no publication breakage |
| `ui/**` only main commit | Edge deploy succeeds; **no backend/report image publish; no SSH/VM change** |
| `src/**` or report pipeline only | Required backend/report build, no unnecessary UI publish |
| Rollback | Single config/Route removal restores healthy UI and all origin routes while origin fallback is present; later edge version rollback proven |
| Offline/error conditions | No cached admin/API response, no public `workers.dev`/preview, Access/JWT failures fail closed, no secrets in logs |

Required evidence: commit SHA, workflow run IDs, edge deployment version, Terraform plan/apply result, response status/headers for every test category, browser screenshots for desktop/mobile, MCP protocol client run, Cloudflare Access status, Worker errors/request rate, Tunnel status, and actual rollback result. Mark missing items `NOT_CHECKED`. Do not claim successful VM/production deployment from passing static tests alone.

## 7. Rollout economics and operations

Cloudflare Workers Static Assets requests served directly as assets are currently free and do not incur storage charges. **Worker script invocations do consume quota and may be billed or 429 on Free**, especially `run_worker_first=true`; use selective negative asset patterns after validation and monitor usage. This architecture targets operation within the account's available free limits, **not a guarantee of zero cost**. Existing VM, Tunnel and Codex costs are unchanged. Limit user-provided analytics and preserve noindex/private handling.

Oncall procedure: identify bad edge deployment by commit/version → revert to known-good edge release; if the edge router itself fails, remove the Route so the same hostname falls back to the existing protected Tunnel origin (until PR D). Re-run authentication and MCP smoke before declaring recovery. Keep Access policies untouched during incident rollback.

Do **not** relocate generated articles merely because Astro produces static HTML: those articles are private, SQL-backed, versioned runtime artifacts. A later optional R2 release pipeline requires its own encrypted/private storage, immutable manifests, atomic pointer, Access checks and rollback proof, with no public bucket or Git commit of private outputs.

## 8. Primary product references

- [Workers Routes: Worker in front of DNS origin and same-host `fetch`](https://developers.cloudflare.com/workers/configuration/routing/routes/)
- [Workers Static Assets configuration and script bindings](https://developers.cloudflare.com/workers/static-assets/)
- [SPA routing and `run_worker_first`](https://developers.cloudflare.com/workers/static-assets/routing/single-page-application/)
- [Access protection of Workers](https://developers.cloudflare.com/workers/configuration/cloudflare-access/)
- [Access JWT verification](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Tunnel `originRequest.access.required`](https://developers.cloudflare.com/tunnel/reference/origin-parameters/)
- [Static Assets billing and limitations](https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/)
- [Cloudflare CLI (`cf`), build and deploy](https://developers.cloudflare.com/cf/)
