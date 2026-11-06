# Nous OSINT — UI static delivery separated from Tunnel traffic

Status: **revised architecture decision; production cutover NOT VERIFIED**
Updated: 2026-11-06
Authority: [ARCHITECTURE.md](ARCHITECTURE.md), [FRONTEND_EXECUTION_POLICY.md](FRONTEND_EXECUTION_POLICY.md), [REMOTE_MCP_ACCESS.md](REMOTE_MCP_ACCESS.md).

## Decision

Keep the canonical Access-protected hostname `nous.yohn.jp`, Cloudflare Tunnel, MCP Managed OAuth, API, runtime-generated reports, and the VM unchanged. Deploy only the prebuilt Quasar SPA's static files to Cloudflare Workers Static Assets. **Do not put API, MCP, or reports through a Worker script or implement an edge reverse proxy.** The purpose is independent UI deployment and static delivery, not an additional application gateway.

The previous design, which attached `nous.yohn.jp/*` to a Worker and forwarded non-UI requests using `fetch(request)`, is **rejected**. It intercepted all requests and added an unnecessary Worker hop to Tunnel-bound traffic.

## Target request paths

```text
Browser / MCP client
  |
  v
Cloudflare Access (existing app and authentication)
  |
  +-- explicit UI/static route(s) --> Workers Static Assets (Quasar build)
  |
  +-- all other routes -----------> existing Cloudflare Tunnel
                                      |
                                      v
                                   nous-mcp:8001 (VM)
                                      +-- /v1/* (API and admin)
                                      +-- /mcp and OAuth/discovery
                                      +-- /reports/* (private generated articles)
```

**Important:** This is a logical target, not a claim that Cloudflare automatically selects the two branches. Route precedence, exact path matching, Access execution order, and the existing Access application type must be proven with the actual account configuration. No Worker Route covering `nous.yohn.jp/*` is permitted in the target design.

## Routing contract

| Request | Owner |
| --- | --- |
| `GET/HEAD /`, `/index.html`, explicit SPA page paths (`/explore`, `/items/{id}`, `/cves/{id}`, `/changes`, `/sources`, `/sources/new`, `/admin/*`) | Cloudflare static UI delivery, **only** where a supported path-specific route can be verified |
| `GET/HEAD /assets/*` and other enumerated immutable Quasar assets | Cloudflare static assets; real missing assets return 404 |
| `/v1/*`, including admin mutations | Existing Tunnel → VM, **never** Worker |
| `/mcp`, `/mcp/*`, OAuth/discovery endpoints including `/.well-known/*` | Existing Access/Tunnel flow, **never** Worker |
| `/reports`, `/reports/*` | Existing Tunnel → VM, **never** Worker |
| Unknown paths, invalid encodings, non-UI methods | Existing fail-closed origin behavior; never SPA fallback |

A root path, a dynamic SPA URL and a prefix wildcard are not interchangeable. **Do not assume that Cloudflare Worker Routes can express arbitrary exclusions or that path patterns cover only intended UI URLs.** For example, a broad `/admin*` route may intercept paths other than UI pages; an `/items/*` route needs an explicit method/asset behavior review. Verify route syntax, precedence and available static-asset fallback behavior before creating any production route.

If the current Cloudflare routing primitives cannot satisfy all of these constraints on the same hostname, **stop before cutover**. Do not silently revert to a catch-all Worker proxy, expose a second public origin, or alter the MCP OAuth boundary. Record the incompatibility and request an explicit architecture decision.

## Security invariants

- Keep the existing Access application, Managed OAuth, Tunnel and origin JWT validation. Preserve issuer/audience/subject, headers, cookies, method checks and admin role checks.
- Static UI files must be denied to unauthenticated clients. `workers.dev` and preview endpoints must remain disabled or equivalently Access-protected.
- No public VM address, bypass policy, permissive CORS, new API hostname, or credentials in browser assets.
- API/MCP/report traffic is not routed through the Worker, is not cached as static content and retains streaming, redirects and response semantics.
- Report HTML remains a VM runtime artifact; GitHub UI builds must not replace or publish it.

## Implementation and rollout

1. **Inspect actual main and Cloudflare state.** Confirm existing Worker scripts/routes, DNS, Tunnel, Access, OAuth and SPA paths. Read the current Terraform and edge deployment configuration before changing anything.
2. **Implement or adjust path-specific static routes only.** Terraform remains authoritative for zone routes; the frontend release pipeline owns the Worker static asset bundle. Remove any catch-all Worker Route from the desired configuration. No dynamic passthrough handler is required or allowed.
3. **Test routing without production cutover.** Prove that UI paths and hashed assets resolve to static files; that `/v1/*`, `/mcp`, discovery and `/reports/*` continue directly to Tunnel; and that unknown/unsafe paths fail closed. Validate GET, HEAD, POST, streaming, OAuth challenge, 404 and Access-denied behavior.
4. **Separate CI/CD.** A UI-only commit builds/tests/deploys Quasar assets without rebuilding the VM/backend or report images. Backend and report changes retain their own independent workflows. Do not remove the origin's fallback UI before rollback is verified.
5. **Cut over only after the route contract is demonstrably satisfiable.** Record route patterns, Terraform plan/apply, commit SHA, workflow run, asset deployment version, HTTP status/headers, authenticated browser tests and MCP client tests. Missing evidence is `NOT_CHECKED`.
6. **Rollback.** Remove only the static UI route(s) to return UI traffic to the existing Tunnel origin while its UI fallback is retained. Recheck API, MCP, Access and reports. Once a separate edge rollback is proven, remove the bundled Quasar build from the VM image in a separate change.

## Acceptance

- Static UI delivered by Cloudflare with existing Access protection and no VM deployment for UI-only commits.
- API/admin, MCP/OAuth/discovery and reports reach Tunnel **without a Worker script invocation or Worker proxy**; confirm with effective routing configuration and telemetry, not just HTTP 200.
- No new public entry point; no changes to existing JWT/role boundaries.
- A verified rollback restores the prior Tunnel-hosted UI and preserves all dynamic services.
- If path-specific same-host routing cannot be validated, deployment remains blocked rather than introducing a catch-all proxy.

## Current state

The repository previously documented a catch-all Worker Route and same-host origin forwarding. This document supersedes that **design**. It does not claim that existing implementation, Terraform, deployed Worker or production routing has already been migrated. Production remains **NOT_VERIFIED** until inspected and tested.
