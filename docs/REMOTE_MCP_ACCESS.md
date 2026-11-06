# Remote MCP ingress — Cloudflare Tunnel + Access Managed OAuth

**Status:** VM-side MCP origin and Tunnel connector deployed on 2026-11-03. The running Tunnel reports the expected hostname, origin, Access-required flag, team and audience. On 2026-11-06 a private static UI Worker and ten narrow UI-only Routes were deployed without changing the MCP origin/Tunnel architecture. GitHub login and end-to-end OAuth remain unverified.
**Canonical hostname:** `nous.yohn.jp`  
**Target URL:** `https://nous.yohn.jp/mcp`  
**Target host:** single VM, reachable for implementation as `ssh nous.osint.vm`  
**Implementation sequencing:** VM deployment uses the merged foundation; Cloudflare control-plane work remains separate.
**Last updated:** 2026-11-07

This document adds a subsequent remote-access phase. It **does not** change the acceptance criteria for Phase 1–3 in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md), and must not trigger unrelated changes to work currently in progress.

## 1. Decision

Use **Cloudflare Tunnel + Cloudflare Access Managed OAuth** with a **VM-hosted, read-only Streamable HTTP MCP endpoint**.

- **Do not implement OAuth termination, a reverse proxy or MCP-specific forwarding in a Cloudflare Worker.** Explicit UI/static Worker Routes may serve Quasar assets, but all MCP/Access/API/report paths must bypass Worker and continue directly through the protected Tunnel. See [EDGE_FRONTEND_DEPLOYMENT.md](EDGE_FRONTEND_DEPLOYMENT.md).
- **Do not create a Workers VPC Service**, Workers KV, Durable Objects, D1, a custom authorization server, or a separate SaaS MCP gateway.
- **Do not expose the database, scheduler, worker, admin API, or an unauthenticated fallback hostname.**
- One canonical public host: `nous.yohn.jp`. Avoid alternate names such as `mcp.osint.yohn.jp`, `osint.yohn.jp` and `nous-osint.yohn.jp` unless a later migration explicitly authorizes them.
- **MCP and the read-only UI share one Access-protected hostname.** The UI lives at `/`; its same-origin read API is a strict GET allowlist under `/v1`. `/api/v1/` remains closed.

Reason: Cloudflare Access Managed OAuth supports non-browser OAuth clients for Access-protected self-hosted applications. Tunnel publishes a private VM origin to the Cloudflare edge with outbound-only connectivity. The host application already has the search/data service layer; a Worker would add deployment and charging surfaces without providing a required function.

Cloudflare Access is the authentication and identity policy boundary; the VM validates the Access-signed assertion as defense in depth and enforces tool-level permissions. Tunnel alone is **not** authentication.

## 2. Requested runtime topology

```text
ChatGPT / compatible MCP client
        |
        | HTTPS, OAuth 2.0 authorization-code + PKCE
        v
https://nous.yohn.jp/mcp
        |
        v
Cloudflare Access application (Managed OAuth, strict allow policy)
        |
        | successful authentication => Access-signed JWT assertion
        v
Cloudflare Tunnel public hostname route (no origin inbound ports)
        |
        v
cloudflared (rootless Podman Quadlet on the VM)
        |
        | restricted ingress network / application origin
        v
Nous FastAPI application + Streamable HTTP MCP adapter
        | JWT verification / read-only tool allowlist
        v
existing search/query service -> PostgreSQL
```

The scheduler and worker never accept incoming traffic. No public PostgreSQL port. The VM should not need inbound internet firewall openings.

### Network boundary

- Add `nous-tunnel.container` using a pinned `cloudflared` image digest and a VM-local secret/token. Do not assume `127.0.0.1` inside a container references the host's loopback.
- Prefer a **separate rootless Podman ingress network** shared only by `cloudflared` and the MCP-serving app; keep PostgreSQL on the pre-existing backend network, which `cloudflared` must not join. Connect the API process to both networks only if required. Inspect actual Quadlet service/network names before writing files; do not replace working deployments blindly.
- On the Tunnel, map the single public hostname to the combined MCP/UI origin. The origin admits `/mcp`, static UI files, report HTML, an explicit read-only `/v1` allowlist, and the dedicated `/v1/admin/*` and `/admin/*` administration flows added in PR #8/#13. Administrative data/actions require verified Access identity, an explicit administrator subject allowlist, same-origin write controls and a separate limited SQL role. It returns `404` for `/api/v1`, diagnostics and every other unapproved path even after authentication.
- Cloudflare Access covers the **whole public hostname**. All reachable paths, including error pages, inherit the Access policy; no broad Bypass policy. Health probes use local/VM-only addresses.
- No direct public DNS A/AAAA to the VM and no secondary unprotected public hostname. The catch-all Worker Route discovered on 2026-11-06 was removed; verify effective routes again before each rollout. The planned static-only edge Worker must keep `workers.dev` and preview routes disabled. Only narrow UI/static routes may be attached on the same hostname; no catch-all Worker Route is permitted. See [EDGE_FRONTEND_DEPLOYMENT.md](EDGE_FRONTEND_DEPLOYMENT.md).

## 3. Identity and OAuth boundary

Configure a Cloudflare Zero Trust Access application for `nous.yohn.jp` with **Managed OAuth enabled**. Prefer the established `mcp` Access application pattern from Majiwari if the current provider/dashboard supports it; verify the exact type and OAuth settings against the Cloudflare API at implementation time. Use a trusted IdP already configured in the account.

1. An MCP client requests `https://nous.yohn.jp/mcp`.
2. Access responds to unauthenticated OAuth-capable clients with `401` and `WWW-Authenticate` discovery metadata, rather than requiring an MCP-specific application OAuth implementation.
3. The client performs OAuth authorization-code with PKCE S256, including authorization-server discovery, client registration where required, Access login, and token exchange.
4. Access enforces an **explicit named-user email allowlist**; no `Everyone` fallback, no empty-allowlist-to-everyone behavior, no public identity provider bypass. DCR `redirect_uri` restrictions must match the **observed** client callback URI (ChatGPT's current URI is not to be guessed).
5. Authenticated requests reach the origin carrying `Cf-Access-Jwt-Assertion`. **The OAuth bearer token seen by the MCP client and the Access JWT seen by the origin are different credentials.**
6. Origin verifies the signed JWT on every MCP request. It trusts **neither** a bare `Cf-Access-Jwt-Assertion` string nor an unauthenticated `Authorization` header.

Suggested initial values (subject to actual IdP and client compatibility): access token lifetime 1 hour; session duration 24 hours; DCR enabled with narrow redirect-URI allowlist. A stored allowlist of zero allowed users is a configuration **error**. Deploy-time policy checks must reject `everyone`, bypass, missing IdP restriction (where required by the selected account), or unintended wildcard redirect URI rules.

### Access assertion verification

Reuse the *contract* of `majiwari/deployments/cloudflare/worker/src/access.ts`, but implement it in the existing Nous Python stack; do not import a TypeScript Worker just for this.

Validate:
- RS256 signature from the team's Access JWKS (`https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`), honoring `kid` and key rotation;
- exact expected `iss` and application `aud`, along with `exp`, `nbf` (when present), and non-empty `sub`;
- mapping of a stable Access subject to request audit context, with email only when the IdP actually supplies it;
- absence, bad signature, wrong audience, expiry, invalid payload, or missing required claims fail **closed**;
- JWKS caching with bounded TTL and safe rotation behavior; a remote key-fetch failure must not become authentication bypass;
- ingress strips/does not trust arbitrary forwarded identity headers from untrusted callers. A process able to access the private origin is within the local VM trust boundary, not magically authenticated by Tunnel.

Cloudflare Access authorizes *who* can connect; the origin authorizes *which operations* are available, independently of authentication.

## 4. MCP server contract

**Protocol:** MCP Streamable HTTP; one endpoint `/mcp`. Do not introduce legacy SSE-only transport or a protocol-specific gateway when the FastAPI MCP adapter can reuse existing application services.

MCP tools initially exposed (read-only):
- `search_intelligence`: existing indexed item search with bounded filters/pagination, type, source, date, query.
- `get_item`: item details, publisher URL and provenance; do not return unauthorized copied full text.
- `get_changes`: new/changed items within a bounded time window.
- `get_source_status`: collection freshness and source errors, excluding credentials and internal network/host secrets.

`get_entity_context` is **conditional** on a real entity-linking implementation; do not ship a mocked tool. All MCP tools call canonical query/service-layer code; no parallel SQL implementation or secondary datastore. Set hard limits on returned records, response bytes, time windows, query complexity, per-user request concurrency and call duration.

**Explicitly forbidden initially:** `add_source`, `run_job`, `delete_item`, shell access, arbitrary URL fetch, database writes, backdoor admin operations and any path granting access to the collector's network capabilities. Request fields from the MCP client are data, never interpreted as instructions for OS operations.

Prefer stateless MCP HTTP requests to long-lived sessions. Verify `POST`, required `GET`/stream and `DELETE` behavior as applicable to the selected MCP SDK; ensure `Accept` and `Mcp-Session-Id` handling is standards-compliant. Disable CDN caching for `/mcp`, preserve relevant headers and streaming behavior, and make authenticated error handling unambiguous.

## 5. Cloudflare and repo configuration

Prefer IaC (Terraform) for the Access application, allow policy, public hostname route and DNS. Keep account-specific IDs, team domain, audience tag and tunnel ID in a **noncommitted deployment profile/state**; secrets live in appropriate VM/Cloudflare secret stores, not Git. A public repository must not contain Access tokens, Tunnel tokens/JSON credentials, IdP credentials, TF state, backup archives or user-specific information.

Integration references (read and adapt, **not copy an entire deployment stack**):
- [Majiwari Access Terraform](https://github.com/yohn-jp/majiwari/blob/main/deployments/cloudflare/terraform/access.tf): Access MCP application, explicit allow policies, Managed OAuth, DCR.
- [Majiwari Managed OAuth contract](https://github.com/yohn-jp/majiwari/blob/main/deployments/cloudflare/docs/OAUTH.md): JWT boundary and client handshake.
- [Proprium MCP Gateway](https://github.com/yohn-jp/proprium/blob/main/docs/architecture/MCP-GATEWAY.md): Access-managed MCP ingress and transport.
- [Proprium Cloudflare Tunnel operations](https://github.com/yohn-jp/proprium/blob/main/docs/deployment/GATEWAY.md): loopback-only gateway, pinned cloudflared and non-root lifecycle.
- [Cloudflare Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/), [Cloudflare MCP access](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/secure-mcp-servers/), [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/).

Remove from the Majiwari pattern: Worker proxy, Workers VPC Service binding, Worker JWT verification and Worker deployment. Retain its verified **policy requirements**. Do not reuse any Majiwari or Proprium credentials, Tunnel IDs or DNS routes.

Proposed IaC and service locations to reconcile with the merged base implementation:
```text
deploy/cloudflare/terraform/      # new Access + Tunnel route + DNS declarations
deploy/cloudflare/README.md       # account bootstrap and rollback runbook
deploy/quadlet/nous-tunnel.container
src/...                            # existing API/MCP integration, not a second application framework
```

Cloudflared's token-file mechanism, Podman secret delivery, container command and user-service dependencies must be verified for the pinned image and installed Podman version; examples are not proof of deployability.

## 6. One canonical host: route contract

| Public path | Current target state | Trust requirement |
| --- | --- | --- |
| `https://nous.yohn.jp/mcp` | MCP | Access Managed OAuth + valid Access JWT + read-only tools |
| `https://nous.yohn.jp/` | Static UI | Narrow Cloudflare UI Routes; VM image-baked fallback retained. Access E2E still unverified |
| `https://nous.yohn.jp/v1/*` | UI read API | Access JWT required; allowlisted GET routes proxy to the private API |
| `https://nous.yohn.jp/admin/sources`, `/admin/reports` | Admin SPA routes | Access JWT required; backend authorizes each admin request by subject |
| `https://nous.yohn.jp/v1/admin/*` | Source/report administration | Strict route/method allowlist + Access JWT + admin subject allowlist + same-origin write controls + limited admin SQL role |
| `https://nous.yohn.jp/reports/*` | Static report HTML/assets | Access JWT required; restrictive report-path allowlist and CSP; no unapproved dynamic execution |
| `https://nous.yohn.jp/api/v1/` | Closed | 404 at origin; internal API remains private |
| `/health/*`, `/admin/*`, `/metrics`, `/docs`, `/openapi.json` | **Not public** | return 404/403; health is VM-local |

A shared hostname is **not** permission to expose every FastAPI route. If a future UI/API needs different authorization than the MCP app, define and verify separate Access path-scoped applications or a strict per-route origin policy before changing the public route contract. No second public hostname should be added merely to sidestep the authorization decision.

## 7. Remaining Cloudflare control-plane work

The VM origin and Tunnel were previously deployed and reboot-tested. Cloudflare now has ten narrow UI Routes and a private Worker version, but authenticated OAuth/browser acceptance has not been demonstrated. Remaining control-plane tasks:

1. Import the existing account, zone, Access policy/application, Tunnel, DNS record and Tunnel configuration into Terraform state. Inspect provider import identifiers and ensure the plan contains only Nous changes.
2. Verify the existing Access app and policy enforce only the approved GitHub IdP and named email; verify Managed OAuth is on and no Everyone/Bypass rule exists.
3. Keep DCR disabled until a real MCP client's callback URI is observed; then allow only that exact HTTPS callback.
4. Perform real GitHub authorization, denial for another user, MCP `initialize`, `tools/list` and read-only `tools/call` through an actual client. Include ChatGPT if the account UI supports it.
5. Record the reviewed Terraform plan/apply and live OAuth evidence. Do not change Majiwari or Proprium resources.

If Cloudflare Managed OAuth + the target MCP client is incompatible in practice, **do not silently add a Worker or open the endpoint**. Record the failing protocol exchange (without secrets) and present the minimal alternative as a separate, reviewed architecture decision.

## 8. Acceptance and security tests

The feature is **not complete** until actual VM + Cloudflare evidence demonstrates:

1. Unknown callers and disallowed identities cannot enumerate or call tools; authentication failure is distinguishable from MCP/HTTP routing failure.
2. Valid Access identity using OAuth authorization code + PKCE can complete initialization, `tools/list` and `tools/call` from a real MCP client and (where account UI permits) ChatGPT.
3. Origin rejects missing/forged/expired/incorrect-audience Access assertions **even if** locally reached without the edge, and accepts valid assertions from the correct audience.
4. Tunnel route exposes only `nous.yohn.jp`; no public VM port, no unprotected alternate host, no public database, admin or internal API access.
5. `/mcp` is uncached, request/response body sizes and pagination are bounded; streaming and MCP error handling are validated against the chosen SDK.
6. Containers run rootless. `cloudflared` cannot connect to the database backend network; Quadlet units start and recover after process restart.
7. Credentials, token values, user data and third-party full text do not appear in repository or diagnostic logs.
8. Search/change/item results retain accurate source attribution and expose no write/shell/remote-fetch capability.
9. Tunnel/Access/identity logs correlate with origin request IDs without logging bearer tokens; failure and recovery paths are tested.
10. A rollback can disable **only this** public ingress while leaving the internal collector, API and PostgreSQL working.

**Initial MCP phase non-goals:** Admin UI and report generation were not part of the initial MCP delivery, but were subsequently implemented behind independent origin-side authorization in PR #8 and #13. Still out of scope: Cloudflare Worker forwarding/terminating MCP or APIs, MCP Portal, duplicate persistence, unreviewed collector changes, or bypassing the existing Access boundary.

## 9. Cost model

The initial MCP architecture requires no Worker. The current static-UI-only Worker may invoke code on navigation/misses, but real static asset hits bypass the script; API/MCP/report requests must never consume Worker invocations. Monitor current account usage and billing after cutover. Cloudflare Tunnel can publish the origin without opening inbound VM ports; Cloudflare Access is subject to current account plan, seat and policy limits. Record the applicable account entitlement during deployment, not an unconditional claim of permanently free unlimited traffic.

## CVE/KEV correlation

`get_cve(cve_id)` is a read-only MCP tool backed by the canonical `GET /v1/cves/{cve_id}` read model. It correlates the exact CVE ID with independent source records. Only current entries in the official CISA `cisa-kev` catalog are marked `listed`; absence without a recent complete snapshot is `unknown`. The tool initiates no outside HTTP requests and makes no changes to the source registry. See [CVE/KEV correlation](CVE_KEV_CORRELATION.md).
