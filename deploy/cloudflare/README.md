# Cloudflare Access + Tunnel staging

Canonical public endpoint: **https://nous.yohn.jp/mcp**.

The Cloudflare resource changes remain unapplied. The VM-side MCP origin and Tunnel connector are now installed from merged `main`; see [the VM deployment record](../../docs/QUADLET_DEPLOYMENT.md#6-initial-vm-deployment-record-2026-11-03).

## Implementation status

- Implemented in the repository and VM: strict allowlisted Access/Managed OAuth IaC, standalone Python read-only MCP adapter and Access JWT verifier; pinned MCP/Tunnel Quadlets, dedicated ingress network and SELECT-only MCP database credential.
- Not performed: Cloudflare Terraform import/init/plan/apply, Access app/IdP/OAuth policy inspection, or live ChatGPT OAuth verification.
- Reuse: Majiwari's Access application/Managed OAuth policy and Proprium's Tunnel/Gateway transport model. Do not copy their credentials or reuse their Tunnel routes.
- No Worker, Workers VPC Service, KV, D1 or custom OAuth service.

## After PR #1 is merged

1. Rebase this branch onto the merged main and inspect the real pyproject, API query layer, Quadlet network and Containerfile. Resolve conflicts without overwriting the working foundation.
2. The stacked branch now pins **mcp==2.3.0** and **cryptography==46.0.3** in the canonical Python project; rebuild the image, run the auth and end-to-end MCP transport tests before deploying.
3. Give the MCP process a dedicated **SELECT-only** PostgreSQL credential. Change the staged nous-mcp.container.example secret from the temporary API credential to the new read-only secret. There must be no ingestion or migration permissions.
4. Verify rootless Podman network DNS and separate nous-ingress network. The cloudflared container joins only ingress; nous-mcp joins ingress and backend. PostgreSQL stays internal. Set Cloudflare tunnel origin to http://nous-mcp:8001 with Host nous.yohn.jp.
5. Pin the actual built app image and a reviewed cloudflared image **by digest**, provision a VM-side Podman Tunnel token secret and provide a root-owned or user-owned non-Git config file for CF_ACCESS_ISSUER / CF_ACCESS_AUDIENCE. Rename example Quadlet files only when runnable.
6. Observe ChatGPT's real OAuth callback URI; configure the exact allowlisted URI and IdP. Do not use an Everyone fallback. Retrieve the new Tunnel token through the Cloudflare UI or API, and never put the token in CLI arguments, plaintext logs or Terraform outputs.
7. Set an encrypted Terraform state backend; then use terraform init, terraform fmt -check, terraform validate, terraform plan and human review of the plan. Ensure no Majiwari/Proprium resources are touched, and import rather than overwrite an existing DNS record if it exists. Apply only after local MCP and Access policy checks pass.
8. Complete Cloudflare Access login, OAuth authorization code + PKCE, MCP initialize, tools/list, tools/call and denial tests using a real MCP client and ChatGPT if supported. Verify no other paths are publicly accessible, no sensitive tokens in logs, and that the Tunnel recovers after restart.

## VM-local environment example (not credentials)

CF_ACCESS_ISSUER=https://YOUR-TEAM.cloudflareaccess.com
CF_ACCESS_AUDIENCE=REPLACE_WITH_ACCESS_AUDIENCE

Store it as ~/.config/nous/mcp.env on the VM with restrictive permissions; NEVER commit a populated version.

## Terraform inputs

Copy terraform/terraform.tfvars.example to terraform/terraform.tfvars and replace the placeholder values. This example is intentionally invalid for production. Account/zone IDs and an actual client redirect URI must be confirmed. Restrict API token to Access, Tunnel and DNS privileges; no Workers permissions needed.

## Security gates

- No unauthenticated or different-audience MCP requests can succeed at the private origin.
- /v1/, /health/, /docs, /admin, /openapi.json and every path other than /mcp remain 404 at the standalone ASGI ingress, even after Access authentication.
- No alternate ingress without Access. Cloudflared optionally validates JWT using the Tunnel origin_request.access rule; Nous independently validates JWT signature, issuer, audience, expiry, not-before and subject.
- Credentials and runtime data must not enter the public repository. Disable just the Tunnel when rolling back, leaving the collector running.

Sources: Cloudflare Access Managed OAuth https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/ ;
Cloudflare Tunnel token-file https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/run-parameters/ ;
MCP Python SDK ASGI https://py.sdk.modelcontextprotocol.io/run/asgi/ .

**Cloudflare account unchanged.** The VM-side runtime is deployed and reboot-tested; its current loaded Tunnel route is recorded in [QUADLET_DEPLOYMENT.md](../../docs/QUADLET_DEPLOYMENT.md#6-initial-vm-deployment-record-2026-11-03).
