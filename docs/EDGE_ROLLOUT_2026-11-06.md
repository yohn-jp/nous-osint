# Edge bootstrap record — 2026-11-06

Status: **private passthrough Worker deployed; production Route/UI cutover BLOCKED**.
This is a partial Phase C operation, not acceptance of the full rollout.

- Source main: `87324e5fac6411842841c8cfc14937fc034e99c1`.
- Phase B PR #28 is merged; [main CI 42214498586](https://github.com/yohn-jp/nous-osint/actions/runs/42214498586) succeeded.
- Worker: `nous-frontend`, `PASSTHROUGH_ONLY=true`, actual Quasar build assets uploaded.
- Active version: `e49e3054-90a4-4655-92d5-f24c3c5c258b` (100%).
- Deployment: `d7216de1-4f4a-4749-9ce7-e29f93e82c05`, 2026-11-06 12:19:58 UTC.
- API verification: workers.dev disabled, version previews disabled, no Route targets for this Worker.
- No production request reaches this Worker yet; the canonical hostname still uses the existing Tunnel/VM UI.

## Execution

The installed Wrangler executable was in the npm cache rather than PATH.
Wrangler 4.158.0 had valid OAuth authentication; `cf auth whoami` alone had not
found those credentials. Existing user authentication was reused locally and was
not copied into GitHub Secrets or repository files.

The pinned cf tool built passthrough output. Its upload/deploy commands then
refused to replace an existing script-API bootstrap Worker because of their
strict conflict check. Initial placement used Wrangler with strict mode explicitly
disabled, after verifying that the target Worker had no public hosting or matching
production Route. A disposable configuration under `/tmp` was derived from the
canonical cf Build Output (bundle, assets and passthrough flag); no competing
Wrangler project configuration was added to the repository. Subsequent CI remains
owned by the existing cf version-release pipeline.

## Effective-state observations and gates

- Zone active; Worker Route list and Custom Domains did not match the canonical hostname.
- Existing `nous-osint` Tunnel healthy. Its canonical ingress remains
  `http://nous-mcp:8001`, Host `nous.yohn.jp`, Access required with the existing audience.
- Anonymous `/explore`, `/assets/nonexistent.js`, `/v1/items`, `/mcp`, `/reports/`
  returned 401 with no-store/private cache controls before placement.
- DNS API inspection returned HTTP 403. Access app listing did not identify the
  canonical application, so its effective policy and Managed OAuth settings were
  not established by this credential. These preflight gates remain **BLOCKED**.
- Authenticated browser/API/admin/Reports/MCP OAuth and streaming through a Route,
  desktop/mobile acceptance, Route rollback and edge-version recovery are **NOT_CHECKED**.
- GitHub's narrow CI deploy credential and protected release Environment remain
  required; local Wrangler OAuth is not a substitute for a least-privilege CI token.

Access policies, Managed OAuth, Tunnel settings, DNS, Terraform state and the VM
were not modified. No Route was attached and static UI serving was not activated.
Retain the current VM UI and do not start Phase D until all rollout/rollback gates pass.
