# Edge release isolation — Phase B

Phase A is merged at `480ad07ea3bfc1c84c2613dd204c3e1218093a34`;
[main CI 42213084645](https://github.com/yohn-jp/nous-osint/actions/runs/42213084645)
succeeded. Phase B prepares independent CI/CD and a disabled Terraform Route.
**No Cloudflare deployment, Route activation or VM change has been performed.**
The approved [deployment plan](EDGE_FRONTEND_DEPLOYMENT.md) remains authoritative.

## Changed-file scopes

`scripts/ci/changes.py` reads the complete local Git diff, with no API file-count
limit. PRs compare merge-base to PR head. Pushes compare event `before`/`after`,
including all commits in a merge or multi-commit push; a zero `before` selects
all tracked files. Rename detection is disabled so both deleted and added paths
are classified. Missing historical SHAs are fetched explicitly; failures stop CI.

Pushes also include changes since the most recent successful main **CI** run.
This carries forward changes from failed/superseded releases: a UI release that
was refused because main advanced must not disappear on the next backend-only
push. If there is no successful main run, all tracked files are classified.

| Changed paths | Selected work |
| --- | --- |
| `ui/**`, `edge/frontend/**` | Quasar typecheck/build + Edge build/tests; main Edge release when enabled |
| Backend `src/**`, migrations, sources, Python manifests | Python checks + application image; shared report dependencies also select report work |
| `src/nous/report_worker.py`, `report_pipeline.py` | Python checks + report checks/image |
| `reports/site/**`, schemas | Python checks + report checks/image; no generated private articles uploaded |
| `reports/templates/**` | Also application image: its admin API uses these templates |
| `src/nous/access_auth.py` | Also frontend, because Edge/Python route parity must pass |
| `tests/**` | Python checks; no image publication just for test edits |
| Terraform | Offline fmt/init/validate; no plan/apply |
| Shared CI/workflow scripts or unknown build inputs | All lanes conservatively |
| Documentation only | Small CI contract checks + aggregate result; no image or Edge release |

All matches are combined. The report runtime dependency closure has a regression
test so adding a new local import cannot silently omit its image rebuild.
The stable aggregate `ci` job fails when any selected lane fails or is cancelled;
intentional skipped lanes are allowed. Configure branch-required checks against
this aggregate rather than requiring a lane that may legitimately be skipped.

The VM UI is deliberately retained. Backend image builds still compile its
fallback Quasar bundle until the cutover/rollback gates permit Phase D. UI-only
commits do not select a backend build, and backend-only changes do not publish an
Edge release (unless catching up a previously unsuccessful UI change). No SSH or
VM deployment is added.

## Protected release configuration

Enable only after the Phase C bootstrap/preflight can establish an existing
private `nous-frontend` Worker with **both workers.dev and version preview URLs
disabled**. A missing Worker or either public endpoint makes the release fail
before upload. CI does not bootstrap Workers or attach a Route.

Configure a single GitHub Environment `frontend-production`, restricted to main
with the repository's required reviewers/approval policy. Put these secrets in it:

- `CLOUDFLARE_API_TOKEN`: intended-account **Workers Scripts Write** only (includes
  static-asset upload and script-version/deployment operations). No Access,
  Tunnel, DNS or Workers Routes write permissions. Cloudflare tokens may not
  support restriction to a single script; use a dedicated token with the narrowest
  available account scope, short expiry and rotation.
- `CLOUDFLARE_ACCOUNT_ID`: the verified intended account identifier.

Environment variable `CLOUDFLARE_ZONE_ID` records the verified intended zone.
The script validates its shape and records it in release evidence; it does not
query or mutate the zone, so the CI token needs no zone-read permission. Account,
zone, canonical-host Route and absence of conflicting Custom Domains/Routes must
be verified separately with the operator's read-only preflight credentials.

Repository variables:

- `FRONTEND_DEPLOY_ENABLED=true`: opt in to release jobs after configuring the
  environment. With any other value, builds/tests still run but no release
  artifact or deployment is created. This gate is off in the current repository.
- `FRONTEND_RELEASE_MODE`: defaults to `passthrough`. Keep it there through the
  initial Phase C verification. Change to `production` only at the approved
  static-UI activation step; those are the only accepted values.

After enabling releases, use a UI/Edge main change to exercise a release. Merely
adding a secret/variable does not trigger a workflow. Do not manufacture a VM
rollout to validate UI delivery.

## Artifact, ordering and ownership

The frontend job first checks the normal static build and tests both router
modes. Enabled main releases then build the selected mode with immutable SHA
provenance, transferring output to the deploy job via an artifact bound to that
same workflow run and SHA. It contains public-source code/assets only, no private
reports or credentials. PRs do not upload preview artifacts or expose a hosted
preview. A restricted PR-preview destination remains unspecified.

The deployment job uses the Environment and a single `frontend-production`
concurrency group with cancellation disabled. Main workflows also serialize and
are not cancelled during mutation. Before upload **and immediately before
activation**, the script asks GitHub for current main HEAD and refuses stale SHAs.
A refused upload remains an inactive version; it cannot supersede a newer release.

`edge/frontend/scripts/release.mjs` checks artifact SHA, build mode, Worker name,
absence of domains/triggers and disabled preview settings. It checks effective
private endpoint settings through the Workers Script Subdomain API. It then uses
the pinned `cf workers versions create --prebuilt` to upload script/assets and
`cf workers deployments create` to activate **that exact returned UUID**, tagged
with the full commit SHA. It does not select `latest`, run `cf deploy`, or deploy
triggers. If the beta CLI's expected version-ID output changes, activation fails
closed. Tests cover stale main (including advancement after upload), missing or
public Worker, wrong artifacts and ambiguous upload output.

Terraform exclusively owns `nous.yohn.jp/*` via `cloudflare_workers_route.frontend`.
Its `frontend_route_enabled` default is **false**. Only Phase C's reviewed plan may
set it true after inspecting effective Access/Tunnel/DNS, confirming no conflicting
Route/Custom Domain, deploying private passthrough and recording baseline behavior.
Use the existing encrypted state/import process; never apply this whole tree as
new resources over existing Access/Tunnel/DNS. The script/assets remain outside
Terraform. Route write permission belongs to the separate Terraform operator token,
scoped to this zone, and must not be added to the CI script token.

Rollback before Phase D: restore passthrough using the same release path or set
only `frontend_route_enabled=false` through a reviewed Terraform plan. The VM
fallback remains intact. Verify UI/MCP/admin/reports after rollback; no live
rollback claim can be made from these offline tests.

References: [cf versions/deployments](https://developers.cloudflare.com/cf/projects/),
[Script Subdomain API](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/subdomain/methods/get/),
[Terraform Worker Route](https://developers.cloudflare.com/api/terraform/resources/workers/subresources/routes/).

## Acceptance status

Offline scope/history tests, route/release tests and Terraform validation are
implemented. GitHub Actions results must be recorded against the PR's latest HEAD.

**BLOCKED (live Phase B acceptance):** repository Secrets, Environments and
variables are empty, and no Cloudflare credentials are present in the execution
environment. The restricted Environment, narrow deploy token, account/zone context
and existing private Worker must be provisioned before testing an actual UI-only
main deployment. No successful independent Cloudflare deployment is claimed.
No Terraform plan/apply, live Access/OAuth/MCP check or rollout/rollback is claimed.
Phase C/D must not begin until the preceding acceptance gates are satisfied.
