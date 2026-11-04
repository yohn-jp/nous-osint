# Source management: official catalog and private-instance administration

## Ownership and deployment model

Nous distributes reviewed **official source definitions** in `sources/*.yaml`.
Those definitions ship in the immutable application image and receive updates
only when the image is updated. A private Nous instance does **not** need
GitHub credentials, GitHub Actions or repository access to add sources.

The database contains the effective runtime configuration for both origins:

| Source origin | Definition owner | Local changes | Catalog/image update |
| --- | --- | --- | --- |
| `official` | Git-tracked YAML | Enabled state, interval, rate and concurrency overrides in PostgreSQL | Imports latest publisher URL, adapter and policy while preserving local operational overrides |
| `custom` | Admin UI / PostgreSQL | Full source definition and operational settings | Never rewritten or removed by catalog sync |

The scheduler imports the official catalog every cycle, creating missing entries
and applying permitted overrides. It disables removed official definitions
without deleting source records, observations or history. An ID collision
between a custom source and a newly introduced official definition fails
closed rather than silently changing source ownership.

The existing five official sources keep their configured enabled state.
Newly added official entries are **disabled by default**. Enabling a source
requires the operator to consider terms, robots directives and collection
budget; a reachable URL or probe result does not prove permission.

## Admin UI flow

Navigate to **管理 → 情報ソース** (`/admin/sources`) as an explicitly
allowlisted administrator.

- **公式カタログ**: view bundled source definitions and last-fetch status;
  probe and enable/disable each source; change polling interval and budgets.
  Official source extraction mapping and publisher URL cannot be edited from
  the instance UI.
- **カスタム**: add a public HTTPS RSS/Atom, JSON API or HTML source;
  configure mapping/selectors, provider, type and reviewed metadata-only
  policy; save it disabled; probe the extraction; then explicitly enable.
  Custom sources may be edited and disabled without losing historical records.
- The UI writes directly to the instance's database through the protected
  admin API, **not** to GitHub. It does not place provider credentials in the
  browser or permit the MCP caller to change the registry.

The existing `/sources/new` Git/YAML proposal flow remains available to
contributors who want to improve the *official distributed catalog*.

## Security boundaries

All admin requests travel through the existing Cloudflare Access-protected
gateway. The gateway independently verifies the signed Access JWT and checks
its stable `sub` claim against the comma-separated `NOUS_ADMIN_SUBJECTS`
allowlist. **Access login alone is not administrative authorization.**

The `NOUS_PUBLIC_HOST` environment variable sets the accepted public
hostname (default `nous.yohn.jp`). The admin write API accepts same-origin
HTTPS requests with JSON content type and `X-Nous-Admin-Action: 1`; cross-origin
writes and unsupported methods are rejected. It is not exposed by Remote MCP.

The gateway uses an independent DB credential read from
`NOUS_ADMIN_DATABASE_URL_FILE`. Missing allowlist or DB secret leaves the
admin API unusable. Do not grant the ordinary MCP read-only database user
source-write access, and do not expose the internal API or database publicly.

### VM prerequisites

Before updating the MCP gateway image, create a distinct PostgreSQL role for
source management, with only these permissions (replace the password
placeholder using secure interactive provisioning, never commit it):

```sql
CREATE ROLE nous_admin LOGIN PASSWORD '<generate-outside-repository>';
GRANT CONNECT ON DATABASE nous TO nous_admin;
GRANT USAGE ON SCHEMA public TO nous_admin;
GRANT SELECT, INSERT, UPDATE ON TABLE sources TO nous_admin;
GRANT SELECT, INSERT ON TABLE source_audits TO nous_admin;
GRANT USAGE, SELECT ON SEQUENCE sources_id_seq, source_audits_id_seq TO nous_admin;
```

Apply `alembic upgrade head` using the migration role before switching to
the new application image. Store a PostgreSQL URL using the dedicated
`nous_admin` role as the rootless Podman secret
`nous-admin-database-url`, and set the gateway's private
`%h/.config/nous/mcp.env` entries:

```ini
NOUS_ADMIN_SUBJECTS=<verified-access-sub-claim>
NOUS_PUBLIC_HOST=nous.yohn.jp
```

The committed `nous-mcp.container` mounts the admin DB secret at
`/run/secrets/admin_database_url`. Provision it before service restart;
otherwise Quadlet cannot start. If administration is intentionally disabled,
the admin role is not allowlisted, but the secret still needs to exist for
this bundled Quadlet template. Self-hosters can change the accepted hostname,
but still need valid Cloudflare Access issuer/audience configuration.

Admin changes are committed transactionally and generate append-only
`source_audits` records containing the Access subject, action and before/after
source configuration. Source deletion and arbitrary command/script execution
are deliberately not exposed. Source URLs remain subject to the production
SSRF-safe fetcher and constrained extraction adapters.

## Native ATS job sources (Greenhouse, Lever and Ashby)

The native job adapters `greenhouse_jobs_v1`, `lever_jobs_v1`, and
`ashby_jobs_v1` read public, unauthenticated publisher endpoints only.
They keep stable posting IDs, titles, source URLs, published/updated dates,
department/location and evidence of Japan/security classification, without
retaining the posting description. Ambiguous countries and unrelated roles
are not silently classified as domestic security jobs.

To add an instance-local board, select **JSON API** and one of the three
native adapters in **管理 → カスタムソースを追加**. Use a publisher's official
board GET URL. Lever allows `max_pages` of 1–10 (100 records per page);
it must fit the per-hour request budget and the worker will reject a
partially fetched board. Missing postings are marked unknown only after
a fully successful enumeration, never closed from a failed request.
The admin UI stores new sources disabled; probe and review rights before
manually enabling.

Publisher API references: https://docs.greenhouse.io/job-board,
https://github.com/lever/postings-api,
https://developers.ashbyhq.com/docs/public-job-posting-api.

## Source rights and extension plan

All bundled source definitions must be assessed independently of Nous's MIT
license. Newly proposed feeds carry a publisher attribution, an explicit
`license_id` (default `NOASSERTION` where no verified universal content license
exists), and links to any identified legal terms. A public feed is not a
permission to relicense or mirror the content. The current set of disabled
sources and their review gates are documented in [Source Rights](SOURCE_LICENSES.md).

For sources that need API pagination, ATS-specific fields, vulnerability dataset
normalization or headless HTML processing, see the [OSS Adapter Evaluation](ADAPTER_EVALUATION.md).

## New catalog candidates

The following are packaged as **disabled** definitions:

| ID | Publisher feed | Extraction |
| --- | --- | --- |
| `jpcert-alerts` | JPCERT/CC alerts + Weekly Report RSS | RSS/RDF |
| `jpcert-notices` | JPCERT/CC announcements RSS | RSS/RDF |
| `jvn-ipedia-updates` | JVN iPedia newly added/updated vulnerability feed | RSS/RDF |

Publisher documentation:

- https://www.jpcert.or.jp/rss/index.html
- https://jvndb.jvn.jp/ja/feed/

These URLs have been matched to official publisher feed links. Runtime reachability,
extractor behavior, rights review and live operator activation remain
separate acceptance checks. They are not marked live solely because CI passes.

## Verification and rollback

1. Verify the exact migration head, admin role/permissions, API readiness and
   a denied unauthenticated/non-admin write.
2. Confirm official catalog entries appear, including disabled additions.
   Save and probe a disabled custom source; enable and disable it.
3. Re-run scheduler sync and verify the custom definition persists, official
   operational overrides survive, and the audit shows the actor and action.
4. Validate actual Cloudflare Access and cache behavior on the configured
   hostname. Admin responses must remain `Cache-Control: no-store`.
5. Deploy a pinned GHCR digest through the existing rollback-controlled
   Quadlet rollout. Revert to the previous digest if checks fail; account
   for the additive migration when planning downgrade. No CI result alone
   proves the VM was updated.

For source promotion to the distributed catalog, use a Git PR and the
existing `probe-source.yml` workflow instead of exporting an instance's
private configuration.
