# Image delivery and Source Onboarding

## CI and immutable application/report Worker images

The `check` (Python, PostgreSQL, migration and backup verification), `cve-role-grants`, `frontend` (Node 24, Quasar typecheck/build), and `reports` (Astro) checks run independently. The `image` job depends on check/frontend/reports; `report-worker-image` depends on check/reports. Pull requests build both images without publishing. Successful pushes to `main` publish `ghcr.io/yohn-jp/nous-osint:main` and `ghcr.io/yohn-jp/nous-osint-reports:main`, recording the immutable `@sha256:...` references in the workflow summaries and `nous-image-digest` / `report-worker-image-digest` artifacts. BuildKit's GitHub Actions cache is shared across runs.

The application image includes the Python API/MCP/collection Worker/scheduler and compiled Quasar assets. The separate report Worker image includes the reviewed Codex CLI, Python report pipeline and build-only Node/Astro dependencies. Neither image replaces separately pinned PostgreSQL/cloudflared. Both mutable `:main` tags are for discovery only: deployment must use each distinct immutable digest.

### VM deployment (not automated by CI)

1. Review **all green** checks for the specific `main` SHA and copy **both** immutable image references from that workflow run.
2. Run the reviewed database migration `alembic upgrade head` (the current repository migration head) with the migration role **before** new containers start. Ensure the conditional KEV journal grants exist for runtime/API/MCP/report Worker roles; migration failure blocks rollout.
3. Pull both exact digests with rootless Podman; keep registry pull credentials local to the VM.
4. Pin the **same application digest** in the four application Quadlets (`nous-api`, `nous-mcp`, `nous-worker`, `nous-scheduler`) and the **separate report digest** in `nous-report-worker`. Do not change PostgreSQL or Tunnel image references.
5. Reload the user systemd manager, restart in dependency order, then confirm API readiness, MCP `initialize`/`tools/list`, source collection, browser access and report Worker recovery. Preserve both previous digests and the existing report-site release for rollback.
6. On failure, restore previous image references and restart the prior services; the additive schema must be checked for backward compatibility. Do not prune either old image before verification.

**Important:** Committing a concrete digest to the repository cannot happen in the same source commit that builds it without creating a self-referential build loop. The workflow publishes the digest as a release artifact; the VM's effective Quadlet configuration is pinned at deployment time. The current Quadlet digests are historical VM build references and are **not** automatically changed by this PR. This is deliberate; no unverified VM deployment is claimed.

## Source Onboarding: official Git catalog and private-instance Admin UI

`src/nous/admin.py` and `/admin/sources` provide Access-authorized **per-instance** source management with a separate write-limited database credential, while the MCP and public query API stay read-only. Custom source creation, review, probing, activation and configuration changes do not require GitHub. Git-tracked `sources/*.yaml` remains authoritative only for **Nous's bundled official catalog**, which is updated through PRs and application image releases. See [Source Management](SOURCE_MANAGEMENT.md).

### Official catalog contribution workflow

To propose a new **distributed official** source, navigate to **Sources → Gitに提案** (`/sources/new`). For instance-local sources, use `/admin/sources/new` instead.

1. Select RSS, JSON API or HTML, add source ID/HTTPS URL, source kind, polling budget, publisher and reviewed policy metadata.
2. For JSON API specify a dot-separated array path and field mapping if needed. For HTML supply the CSS selectors for item/title/link. Generated YAML is always `enabled: false`.
3. Review the YAML preview and choose **GitHubで提案を作成**. GitHub's editor opens with the filename and contents prefilled; choose a **new branch and a pull request**, not a direct commit to main. Browser supports copy/download as fallback.
4. CI checks the registry and candidate schema. For new/changed sources run the operator-only **Probe a reviewed OSINT source** Actions workflow (`source_id`) on the proposal ref, review response count/sample URLs and policy. Do not use a successful parser as proof of legal reuse.
5. Enable the approved source in the PR after review. Merge only after source terms/robots/polling and extraction are acceptable. The next build creates a new GHCR digest containing the registry change. Roll it out on the VM using the digest procedure above.
6. Verify `/v1/sources` and the first real scheduler/worker fetch, item identities, provenance, 304/unchanged behavior and error state. If ingestion fails, disable the source in Git and deploy a new image.

### CLI workflow

```sh
# Validate all existing definitions, no network access:
python -m nous.onboard_source --check-registry

# Stage a candidate as disabled:
python -m nous.onboard_source \\
  --id example-advisories \\
  --url https://example.org/advisories.xml \\
  --kind rss --item-kind advisory \\
  --organization Example \\
  --reviewed-at 2026-11-03 \\
  --terms-url https://example.org/terms \\
  --policy-note "Official feed reviewed; metadata-only storage" \\
  --probe --write

# Probe any already tracked source without changing storage:
python -m nous.onboard_source --probe-id cisa-advisories

# JSON API and HTML options:
# --kind json_api --json-path results.items --map id=uuid --map title=headline --map url=link
# --kind html --selector item=article --selector title=h2 --selector url=a
```

Without `--write`, the candidate is printed as YAML. `--probe` performs one bounded production-fetcher HTTPS request with SSRF protections, then verifies the extracted records and prints a bounded summary. A `--write` call creates an exclusive source YAML file to prevent overwrites. JSON API and HTML candidates are supported by the CLI, though endpoint-specific mappings/selectors must be reviewed. A probe does **not** grant approval and cannot turn a source on.

### Trust boundary and limitations

There is no GitHub write token in the SPA or MCP origin. Instance administration uses the dedicated Access-authorized gateway endpoint; the GitHub approval and image rollout for **official catalog** updates remain intentional operations, not background automation. The UI validates simple field constraints for feedback, while CI/CLI validate the canonical Pydantic schema. Untrusted source bodies are never injected into HTML or Git; only metadata, title and URLs appear in probe output. No unauthenticated URL-fetch tool is exposed to the public interface.

Ingestion and UI should be checked independently after deployment. Neither PR CI nor a GitHub Actions probe can demonstrate that a VM restarted onto the new digest without runtime evidence.

See [CACHE_STRATEGY.md](CACHE_STRATEGY.md) for response and Cloudflare CDN cache boundaries.
