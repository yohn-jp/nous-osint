# Image delivery and Source Onboarding

## CI and immutable application image

The `check` (Python, PostgreSQL, migration and backup verification) and `frontend` (Node 24, Quasar typecheck/build) jobs run concurrently. The `image` job depends on both; pull requests build without publishing, while pushes to `main` publish `ghcr.io/yohn-jp/nous-osint:main` and record the immutable `ghcr.io/yohn-jp/nous-osint@sha256:...` reference in the workflow summary and `nous-image-digest` artifact. BuildKit's GitHub Actions cache is shared across runs.

The application image includes the Python API/MCP/worker/scheduler and compiled Quasar assets. It does **not** replace the separately pinned PostgreSQL or cloudflared images. Only the application image is published here. The mutable `:main` tag is for discovery; deployment must use the digest, never the tag.

### VM deployment (not automated by CI)

1. Review successful CI checks and copy the image reference from the **specific** successful main workflow run.
2. Pull the exact digest on the VM using rootless Podman. If GHCR is private, provision a VM-local pull-only registry credential; never commit it or expose it to the browser.
3. Update the `Image=` line of **all four** application Quadlets (`nous-api`, `nous-mcp`, `nous-worker`, `nous-scheduler`) to the **same** `ghcr.io/yohn-jp/nous-osint@sha256:...` reference. Do not change the database or Tunnel image.
4. Reload the user systemd manager and restart application units in a controlled sequence. Confirm readiness, MCP `initialize` and `tools/list`, source collection, and UI access. Preserve the previous digest for rollback.
5. If checks fail, restore the prior four `Image=` values and restart. Do not prune the old image before verification.

**Important:** Committing a concrete digest to the repository cannot happen in the same source commit that builds it without creating a self-referential build loop. The workflow publishes the digest as a release artifact; the VM's effective Quadlet configuration is pinned at deployment time. The current Quadlet digests are historical VM build references and are **not** automatically changed by this PR. This is deliberate; no unverified VM deployment is claimed.

## Source Onboarding: Git-controlled intake to scheduled ingestion

Source YAML in `sources/*.yaml` remains authoritative. No API endpoints capable of changing the collector are exposed through read-only MCP or Cloudflare Access. Registration is **reviewed and activated in Git**, then picked up by the runtime scheduler after that commit's immutable application image has been deployed.

### Browser workflow

In Nous, navigate to **Sources → 情報源を追加** (`/sources/new`).

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

There is no GitHub write token in the SPA or MCP origin. The GitHub approval and image rollout remain intentional operations, not background automation. The UI validates simple field constraints for feedback, while CI/CLI validate the canonical Pydantic schema. Untrusted source bodies are never injected into HTML or Git; only metadata, title and URLs appear in probe output. No unauthenticated URL-fetch tool is exposed to the public interface.

Ingestion and UI should be checked independently after deployment. Neither PR CI nor a GitHub Actions probe can demonstrate that a VM restarted onto the new digest without runtime evidence.

See [CACHE_STRATEGY.md](CACHE_STRATEGY.md) for response and Cloudflare CDN cache boundaries.
