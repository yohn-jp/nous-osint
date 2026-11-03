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

## Source Onboarding v1

The registry under `sources/*.yaml` remains the only authority. The new staging command creates a **disabled** RSS candidate and validates it using the canonical `SourceConfig` model and the existing registry. It does not fetch remote sites, change PostgreSQL, or enable ingestion.

```sh
python -m nous.onboard_source \
  --id example-advisories \
  --url https://example.org/advisories.xml \
  --kind rss --item-kind advisory \
  --organization Example \
  --reviewed-at 2026-11-03 \
  --terms-url https://example.org/terms \
  --policy-note "Official feed reviewed; metadata-only use permitted"
```

Without `--write`, it prints the YAML preview. With `--write`, it creates `sources/example-advisories.yaml` exclusively and fails on duplicate IDs. The generated entry is `enabled: false`. Operators must independently review the publisher terms, robots guidance, URL, feed format, polling budget, extraction behavior, and data rights; the CLI cannot certify compliance. A reviewed PR enables the source and merges it into Git. Existing registry synchronization then imports the approved configuration and the existing scheduler/worker perform collection. Validate the first successful fetch, normalized items, provenance, duplicates, and subsequent polling before calling onboarding complete.

JSON APIs and HTML need endpoint-specific mappings/selectors; v1 intentionally requires manual YAML authoring and canonical validation for those adapters. The command is **not** a general automatic source discovery engine.

## Next implementation boundaries

A complete Source Onboarding product needs candidate persistence, server-side URL/feed probes with SSRF protections, explicit approval, per-source first-run evidence, and a Quasar management flow with separate authenticated write permissions. Do not expose source mutations through the existing read-only MCP tools or the public read API. These capabilities are **not implemented by this change**.
